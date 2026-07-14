//! RustDesk SOS 精简受控端 — 主入口
//!
//! 基于 `hbb_common` 库构建，仅支持 Windows。
//! 单一可执行文件，通过命令行参数切换运行模式：
//!
//! ```text
//! rustdesk-sos.exe                          → 主进程模式（托盘 + 全部服务）
//! rustdesk-sos.exe --portable-service ...   → SYSTEM 便携服务模式（UAC 捕获）
//! ```
//!
//! Release 构建使用 Windows GUI 子系统（默认无控制台窗口）。
//! 传入 `--debug` 时分配控制台，显示日志输出。

// Release 构建使用 Windows GUI 子系统，不显示控制台窗口
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sos_bootstrap;
mod sos_capture;
mod sos_config;
mod sos_connection;
mod sos_constants;
mod sos_file_transfer;
mod sos_input;
mod sos_pipe;
mod sos_rendezvous;
mod sos_shmem;
mod sos_system;
mod sos_tray;

use clap::Parser;
use hbb_common::ResultType;
use std::io::Write;
use std::sync::mpsc;

/// RustDesk SOS 精简受控端
#[derive(Parser)]
#[command(
    name = "rustdesk-sos",
    about = "RustDesk SOS 精简受控端 - 单文件远程协助客户端"
)]
struct Cli {
    /// 显示控制台窗口并输出调试日志
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// 信令服务器地址，如 rs-ny.rustdesk.com
    #[arg(long, default_value = "")]
    rendezvous: String,

    /// 中继服务器地址（可选，未指定时由信令服务器自动下发）
    #[arg(long, default_value = "")]
    relay: String,

    /// 信令服务器公钥（Base64，可选，使用自定义信令服务器时必填）
    #[arg(long, default_value = "")]
    key: String,

    /// 固定密码（传入后永久使用，不断开刷新；不传入则每次连接后自动更换）
    #[arg(long, default_value = "")]
    password: String,

    /// 启动模式开关
    #[arg(long, default_value_t = false)]
    service: bool,
}

#[tokio::main]
async fn main() -> ResultType<()> {
    // 捕获所有 panic，输出到 stderr 防止静默崩溃
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            *s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.as_str()
        } else {
            "unknown payload"
        };
        eprintln!("!!! PANIC at {}: {}", loc, msg);
        default_hook(info);
    }));

    let cli = Cli::parse();

    // ── 控制台管理 ──
    // Release 构建使用 GUI 子系统（无控制台），仅 --debug 时显示控制台。
    // AttachConsole 挂接父控制台后标准句柄仍是无效的，需要手动通过
    // CreateFile("CONOUT$") 打开控制台并用 SetStdHandle 重定向。
    #[cfg(windows)]
    if cli.debug && !cli.service {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::System::Console::*;
        unsafe {
            let has_parent = AttachConsole(ATTACH_PARENT_PROCESS).is_ok();
            if !has_parent {
                AllocConsole();
            }
            // 打开控制台的输出设备，重定向 stdout/stderr
            // CreateFileW 的 dwDesiredAccess 是 u32，不能用 FILE_GENERIC_WRITE（类型不匹配）
            const GENERIC_WRITE: u32 = 0x40000000;
            const GENERIC_READ: u32 = 0x80000000;
            let con_out: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
            let handle = CreateFileW(
                PCWSTR(con_out.as_ptr()),
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            );
            if let Ok(h) = handle {
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
                let _ = SetStdHandle(STD_ERROR_HANDLE, h);
            }
        }
        // 确保 Rust stdio 重定向到新句柄
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }

    let log_level = if cli.debug { "info" } else { "warn" };
    // 初始化日志（所有模式都需要）
    if cli.service {
        sos_bootstrap::init_system_logger(log_level);
    } else {
        sos_bootstrap::init_logger(log_level);
    }

    // ── 模式分发：服务模式 ──
    if cli.service {
        return sos_system::run_service();
    }

    // ── 主进程模式 ──

    // 0. 硬性检查：必须以管理员权限运行
    if !sos_bootstrap::is_admin() {
        sos_bootstrap::show_admin_required_and_exit();
    }

    log::info!(
        "{} v{} starting...",
        sos_constants::APP_NAME,
        env!("CARGO_PKG_VERSION")
    );

    // 1a. 输出主进程令牌诊断
    #[cfg(windows)]
    sos_system::log_token_info("MAIN_INIT");

    // 2. 读取/初始化注册表配置
    //    ID 优先级: --id > 注册表 > MAC 地址自动生成
    //    信令服务器优先级: --rendezvous > 注册表 > 默认
    let config = sos_config::SosConfig::from_cli_and_registry(
        &cli.rendezvous,
        &cli.relay,
        &cli.key,
        &cli.password,
    )?;
    log::info!("Device ID: {}", config.id);
    log::info!("Rendezvous server: {}", config.rendezvous_server);

    // 种子 CPU 使用率初始值，防止 codec_thread_num 因 PDH 计数器未就绪
    // 而回退到 1 线程。后台 PDH 线程就绪后会自动用真实数据覆盖。
    #[cfg(windows)]
    hbb_common::platform::windows::sync_cpu_usage(Some(50.0));

    // 密码策略：
    //   --password 传入 → 永久固定，不保存注册表，不断开刷新
    //   未传入       → 自动生成临时密码，每次连接断开后刷新
    let cli_password_provided = !config.password.is_empty();
    let temp_pwd = if cli_password_provided {
        config.password.clone()
    } else {
        sos_config::generate_temp_password()
    };
    sos_config::set_current_password(temp_pwd.clone());
    if cli_password_provided {
        log::info!("Using fixed CLI password (not regenerated on disconnect)");
    } else {
        log::info!(
            "Temporary password (will refresh each connection): {}",
            temp_pwd
        );
    }

    // 4. 创建 SOS 自有 SHMEM（固定名 "sos"，SYSTEM 子进程常驻写帧）
    let _shmem = match sos_shmem::create_shmem() {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create SOS SHMEM: {}", e);
            return Err(e);
        }
    };

    // 创建输入管道服务器（Main → System 输入事件）
    let (pipe_tx, pipe_thread) =
        sos_pipe::create_pipe_server(sos_constants::INPUT_PIPE, sos_pipe::PIPE_ACCESS_OUTBOUND);
    crate::sos_pipe::set_down_tx(pipe_tx);

    // 创建控制管道服务器（Main → System 启停捕获，独立管道）
    let (ctrl_tx, ctrl_thread) =
        sos_pipe::create_pipe_server(sos_constants::CONTROL_PIPE, sos_pipe::PIPE_ACCESS_OUTBOUND);
    crate::sos_pipe::set_control_tx(ctrl_tx);

    // 用 Arc<Mutex<Option<>>> 包装线程句柄，看门狗 join 后替换新句柄
    let pipe_thread_ref = std::sync::Arc::new(std::sync::Mutex::new(Some(pipe_thread)));
    let ctrl_thread_ref = std::sync::Arc::new(std::sync::Mutex::new(Some(ctrl_thread)));

    // 5. 以 SYSTEM 身份启动子进程（常驻）
    #[cfg(windows)]
    {
        sos_system::launch_system_sub_process(cli.debug);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // 5a. SYSTEM 子进程存活看门狗：join 管道线程，死亡时自动重建 + 重启
    #[cfg(windows)]
    {
        let debug = cli.debug;
        let ptr = pipe_thread_ref.clone();
        let ctr = ctrl_thread_ref.clone();
        std::thread::spawn(move || loop {
            // 阻塞等待管道线程退出（子进程死亡时 OS 关闭管道 → 线程退出 → join 返回）
            // 用 ctrl_thread 作为代表：子进程一死，两个管道同时断开
            let old_ctrl = ctr.lock().unwrap().take().unwrap();
            let _ = old_ctrl.join();
            log::warn!("SYSTEM sub-process pipe broken (ctrl_thread exited), restarting...");

            // 重建管道，更新全局 sender
            let (pt, pth) = sos_pipe::create_pipe_server(
                sos_constants::INPUT_PIPE,
                sos_pipe::PIPE_ACCESS_OUTBOUND,
            );
            let (ct, cth) = sos_pipe::create_pipe_server(
                sos_constants::CONTROL_PIPE,
                sos_pipe::PIPE_ACCESS_OUTBOUND,
            );
            sos_pipe::set_down_tx(pt);
            sos_pipe::set_control_tx(ct);

            // 同步清理可能还活着的旧 pipe_thread（子进程死亡后它也已退出或即将退出）
            if let Some(old_pipe) = ptr.lock().unwrap().take() {
                let _ = old_pipe.join();
            }

            // 放入新句柄供下一轮 join
            *ptr.lock().unwrap() = Some(pth);
            *ctr.lock().unwrap() = Some(cth);

            // 启动新的 SYSTEM 子进程
            sos_system::launch_system_sub_process(debug);
            std::thread::sleep(std::time::Duration::from_secs(3));
        });
    }

    // 6. 启动上游 video_service（默认使用自身 DXGI，不劫持）
    log::info!("Starting upstream video service (DXGI)...");
    let video_svc =
        librustdesk::video_service::new(librustdesk::video_service::VideoSource::Monitor, 0);
    sos_config::set_video_service(video_svc);
    log::info!("Video service started (upstream)");

    // 6a. UAC 监控：检测到安全桌面时注入自定义工厂
    #[cfg(windows)]
    {
        let uac_w = {
            scrap::Display::all()
                .unwrap_or_default()
                .first()
                .map(|d| d.width() as usize)
                .unwrap_or(1920)
        };
        let uac_h = {
            scrap::Display::all()
                .unwrap_or_default()
                .first()
                .map(|d| d.height() as usize)
                .unwrap_or(1080)
        };
        std::thread::spawn(move || loop {
            let uac = librustdesk::platform::windows::is_process_consent_running().unwrap_or(false);
            let has_factory = librustdesk::video_service::custom_capturer_factory_is_set();
            if uac && !has_factory {
                // UAC 安全桌面激活 → 先发信号让 SYSTEM 子进程启动 GDI 捕获
                log::info!("[UAC] consent.exe detected, sending START_CAPTURE via control pipe");
                sos_pipe::try_send_control(
                    sos_constants::MSG_CONTROL_START_CAPTURE
                        .to_ne_bytes()
                        .to_vec(),
                );
                // 短暂等待捕获线程启动并产出首帧（~33ms per frame + setup）
                std::thread::sleep(std::time::Duration::from_millis(150));
                // 再注入 SHMEM 工厂让 video_service 切换捕获源
                if let Ok(shmem) = sos_shmem::SosShmem::open_existing(sos_shmem::SHMEM_NAME) {
                    sos_shmem::register_shmem_and_factory(shmem, uac_w, uac_h);
                    log::info!("[UAC] Factory injected, video_service will switch to SOS SHMEM");
                }
            } else if !uac && has_factory {
                // UAC 安全桌面关闭 → 先清除工厂让 video_service 切回 DXGI
                sos_shmem::clear_shmem_factory();
                log::info!("[UAC] Factory cleared, video_service will switch back to DXGI");
                // 再通过控制管道发信号让 SYSTEM 子进程停止 GDI 捕获
                log::info!("[UAC] Sending STOP_CAPTURE via control pipe");
                sos_pipe::try_send_control(
                    sos_constants::MSG_CONTROL_STOP_CAPTURE
                        .to_ne_bytes()
                        .to_vec(),
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        });
    }

    // 5b. 启动上游 clipboard_service（剪贴板同步，含文件剪贴板）
    log::info!("Starting upstream clipboard service...");
    let clip_svc = librustdesk::server::clipboard_service::new("clipboard".into());
    sos_config::set_clipboard_service(clip_svc);
    log::info!("Clipboard service started (upstream)");

    // 5c. 初始化 cliprdr 上下文（OLE 文件剪贴板引擎，用于远程文件粘贴）
    #[cfg(windows)]
    {
        log::info!("Initializing cliprdr context for file clipboard...");
        clipboard::ContextSend::enable(true);
        if clipboard::ContextSend::is_enabled() {
            log::info!("Cliprdr context initialized successfully");
        } else {
            log::warn!("Cliprdr context initialization failed - file clipboard may not work");
        }
    }

    // 6. 创建托盘
    let (tray_tx, tray_rx) = mpsc::channel::<sos_tray::TrayCommand>();
    let tray_tx_for_rendezvous = tray_tx.clone();
    std::thread::spawn(move || {
        if let Err(e) = sos_tray::run(tray_tx) {
            log::error!("Tray thread error: {}", e);
        }
    });

    // 8. 创建密码刷新通道（仅未传入 --password 时才需要断开后刷新）
    let (pwd_refresh_tx, mut pwd_refresh_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // 8. 启动信令注册任务（后台持续运行）
    let rendezvous_config = config.clone();
    let rendezvous_handle = tokio::spawn(async move {
        if let Err(e) =
            sos_rendezvous::run(rendezvous_config, tray_tx_for_rendezvous, pwd_refresh_tx).await
        {
            log::error!("Rendezvous service error: {}", e);
        }
    });

    log::info!(
        "SOS client is ready, ID: {}, waiting for incoming connections...",
        config.id
    );

    // 9. 主事件循环：接受托盘命令 + 密码刷新通知 + 保持运行
    use std::sync::Mutex;
    let tray_rx = std::sync::Arc::new(Mutex::new(tray_rx));
    loop {
        tokio::select! {
            // 密码刷新通知：连接断开后重新生成临时密码（仅当未通过 --password 固定时生效）
            Some(()) = pwd_refresh_rx.recv() => {
                if cli_password_provided {
                    log::trace!("CLI password is fixed, ignoring password refresh trigger");
                } else {
                    let new_pwd = sos_config::generate_temp_password();
                    sos_config::set_current_password(new_pwd.clone());
                    log::info!("Connection closed, regenerated temporary password: {}", new_pwd);
                }
            }

            // 托盘命令（每 1 秒轮询）
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                let cmd = tray_rx.lock().unwrap().recv_timeout(std::time::Duration::from_millis(10));
                match cmd {
                    Ok(sos_tray::TrayCommand::Exit) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        log::info!("Exit requested via tray");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // 8. 清理：通知信令任务退出
    rendezvous_handle.abort();

    log::info!("SOS client exiting.");
    Ok(())
}
