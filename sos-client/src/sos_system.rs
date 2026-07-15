//! SYSTEM 会话 1 特权模块
//!
//! SYSTEM 子进程入口：管道通信、GDI 帧捕获写 SHMEM、输入事件处理、桌面切换。

use hbb_common::ResultType;

#[cfg(windows)]
extern "C" {
    /// 在交互 session 中以 SYSTEM 身份启动进程（sessionId != 0 过滤 winlogon）
    /// 等效上游 impersonate_system::run_as_system，但按 session 过滤。
    /// 返回子进程句柄（调用者负责 CloseHandle），失败返回 0。
    pub fn SosRunAsSystemInSession1(cmd: *const u16) -> isize;

    /// 切换到输入桌面（最小权限版本，替代上游 selectInputDesktop 的 GENERIC_WRITE）
    pub fn SosSwitchToInputDesktop() -> i32;

    /// 阻塞等待下一次桌面切换，或 dwTimeout 毫秒超时。
    /// 返回 1=桌面已切换，0=超时，-1=错误。
    /// 内部使用 SetWinEventHook(WINEVENT_INCONTEXT) + 消息泵。
    pub fn SosWaitForDesktopSwitch(timeout_ms: u32) -> i32;
}

// ── 令牌诊断 ──

/// 检查当前进程是否以 SYSTEM 身份运行
#[cfg(windows)]
pub fn is_system_process() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut size = 0u32;
        GetTokenInformation(token, TokenUser, None, 0, &mut size).ok();
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .is_err()
        {
            return false;
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool()
    }
}

/// 输出当前进程的令牌/权限诊断信息
#[cfg(windows)]
pub fn log_token_info(stage: &str) {
    use winapi::um::processthreadsapi::ProcessIdToSessionId;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenElevation, TokenIntegrityLevel, TokenStatistics,
        TokenUser, WinLocalSystemSid, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TOKEN_STATISTICS, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };

    unsafe {
        let mut session_id = 0u32;
        let pid = GetCurrentProcessId();
        ProcessIdToSessionId(pid, &mut session_id);

        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            log::warn!(
                "[TOKEN:{}] PID={} Session={} CANNOT_OPEN_TOKEN",
                stage,
                pid,
                session_id
            );
            return;
        }

        // User SID + SYSTEM check
        let mut size = 0u32;
        GetTokenInformation(token, TokenUser, None, 0, &mut size).ok();
        let mut buf = vec![0u8; size as usize];
        let user_info = if GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .is_ok()
        {
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let is_sys = IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool();
            format!("is_system={}", is_sys)
        } else {
            "SID_UNKNOWN".to_string()
        };

        // Integrity level
        let mut il_size = 0u32;
        GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut il_size).ok();
        let il_str = if il_size > 0 {
            let mut il_buf = vec![0u8; il_size as usize];
            if GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some(il_buf.as_mut_ptr() as *mut _),
                il_size,
                &mut il_size,
            )
            .is_ok()
            {
                let label = &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let sid = label.Label.Sid;
                let sub_auth = windows::Win32::Security::GetSidSubAuthority(sid, 0);
                match *sub_auth {
                    0x0000 => "Untrusted",
                    0x1000 => "Low",
                    0x2000 => "Medium",
                    0x3000 => "High",
                    0x4000 => "System",
                    _ => "Other",
                }
            } else {
                ""
            }
        } else {
            ""
        };
        let il_str = il_str.to_string();

        // Elevation
        let mut elev = TOKEN_ELEVATION::default();
        let mut elev_size = 0u32;
        let elev_str = if GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut elev_size,
        )
        .is_ok()
        {
            if elev.TokenIsElevated != 0 {
                "elevated"
            } else {
                "not_elevated"
            }
        } else {
            "unknown"
        };

        // Token type (primary/impersonation)
        let mut stats = TOKEN_STATISTICS::default();
        let mut stats_size = 0u32;
        let type_str = if GetTokenInformation(
            token,
            TokenStatistics,
            Some(&mut stats as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut stats_size,
        )
        .is_ok()
        {
            match stats.TokenType.0 {
                1 => "Primary",
                2 => "Impersonation",
                _ => "Other",
            }
        } else {
            "unknown"
        };

        log::info!(
            "[TOKEN:{}] PID={} Session={} {} Integrity={} Elevation={} Type={}",
            stage,
            pid,
            session_id,
            user_info,
            il_str,
            elev_str,
            type_str,
        );
    }
}

/// 服务模式入口：由主进程以 SYSTEM 身份启动。
pub fn run_service() -> ResultType<()> {
    #[cfg(windows)]
    if !is_system_process() {
        log::info!("Non-SYSTEM process, exiting");
        return Ok(());
    }

    use crate::sos_constants::{CAPTURE_START_EVENT, CAPTURE_STOP_EVENT, INPUT_PIPE};
    use crate::sos_pipe::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    log_token_info("SUB_INIT");

    // 连接输入管道
    log::info!("Connecting to input pipe: {}", INPUT_PIPE);
    let input_pipe = match connect_pipe_client(INPUT_PIPE, 6) {
        Some(h) => h,
        None => {
            log::error!("Failed to connect input pipe");
            return Ok(());
        }
    };

    // 打开捕获启停命名事件（替代原 CONTROL_PIPE，统一为内核事件模型）
    let (start_event, stop_event) = unsafe {
        extern "system" {
            fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> isize;
            fn WaitForMultipleObjects(
                count: u32,
                handles: *const isize,
                wait_all: i32,
                ms: u32,
            ) -> u32;
        }
        const SYNCHRONIZE: u32 = 0x00100000;
        let to_wide = |s: &str| {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        };
        let se = OpenEventW(SYNCHRONIZE, 0, to_wide(CAPTURE_START_EVENT).as_ptr());
        let pe = OpenEventW(SYNCHRONIZE, 0, to_wide(CAPTURE_STOP_EVENT).as_ptr());
        if se == 0 || pe == 0 {
            log::error!("Failed to open capture start/stop events");
            return Ok(());
        }
        (se, pe)
    };

    // 捕获启停标志：初始为 false（暂停）
    let capture_active = Arc::new(AtomicBool::new(false));
    // 捕获线程句柄：事件线程在收到 START 时 unpark 以实现零延迟唤醒
    let cap_thread_handle: Arc<std::sync::Mutex<Option<std::thread::Thread>>> =
        Arc::new(std::sync::Mutex::new(None));

    // 输入线程：读输入管道 → 分派输入事件
    let input_thread = std::thread::spawn(move || {
        loop {
            let data = match unsafe { read_message(input_pipe) } {
                Some(d) => d,
                None => break,
            };
            if data.len() < 5 {
                continue;
            }
            let msg_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            if !crate::sos_input::dispatch(msg_type, &data[4..]) {
                return;
            }
        }
        log::warn!("[PIPE] Input pipe disconnected");
        std::process::exit(0);
    });

    // 事件线程：WaitForMultipleObjects 等待启停事件 → 更新 AtomicBool + unpark 捕获线程
    let cap_active = capture_active.clone();
    let cap_handle = cap_thread_handle.clone();
    let event_thread = std::thread::spawn(move || {
        extern "system" {
            fn WaitForMultipleObjects(
                count: u32,
                handles: *const isize,
                wait_all: i32,
                ms: u32,
            ) -> u32;
        }
        const INFINITE: u32 = 0xFFFFFFFF;
        const WAIT_OBJECT_0: u32 = 0;

        let handles = [start_event, stop_event];
        loop {
            let ret = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
            if ret == WAIT_OBJECT_0 {
                // CAPTURE_START
                log::info!("[EVENT] Received CAPTURE_START");
                cap_active.store(true, Ordering::SeqCst);
                if let Some(t) = cap_handle.lock().unwrap().as_ref() {
                    t.unpark();
                }
            } else if ret == WAIT_OBJECT_0 + 1 {
                // CAPTURE_STOP
                log::info!("[EVENT] Received CAPTURE_STOP");
                cap_active.store(false, Ordering::SeqCst);
            } else {
                log::error!("[EVENT] WaitForMultipleObjects failed, ret={}", ret);
                break;
            }
        }
        cap_active.store(false, Ordering::SeqCst);
        std::process::exit(0);
    });

    // 捕获线程：按需 GDI 捕获
    let cap_thread = std::thread::spawn(move || {
        *cap_thread_handle.lock().unwrap() = Some(std::thread::current());
        crate::sos_capture::run(crate::sos_shmem::SHMEM_NAME, capture_active);
    });

    let _ = input_thread.join();
    let _ = event_thread.join();
    let _ = cap_thread.join();
    Ok(())
}

// ── 主进程中启动 SYSTEM 子进程 ──

/// 在 Session 1 中以 SYSTEM 身份启动自身副本。
/// 成功返回子进程句柄（用于 WaitForSingleObject 监控），失败返回 0。
pub fn launch_system_sub_process(debug: bool) -> isize {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "rustdesk-sos.exe".into());
        let args = if debug {
            "--service --debug"
        } else {
            "--service"
        };
        let cmd = format!("\"{}\" {}", exe, args);
        log::info!("Starting SYSTEM sub-process: {}", cmd);

        let cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { SosRunAsSystemInSession1(cmd_wide.as_ptr()) };
        if handle != 0 {
            log::info!(
                "SYSTEM sub-process created via CreateProcessWithTokenW, handle=0x{:x}",
                handle
            );
            return handle;
        }
        log::error!("SosRunAsSystemInSession1 failed, fallback to run_as_system");
        match librustdesk::platform::run_as_system(args) {
            Ok(()) => {
                log::info!("fallback run_as_system succeeded (no handle for monitor)");
                0
            }
            Err(e) => {
                log::error!("fallback also failed: {}", e);
                0
            }
        }
    }
    #[cfg(not(windows))]
    0
}
