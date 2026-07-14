//! SOS 启动引导模块
//!
//! 处理管理员权限检查、服务启动、信令注册初始化。

use std::io::Write;

/// 检查当前进程是否以管理员权限运行
#[cfg(windows)]
pub fn is_admin() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut return_length = 0u32;
    unsafe {
        if GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .is_err()
        {
            return false;
        }
    }
    elevation.TokenIsElevated != 0
}

/// 非管理员权限时弹窗报错并退出
pub fn show_admin_required_and_exit() -> ! {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let title: Vec<u16> = "权限不足\0".encode_utf16().collect();
        let msg: Vec<u16> =
            "RustDesk SOS 必须以管理员权限运行。\n\n请右键点击程序 → \"以管理员身份运行\"，\n或在命令行中使用管理员权限启动。\0"
                .encode_utf16()
                .collect();
        unsafe {
            MessageBoxW(
                None,
                windows::core::PCWSTR(msg.as_ptr()),
                windows::core::PCWSTR(title.as_ptr()),
                MB_ICONERROR | MB_OK,
            );
        }
    }
    std::process::exit(1);
}

/// 初始化日志系统（控制台输出，用于主进程 --debug 模式）
pub fn init_logger(level: &str) {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(level),
    )
    .format_timestamp_millis()
    .try_init();
}

/// 初始化 SYSTEM 子进程日志（写入 exe 同目录的 rustdesk-sos-system.log）
#[cfg(windows)]
pub fn init_system_logger(level: &str) {
    use std::io::Write;

    let level_filter = match level {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info"  => log::LevelFilter::Info,
        "warn"  => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _       => log::LevelFilter::Info,
    };

    let log_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("rustdesk-sos-system.log")))
        .unwrap_or_else(|| std::path::PathBuf::from("rustdesk-sos-system.log"));

    let file = match std::fs::OpenOptions::new()
        .create(true).append(true).open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            // 无法写文件时退化到 env_logger（stderr）
            init_logger(level);
            log::warn!("Cannot open log file {}: {}", log_path.display(), e);
            return;
        }
    };

    let logger = FileLogger {
        level: level_filter,
        file: std::sync::Mutex::new(file),
    };

    log::set_boxed_logger(Box::new(logger)).ok();
    log::set_max_level(level_filter);
    log::info!("System logger initialized: {}", log_path.display());
}

#[cfg(windows)]
struct FileLogger {
    level: log::LevelFilter,
    file: std::sync::Mutex<std::fs::File>,
}

#[cfg(windows)]
impl log::Log for FileLogger {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let msg = format!(
            "[{}.{:03}] [{:5}] {}\n",
            ts.as_secs(),
            ts.subsec_millis(),
            record.level(),
            record.args(),
        );
        let mut file = self.file.lock().unwrap();
        let _ = file.write_all(msg.as_bytes());
        let _ = file.flush();
        // 同时输出到 stderr，确保控制台可见
        let _ = std::io::stderr().write_all(msg.as_bytes());
    }

    fn flush(&self) {
        let _ = self.file.lock().unwrap().flush();
    }
}

// is_system_process, log_token_info, run_capture_shmem 已移入 sos_system 模块
