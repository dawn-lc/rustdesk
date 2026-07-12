//! SYSTEM 会话 1 特权模块
//!
//! SYSTEM 子进程入口：管道通信、GDI 帧捕获写 SHMEM、输入事件处理、桌面切换。

use hbb_common::ResultType;

#[cfg(windows)]
extern "C" {
    /// 在交互 session 中以 SYSTEM 身份启动进程（sessionId != 0 过滤 winlogon）
    /// 等效上游 impersonate_system::run_as_system，但按 session 过滤。
    /// 返回 0=成功，-1=失败
    pub fn SosRunAsSystemInSession1(cmd: *const u16) -> i32;

    /// 切换到输入桌面（最小权限版本，替代上游 selectInputDesktop 的 GENERIC_WRITE）
    pub fn SosSwitchToInputDesktop() -> i32;
}

// ── 令牌诊断 ──

/// 检查当前进程是否以 SYSTEM 身份运行
#[cfg(windows)]
pub fn is_system_process() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY,
        TokenUser, TOKEN_USER, WinLocalSystemSid, IsWellKnownSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Foundation::HANDLE;

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
        ).is_err() {
            return false;
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool()
    }
}

/// 输出当前进程的令牌/权限诊断信息
#[cfg(windows)]
pub fn log_token_info(stage: &str) {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY, TokenUser, TOKEN_USER,
        TokenElevation, TOKEN_ELEVATION, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL,
        TokenStatistics, TOKEN_STATISTICS,
        WinLocalSystemSid, IsWellKnownSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, GetCurrentProcessId};
    use windows::Win32::Foundation::HANDLE;
    use winapi::um::processthreadsapi::ProcessIdToSessionId;

    unsafe {
        let mut session_id = 0u32;
        let pid = GetCurrentProcessId();
        ProcessIdToSessionId(pid, &mut session_id);

        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            log::warn!("[TOKEN:{}] PID={} Session={} CANNOT_OPEN_TOKEN", stage, pid, session_id);
            return;
        }

        // User SID + SYSTEM check
        let mut size = 0u32;
        GetTokenInformation(token, TokenUser, None, 0, &mut size).ok();
        let mut buf = vec![0u8; size as usize];
        let user_info = if GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), size, &mut size).is_ok() {
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let is_sys = IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool();
            format!("is_system={}", is_sys)
        } else { "SID_UNKNOWN".to_string() };

        // Integrity level
        let mut il_size = 0u32;
        GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut il_size).ok();
        let il_str = if il_size > 0 {
            let mut il_buf = vec![0u8; il_size as usize];
            if GetTokenInformation(token, TokenIntegrityLevel, Some(il_buf.as_mut_ptr() as *mut _), il_size, &mut il_size).is_ok() {
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
            } else { "" }
        } else { "" };
        let il_str = il_str.to_string();

        // Elevation
        let mut elev = TOKEN_ELEVATION::default();
        let mut elev_size = 0u32;
        let elev_str = if GetTokenInformation(token, TokenElevation, Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut elev_size).is_ok() {
            if elev.TokenIsElevated != 0 { "elevated" } else { "not_elevated" }
        } else { "unknown" };

        // Token type (primary/impersonation)
        let mut stats = TOKEN_STATISTICS::default();
        let mut stats_size = 0u32;
        let type_str = if GetTokenInformation(token, TokenStatistics, Some(&mut stats as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32, &mut stats_size).is_ok() {
            match stats.TokenType.0 {
                1 => "Primary",
                2 => "Impersonation",
                _ => "Other",
            }
        } else { "unknown" };

        log::info!(
            "[TOKEN:{}] PID={} Session={} {} Integrity={} Elevation={} Type={}",
            stage, pid, session_id, user_info, il_str, elev_str, type_str,
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

    use crate::sos_pipe::*;
    use crate::sos_constants::INPUT_PIPE;
    log_token_info("SUB_INIT");

    // 连接输入管道
    log::info!("Connecting to input pipe: {}", INPUT_PIPE);
    let pipe = match connect_pipe_client(INPUT_PIPE, 6) {
        Some(h) => h,
        None => { log::error!("Failed to connect input pipe"); return Ok(()); }
    };

    // 启动独立输入线程
    let input_pipe = pipe;
    let input_thread = std::thread::spawn(move || {
        loop {
            let data = match unsafe { read_message(input_pipe) } {
                Some(d) => d,
                None => break,
            };
            if data.len() < 5 { continue; }
            let msg_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            if !crate::sos_input::dispatch(msg_type, &data[4..]) { return; }
        }
        log::warn!("[PIPE] Input pipe disconnected");
        std::process::exit(0);
    });

    // GDI 捕获（主线程阻塞）
    crate::sos_capture::run(crate::sos_shmem::SHMEM_NAME);
    let _ = input_thread.join();
    Ok(())
}

// ── 主进程中启动 SYSTEM 子进程 ──

/// 在 Session 1 中以 SYSTEM 身份启动自身副本。
pub fn launch_system_sub_process(debug: bool) -> bool {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "rustdesk-sos.exe".into());
        let args = if debug { "--service --debug" } else { "--service" };
        let cmd = format!("\"{}\" {}", exe, args);
        log::info!("Starting SYSTEM sub-process: {}", cmd);

        let cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let ok = unsafe { SosRunAsSystemInSession1(cmd_wide.as_ptr()) == 0 };
        if ok {
            log::info!("SYSTEM sub-process created via CreateProcessWithTokenW");
            return true;
        }
        log::error!("SosRunAsSystemInSession1 failed, fallback to run_as_system");
        match librustdesk::platform::run_as_system(args) {
            Ok(()) => { log::info!("fallback run_as_system succeeded"); true }
            Err(e) => { log::error!("fallback also failed: {}", e); false }
        }
    }
    #[cfg(not(windows))]
    false
}


