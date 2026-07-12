//! Windows 系统托盘模块
//!
//! 提供任务栏托盘图标和右键菜单交互。
//! 使用 Win32 API（windows crate）实现，无额外 UI 框架依赖。

#![allow(non_snake_case)]

use std::sync::mpsc;

/// 托盘命令枚举
#[derive(Debug, Clone)]
pub enum TrayCommand {
    /// 退出程序
    Exit,
    /// 左键双击——显示设备信息
    ShowInfo,
}

#[cfg(windows)]
mod win32_impl {
    use super::TrayCommand;
    use hbb_common::ResultType;
    use std::sync::mpsc;
    use windows::Win32::UI::Shell::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::Win32::Foundation::*;
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::System::LibraryLoader::*;
    use windows::Win32::System::DataExchange::*;
    use windows::Win32::System::Memory::*;
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    const WM_TRAY_ICON: u32 = WM_USER + 1;
    const TRAY_ICON_ID: u32 = 1;
    const TIP_UPDATE_TIMER_ID: usize = 2;

    const MENU_SHOW_ID: u16 = 100;
    const MENU_SHOW_PASSWORD: u16 = 101;
    const MENU_EXIT: u16 = 6;

    struct TrayState {
        tx: mpsc::Sender<TrayCommand>,
        device_id: String,
    }

    /// 更新托盘提示文字（只刷新文字，不碰图标）
    pub fn run(tx: mpsc::Sender<TrayCommand>, device_id: String) -> ResultType<()> {
        // 注册窗口类
        let class_name: Vec<u16> = "RustDeskSOS_Tray\0".encode_utf16().collect();
        let hinstance = unsafe { GetModuleHandleW(None)?.into() };

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(tray_window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: HICON::default(),
            hCursor: HCURSOR::default(),
            hbrBackground: HBRUSH(5 as *mut std::ffi::c_void), // COLOR_WINDOW+1
            lpszMenuName: windows::core::PCWSTR::null(),
            lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
        };

        unsafe { RegisterClassW(&wc); } // returns atom (class id), ignore on success

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                windows::core::PCWSTR(class_name.as_ptr()),
                windows::core::w!("RustDeskSOS"),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                HWND::default(),
                HMENU::default(),
                hinstance,
                None,
            )
        }?;

        // 添加托盘图标（提示文字显示 ID 和密码）
        let tip_text = build_tip_text(&device_id);
        let tip: Vec<u16> = format!("{}\0", tip_text).encode_utf16().collect();
        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            uFlags: NIF_MESSAGE | NIF_TIP | NIF_ICON,
            uCallbackMessage: WM_TRAY_ICON,
            szTip: {
                let mut arr = [0u16; 128];
                let len = tip.len().min(127);
                arr[..len].copy_from_slice(&tip[..len]);
                arr
            },
            ..Default::default()
        };

        // 设置托盘图标（从 exe 嵌入的资源加载）
        nid.hIcon = unsafe {
            let hinst = GetModuleHandleW(None).map(|h| HINSTANCE(h.0)).unwrap_or_default();
            LoadIconW(hinst, windows::core::PCWSTR(1 as *const u16))
                .unwrap_or_default()
        };
        nid.uFlags |= NIF_ICON;
        unsafe { let _ = Shell_NotifyIconW(NIM_ADD, &nid); }

        // 创建状态对象并保存到窗口
        let state = Box::into_raw(Box::new(TrayState {
            tx,
            device_id,
        }));
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
        }

        // 消息循环
        let mut msg = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut msg, HWND::default(), 0, 0) };
            if result.0 == 0 || result.0 == -1 {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // 清理
        unsafe { let _ = Shell_NotifyIconW(NIM_DELETE, &nid); }
        unsafe { let _ = Box::from_raw(state); }
        Ok(())
    }

    unsafe extern "system" fn tray_window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_TRAY_ICON {
            let state = get_state(hwnd);
            match lparam.0 as u32 {
                WM_RBUTTONUP => {
                    // 右键菜单前先刷新提示文字
                    update_tip(hwnd, &state.device_id);
                    show_context_menu(hwnd);
                }
                WM_LBUTTONDBLCLK => {
                    let _ = state.tx.send(TrayCommand::ShowInfo);
                }
                _ => {}
            }
            return LRESULT(0);
        }

        if msg == WM_TIMER && wparam.0 as usize == TIP_UPDATE_TIMER_ID {
            let state = get_state(hwnd);
            update_tip(hwnd, &state.device_id);
            return LRESULT(0);
        }

        if msg == WM_COMMAND {
            let state = get_state(hwnd);
            let cmd = (wparam.0 & 0xFFFF) as u16;
            match cmd {
                MENU_SHOW_ID => {
                    let _ = open_clipboard_and_set_text(&state.device_id);
                }
                MENU_SHOW_PASSWORD => {
                    // 从内存获取当前密码再复制
                    let pwd = crate::sos_config::get_current_password();
                    if !pwd.is_empty() {
                        let _ = open_clipboard_and_set_text(&pwd);
                    }
                }
                MENU_EXIT => {
                    let _ = state.tx.send(TrayCommand::Exit);
                }
                _ => {}
            }
            return LRESULT(0);
        }

        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    unsafe fn get_state(hwnd: HWND) -> &'static mut TrayState {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut TrayState;
        &mut *ptr
    }

    /// 更新托盘提示文字（只刷新文字，不碰图标）
    unsafe fn update_tip(hwnd: HWND, device_id: &str) {
        let tip_text = build_tip_text(device_id);
        let tip: Vec<u16> = format!("{}\0", tip_text).encode_utf16().collect();
        let nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            uFlags: NIF_TIP,
            szTip: {
                let mut arr = [0u16; 128];
                let len = tip.len().min(127);
                arr[..len].copy_from_slice(&tip[..len]);
                arr
            },
            ..Default::default()
        };
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    fn build_tip_text(device_id: &str) -> String {
        let pwd = crate::sos_config::get_current_password();
        if pwd.is_empty() {
            format!("RustDesk SOS\nID: {}", device_id)
        } else {
            format!("RustDesk SOS\nID: {}\n密码: {}", device_id, pwd)
        }
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let state = get_state(hwnd);
        if let Ok(menu) = CreatePopupMenu() {
            let id_text = format!("ID: {}\0", state.device_id);
            let id_wide: Vec<u16> = id_text.encode_utf16().collect();
            let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW_ID as usize, windows::core::PCWSTR(id_wide.as_ptr()));

            let pwd = crate::sos_config::get_current_password();
            let pwd_display = if pwd.is_empty() {
                "密码: (未设置)\0".to_string()
            } else {
                format!("密码: {}\0", pwd)
            };
            let pwd_wide: Vec<u16> = pwd_display.encode_utf16().collect();
            let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW_PASSWORD as usize, windows::core::PCWSTR(pwd_wide.as_ptr()));

            let _ = AppendMenuW(menu, MF_SEPARATOR, 0, None);
            let _ = AppendMenuW(menu, MF_STRING, MENU_EXIT as usize, windows::core::w!("退出"));

            let mut point = std::mem::zeroed();
            let _ = GetCursorPos(&mut point);

            let _ = SetForegroundWindow(hwnd);
            let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, None);
            let _ = PostMessageW(hwnd, WM_NULL, WPARAM::default(), LPARAM::default());
            let _ = DestroyMenu(menu);
        }
    }

    fn open_clipboard_and_set_text(text: &str) -> ResultType<()> {
        let wide: Vec<u16> = format!("{}\0", text).encode_utf16().collect();
        unsafe {
            OpenClipboard(HWND::default())?;
            EmptyClipboard()?;
            let hmem = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2)?;
            let ptr = GlobalLock(hmem) as *mut u16;
            if ptr.is_null() {
                CloseClipboard()?;
                return Err(anyhow::anyhow!("GlobalLock failed"));
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
            GlobalUnlock(hmem)?;
            SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(hmem.0))?;
            CloseClipboard()?;
        }
        Ok(())
    }
}

/// 公开的托盘入口（非 Windows 平台提供空实现）
#[cfg(not(windows))]
pub fn run(_tx: mpsc::Sender<TrayCommand>, _device_id: String) -> hbb_common::ResultType<()> {
    log::warn!("System tray is only supported on Windows");
    // 阻塞以保持兼容接口
    std::thread::park();
    Ok(())
}

/// 公开的托盘入口
#[cfg(windows)]
pub fn run(tx: mpsc::Sender<TrayCommand>, device_id: String) -> hbb_common::ResultType<()> {
    win32_impl::run(tx, device_id)
}
