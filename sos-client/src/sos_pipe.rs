//! 命名管道工具模块

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

const INVALID_HANDLE_VALUE: isize = -1;

// ── raw FFI ──

extern "system" {
    fn CreateNamedPipeW(
        p: *const u16,
        open: u32,
        mode: u32,
        max: u32,
        ob: u32,
        ib: u32,
        t: u32,
        sa: *const u8,
    ) -> isize;
    fn ConnectNamedPipe(h: isize, ol: *const u8) -> i32;
    fn CreateFileW(n: *const u16, a: u32, s: u32, sa: *const u8, c: u32, f: u32, t: isize)
        -> isize;
    fn ReadFile(h: isize, b: *mut u8, n: u32, r: *mut u32, ol: *const u8) -> i32;
    fn WriteFile(h: isize, b: *const u8, n: u32, w: *mut u32, ol: *const u8) -> i32;
    fn CloseHandle(h: isize) -> i32;
    fn GetLastError() -> u32;
}

pub const PIPE_ACCESS_OUTBOUND: u32 = 2;
const PIPE_ACCESS_INBOUND: u32 = 1;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const GENERIC_READ: u32 = 0x80000000;
const OPEN_EXISTING: u32 = 3;
const ERROR_PIPE_CONNECTED: u32 = 535;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 从管道读取一条完整消息（4B 长度 + payload）。失败返回 None（管道断开）。
pub unsafe fn read_message(handle: isize) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    let mut read = 0u32;
    if ReadFile(handle, len.as_mut_ptr(), 4, &mut read, std::ptr::null()) == 0 || read != 4 {
        return None;
    }
    let pl = u32::from_le_bytes(len) as usize;
    if pl == 0 {
        return Some(Vec::new());
    }
    if pl > 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; pl];
    let mut total = 0usize;
    while total < pl {
        let mut chunk = 0u32;
        if ReadFile(
            handle,
            buf.as_mut_ptr().add(total),
            (pl - total) as u32,
            &mut chunk,
            std::ptr::null(),
        ) == 0
            || chunk == 0
        {
            return None;
        }
        total += chunk as usize;
    }
    Some(buf)
}

// ── 管道客户端 / 服务器 ──

/// 连接到命名管道（客户端），重试直到成功或超时。
/// `timeout_secs` 秒内每 100ms 尝试一次；成功返回句柄。
pub fn connect_pipe_client(name: &str, timeout_secs: u32) -> Option<isize> {
    let wide = to_wide(name);
    for _ in 0..timeout_secs * 10 {
        unsafe {
            let h = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if h != INVALID_HANDLE_VALUE {
                return Some(h);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    None
}

/// 创建命名管道服务器，返回 (发送端, 线程句柄)。
/// 后台线程 accept 一个客户端后，循环将 `Sender` 收到的数据写入管道。
/// 管道断开或 `Sender` 关闭时线程退出。
pub fn create_pipe_server(
    name: &str,
    access: u32,
) -> (
    std::sync::mpsc::Sender<Vec<u8>>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let name = name.to_owned();
    let handle = std::thread::spawn(move || unsafe {
        let wide = to_wide(&name);
        let pipe = CreateNamedPipeW(
            wide.as_ptr(),
            access,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            std::ptr::null(),
        );
        if pipe == INVALID_HANDLE_VALUE {
            log::error!("[PIPE] CreateNamedPipeW({name}) failed: {}", GetLastError());
            return;
        }
        log::info!("[PIPE] Server: {name}");
        if ConnectNamedPipe(pipe, std::ptr::null()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
            CloseHandle(pipe);
            return;
        }
        log::info!("[PIPE] Client connected on {name}");
        while let Ok(data) = rx.recv() {
            if !send_pipe_message(pipe, &data) {
                break;
            }
        }
        CloseHandle(pipe);
    });
    (tx, handle)
}

/// 向管道写入一条消息（4B 长度前缀 + 数据体）。成功返回 true。
unsafe fn send_pipe_message(pipe: isize, data: &[u8]) -> bool {
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.extend_from_slice(&(data.len() as u32).to_le_bytes());
    packet.extend_from_slice(data);
    let mut written = 0u32;
    WriteFile(
        pipe,
        packet.as_ptr(),
        packet.len() as u32,
        &mut written,
        std::ptr::null(),
    ) != 0
}

// ── 全局发送端（main → sos_connection → pipe）─

static DOWN_TX: std::sync::RwLock<Option<std::sync::mpsc::Sender<Vec<u8>>>> =
    std::sync::RwLock::new(None);

pub fn set_down_tx(tx: std::sync::mpsc::Sender<Vec<u8>>) {
    *DOWN_TX.write().unwrap() = Some(tx);
}

pub fn try_send_input(msg: Vec<u8>) {
    if let Some(tx) = DOWN_TX.read().unwrap().as_ref() {
        tx.send(msg).ok();
    }
}
