//! GDI 帧捕获模块
//!
//! UAC 安全桌面时，SYSTEM 子进程通过 GDI 抓屏写入 SHMEM。

#[cfg(windows)]
extern "C" {
    fn SosSwitchToInputDesktop() -> i32;
}

use std::time::Duration;
use scrap::{Capturer, Frame, TraitCapturer, TraitPixelBuffer};
use crate::sos_shmem::{
    SosShmem,
    SHMEM_ADDR_CAPTURE_FRAME_INFO, SHMEM_ADDR_CAPTURE_WOULDBLOCK,
    SHMEM_ADDR_CAPTURE_FRAME_COUNTER, SHMEM_ADDR_CAPTURE_FRAME,
};

/// GDI 捕获写 SHMEM（主线程阻塞）。
pub fn run(shmem_name: &str) {
    const ADDR_FRAME: usize = SHMEM_ADDR_CAPTURE_FRAME;

    log::info!("[CAP] Opening SHMEM: {}", shmem_name);

    let shmem = match SosShmem::open_existing(shmem_name) {
        Ok(m) => m,
        Err(e) => { log::error!("[CAP] Failed to open SHMEM: {}", e); return; }
    };
    log::info!("[CAP] SHMEM opened size={}", shmem.len());
    if shmem.len() < ADDR_FRAME {
        log::error!("[CAP] SHMEM too small: {} < {}", shmem.len(), ADDR_FRAME);
        return;
    }

    let mut displays = match scrap::Display::all() {
        Ok(d) => d,
        Err(e) => { log::error!("[CAP] Failed to enumerate displays: {}", e); return; }
    };
    if displays.is_empty() { log::error!("[CAP] No display"); return; }
    let display = displays.remove(0);
    let dw = display.width() as usize;
    let dh = display.height() as usize;
    log::info!("[CAP] Display: {}x{}", dw, dh);

    // UAC 安全桌面只可用 GDI（DXGI 不可用）
    let mut capturer = match Capturer::new(display) {
        Ok(mut c) => { c.set_gdi(); log::info!("[CAP] Capturer GDI"); c }
        Err(e) => { log::error!("[CAP] Failed to create capturer: {:?}", e); return; }
    };

    let mut first = true;
    let mut cap_err_count = 0u32;
    let mut frame_count = 0u64;
    let mut last_heartbeat = std::time::Instant::now();

    loop {
        match capturer.frame(Duration::from_millis(33)) {
            Ok(frame) => {
                if let Frame::PixelBuffer(pixels) = frame {
                    let data = pixels.data();
                    let len = data.len();
                    if len > shmem.len().saturating_sub(ADDR_FRAME) {
                        log::error!("[CAP] Frame too large: {}", len);
                        break;
                    }
                    shmem.write(ADDR_FRAME, data);
                    shmem.write(SHMEM_ADDR_CAPTURE_WOULDBLOCK, &1i32.to_ne_bytes());
                    let info = [&len.to_ne_bytes()[..], &dw.to_ne_bytes()[..], &dh.to_ne_bytes()[..]].concat();
                    shmem.write(SHMEM_ADDR_CAPTURE_FRAME_INFO, &info);
                    unsafe {
                        let ptr = shmem.as_ptr().add(SHMEM_ADDR_CAPTURE_FRAME_COUNTER);
                        let old = *(ptr as *const i32);
                        std::ptr::write_volatile(ptr as *mut i32, if old == i32::MAX { 0 } else { old + 1 });
                    }
                    if first { log::info!("[CAP] First frame written, len={}", len); first = false; }
                    frame_count += 1;
                    cap_err_count = 0;
                    if last_heartbeat.elapsed().as_secs() >= 5 {
                        log::info!("[CAP] Heartbeat: {} frames written (GDI)", frame_count);
                        last_heartbeat = std::time::Instant::now();
                    }
                }
            }
            Err(e) => {
                cap_err_count += 1;
                if librustdesk::platform::windows::desktop_changed() {
                    log::info!("[CAP] Desktop changed, switching...");
                    crate::sos_system::log_token_info("CAP_BEFORE_DESKTOP_SWITCH");
                    let switched = unsafe { SosSwitchToInputDesktop() != 0 };
                    log::info!("[CAP] SosSwitchToInputDesktop returned {}", switched);
                    crate::sos_system::log_token_info("CAP_AFTER_DESKTOP_SWITCH");
                    // 重建 GDI DC（旧 DC 在新桌面画面冻结）
                    capturer.set_gdi();
                    log::info!("[CAP] GDI DC recreated");
                    cap_err_count = 0;
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    log::error!("[CAP] Capture error #{}({:?}): {:?}", cap_err_count, e.kind(), e);
                } else if first && cap_err_count % 100 == 0 {
                    log::warn!("[CAP] Still waiting for first frame... ({})", cap_err_count);
                }
                std::thread::sleep(Duration::from_millis(33));
            }
        }
    }
    log::info!("[CAP] Capture loop ended");
}
