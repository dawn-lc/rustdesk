//! 输入事件分发模块（纯逻辑，不依赖管道）
//!
//! protobuf 反序列化 → 调上游 input_service / enigo。

use crate::sos_constants::{MSG_KEY, MSG_MOUSE, MSG_SHUTDOWN};
use std::sync::Mutex;
use std::time::Instant;

/// 事件速率追踪器
struct RateTracker {
    count: u64,
    last_log: Instant,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            count: 0,
            last_log: Instant::now(),
        }
    }

    fn tick(&mut self, label: &str) {
        self.count += 1;
        let elapsed = self.last_log.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            let hz = self.count as f64 / elapsed;
            log::info!("[{}] #{} rate={:.0}Hz", label, self.count, hz);
            self.count = 0;
            self.last_log = Instant::now();
        }
    }
}

static MOUSE_RATE: std::sync::LazyLock<Mutex<RateTracker>> =
    std::sync::LazyLock::new(|| Mutex::new(RateTracker::new()));
static KEY_RATE: std::sync::LazyLock<Mutex<RateTracker>> =
    std::sync::LazyLock::new(|| Mutex::new(RateTracker::new()));

/// 分发单个输入事件。返回 false 表示 shutdown。
pub fn dispatch(msg_type: u32, payload: &[u8]) -> bool {
    match msg_type {
        MSG_SHUTDOWN => false,
        MSG_MOUSE => {
            dispatch_mouse(payload);
            MOUSE_RATE.lock().unwrap().tick("MOUSE");
            true
        }
        MSG_KEY => {
            dispatch_key(payload);
            KEY_RATE.lock().unwrap().tick("KEY");
            true
        }
        other => {
            log::debug!("[INPUT] Unknown msg_type: {}", other);
            true
        }
    }
}

fn dispatch_mouse(data: &[u8]) {
    use hbb_common::protobuf::Message;
    let t0 = std::time::Instant::now();
    match hbb_common::message_proto::MouseEvent::parse_from_bytes(data) {
        Ok(me) => {
            let parse_us = t0.elapsed().as_micros();
            librustdesk::input_service::handle_mouse_(&me, 1, String::new(), 0, true, true);
            let handle_us = t0.elapsed().as_micros() - parse_us;
            // 每秒报告一次耗时统计
            static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            static PARSE_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            static HANDLE_TOTAL: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let n = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            PARSE_TOTAL.fetch_add(parse_us as u64, std::sync::atomic::Ordering::Relaxed);
            HANDLE_TOTAL.fetch_add(handle_us as u64, std::sync::atomic::Ordering::Relaxed);
            if n % 100 == 0 {
                let avg_parse = PARSE_TOTAL.load(std::sync::atomic::Ordering::Relaxed) / n;
                let avg_handle = HANDLE_TOTAL.load(std::sync::atomic::Ordering::Relaxed) / n;
                log::info!(
                    "[MOUSE_MSR] #{} parse={}us handle={}us",
                    n,
                    avg_parse,
                    avg_handle
                );
            }
        }
        Err(e) => log::error!("[INPUT] Failed to parse MouseEvent: {}", e),
    }
}

fn dispatch_key(data: &[u8]) {
    use hbb_common::protobuf::Message;
    let ke = match hbb_common::message_proto::KeyEvent::parse_from_bytes(data) {
        Ok(k) => k,
        Err(e) => {
            log::error!("[INPUT] Failed to parse KeyEvent: {}", e);
            return;
        }
    };
    if ke.has_chr() {
        if let Some(c) = std::char::from_u32(ke.chr()) {
            let mut en = enigo::Enigo::new();
            use enigo::KeyboardControllable;
            if ke.down {
                let _ = en.key_down(enigo::Key::Layout(c));
            } else {
                let _ = en.key_up(enigo::Key::Layout(c));
            }
        }
        return;
    }
    librustdesk::input_service::handle_key(&ke);
}
