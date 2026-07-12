//! 输入事件分发模块（纯逻辑，不依赖管道）
//!
//! protobuf 反序列化 → 调上游 input_service / enigo。

use crate::sos_constants::{MSG_MOUSE, MSG_KEY, MSG_SHUTDOWN};

/// 分发单个输入事件。返回 false 表示 shutdown。
pub fn dispatch(msg_type: u32, payload: &[u8]) -> bool {
    match msg_type {
        MSG_SHUTDOWN => false,
        MSG_MOUSE => { dispatch_mouse(payload); true }
        MSG_KEY => { dispatch_key(payload); true }
        other => { log::debug!("[INPUT] Unknown msg_type: {}", other); true }
    }
}

fn dispatch_mouse(data: &[u8]) {
    use hbb_common::protobuf::Message;
    match hbb_common::message_proto::MouseEvent::parse_from_bytes(data) {
        Ok(me) => librustdesk::input_service::handle_mouse_(&me, -1, String::new(), 0, true, false),
        Err(e) => log::error!("[INPUT] Failed to parse MouseEvent: {}", e),
    }
}

fn dispatch_key(data: &[u8]) {
    use hbb_common::protobuf::Message;
    let ke = match hbb_common::message_proto::KeyEvent::parse_from_bytes(data) {
        Ok(k) => k,
        Err(e) => { log::error!("[INPUT] Failed to parse KeyEvent: {}", e); return; }
    };
    if ke.has_chr() {
        if let Some(c) = std::char::from_u32(ke.chr()) {
            let mut en = enigo::Enigo::new();
            use enigo::KeyboardControllable;
            if ke.down { let _ = en.key_down(enigo::Key::Layout(c)); }
            else { let _ = en.key_up(enigo::Key::Layout(c)); }
        }
        return;
    }
    librustdesk::input_service::handle_key(&ke);
}
