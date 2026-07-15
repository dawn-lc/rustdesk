//! SOS 客户端专用常量定义
//!
//! 从 `hbb_common::config` 中提取 SOS 需要的常量，避免依赖完整 Config 结构。

/// 信令服务器注册间隔（毫秒）
/// 与 hbb_common::config::REG_INTERVAL 一致
pub const REG_INTERVAL: u64 = 15_000;

/// TCP 连接超时（毫秒）
pub const CONNECT_TIMEOUT: u64 = 18_000;

/// 默认信令服务器 — 引用 hbb_common 的配置，与 RustDesk 主项目保持一致
pub fn default_rendezvous_server() -> String {
    hbb_common::config::RENDEZVOUS_SERVERS
        .first()
        .copied()
        .unwrap_or("rs-ny.rustdesk.com")
        .to_string()
}

/// 信令服务器默认端口
pub use hbb_common::config::RENDEZVOUS_PORT;

/// 注册表路径
pub const REGISTRY_PATH: &str = "SOFTWARE\\RustDeskSOS";

/// 应用名称
pub const APP_NAME: &str = "RustDesk SOS";

/// 输入管道名（Main → System 输入事件）
pub const INPUT_PIPE: &str = r"\\.\pipe\sos_input";

/// 输入管道消息类型
pub const MSG_MOUSE: u32 = 1;
pub const MSG_KEY: u32 = 2;
pub const MSG_SHUTDOWN: u32 = 3;

/// 捕获就绪事件（捕获线程写完首帧 → SetEvent，主进程 WaitForSingleObject）
pub const CAPTURE_READY_EVENT: &str = "SosCaptureReady";

/// 捕获启停事件（主进程 SetEvent → 子进程 WaitForMultipleObjects）
pub const CAPTURE_START_EVENT: &str = "SosCaptureStart";
pub const CAPTURE_STOP_EVENT: &str = "SosCaptureStop";


