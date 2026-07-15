//! SOS 精简连接处理器
//!
//! 替代 `src/server/connection.rs`，实现精简的事件循环：
//! 密钥交换 → 登录验证 → 视频/输入/剪贴板/文件 7 路并发

use crate::sos_config::SosConfig;
use hbb_common::protobuf::Message as ProtobufMessage;
use hbb_common::{protos::message::*, ResultType, Stream};

/// 处理单个远程连接
pub async fn handle(
    stream: Stream,
    peer_addr: std::net::SocketAddr,
    config: SosConfig,
    pwd_refresh_tx: Option<&tokio::sync::mpsc::UnboundedSender<()>>,
) -> ResultType<()> {
    let addr_str = peer_addr.ip().to_string();
    log::info!(
        "New connection from {}, performing key exchange...",
        addr_str
    );

    // 检查登录频率限制
    let wait = check_login_rate_limit(&addr_str);
    if wait > 0 {
        log::warn!("Rate limit for {}, wait {}s", addr_str, wait);
        return Ok(());
    }

    // Phase 1: 密钥交换 + 加密层
    let mut stream = match setup_encrypted_stream(stream, &config.id).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Key exchange failed: {}", e);
            return Ok(());
        }
    };

    // Phase 2: 登录验证循环
    // 与 RustDesk 一致：先发送 Hash(salt+challenge)，然后循环等待 LoginRequest
    // 验证失败时不重新发送 Hash，仅发送错误让客户端重试（使用同一组 salt/challenge）
    log::info!("Waiting for login request...");

    // 生成 salt 和 challenge（salt 使用持久化值，确保 token 复用跨连接有效）
    // 注意：与上游一致，salt 是持久化的，challenge 每次连接随机
    use hbb_common::rand::Rng;
    use hbb_common::sha2::{Digest, Sha256};
    let salt = crate::sos_config::RegistryConfig::get_password_salt();
    let challenge: String = (0..6)
        .map(|_| {
            hbb_common::rand::thread_rng().sample(hbb_common::rand::distributions::Alphanumeric)
                as char
        })
        .collect();

    // 发送 Hash 给客户端（仅一次）
    {
        let mut hash_msg = Hash::new();
        hash_msg.salt = salt.clone();
        hash_msg.challenge = challenge.clone();
        let mut msg = Message::new();
        msg.set_hash(hash_msg);
        stream.send(&msg).await?;
    }

    let mut login_attempts = 0;
    const MAX_LOGIN_ATTEMPTS: u32 = 5;
    loop {
        // 等待 LoginRequest（不重新发送 Hash）
        let login_data = match stream.next_timeout(60_000).await {
            Some(Ok(d)) => d,
            Some(Err(e)) => {
                log::info!("Stream error while waiting for login: {}", e);
                return Ok(());
            }
            None => {
                log::info!("Timeout waiting for login request");
                return Ok(());
            }
        };

        let login_msg = match Message::parse_from_bytes(&login_data) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !login_msg.has_login_request() {
            continue;
        }

        let login_req = login_msg.login_request();
        let received_h2 = &login_req.password;

        // 确定用于验证的密码
        let password_to_check = if !config.password.is_empty() {
            config.password.clone()
        } else {
            let current = crate::sos_config::get_current_password();
            if !current.is_empty() {
                current
            } else {
                String::new()
            }
        };

        let authorized = if !password_to_check.is_empty() {
            // 与 RustDesk 客户端一致：salt/challenge 是字符串，直接拼接到哈希
            // h1 = SHA256(password || salt)
            // h2 = SHA256(h1 || challenge)
            let mut hasher = Sha256::new();
            hasher.update(password_to_check.as_bytes());
            hasher.update(salt.as_bytes());
            let h1 = hasher.finalize();

            let mut hasher2 = Sha256::new();
            hasher2.update(h1);
            hasher2.update(challenge.as_bytes());
            let expected_h2 = hasher2.finalize();

            let match_ = received_h2 == expected_h2.as_slice();
            match_
        } else {
            false
        };

        if authorized {
            log::info!("Client authorized, starting services...");
            clear_login_failures(&addr_str);
            let is_file_transfer = login_msg.login_request().has_file_transfer();
            send_login_response(&mut stream).await?;

            if is_file_transfer {
                log::info!("File transfer connection detected");
                // 上游 behavior: 不主动发送初始目录列表，等待客户端 ReadDir 请求
                // 客户端打开文件传输 UI 后会自动发送 ReadDir，我们在 handle_incoming_message 中即时响应
                let result = run_file_transfer_loop(stream).await;
                log::info!("Connection closed");
                if let Some(tx) = pwd_refresh_tx {
                    let _ = tx.send(());
                }
                return result;
            }
            break;
        } else if received_h2.is_empty() {
            // 空密码 = 客户端尚未输入密码（正在显示密码输入框）
            // 不报错，不增加尝试计数，继续等待
            log::info!("Empty password received, waiting for user to input...");
            continue;
        } else {
            login_attempts += 1;
            log::warn!(
                "Login authorization failed from {} (attempt {})",
                addr_str,
                login_attempts
            );
            record_login_failure(&addr_str);
            // 发送错误消息，不关闭连接（客户端会弹出重试对话框）
            send_login_error(&mut stream, "Wrong Password").await;
            if login_attempts >= MAX_LOGIN_ATTEMPTS {
                log::warn!("Too many login attempts from {}, closing", addr_str);
                send_close_reason(&mut stream, "Wrong Password").await;
                return Ok(());
            }
        }
    }
    // 登录响应已在授权成功后发送

    // Phase 3: 启动所有服务
    let result = run_service_loop(stream, config).await;

    // Phase 4: 连接清理
    log::info!("Connection closed");
    // 只在认证成功的连接关闭后才刷新密码（防止中间失败也刷新）
    if let Some(tx) = pwd_refresh_tx {
        let _ = tx.send(());
    }
    result
}

/// 密钥交换 + 设置加密层
///
/// 与 RustDesk `create_tcp_connection` 一致：
/// 1. 生成本次会话的临时 NaCl box 密钥对
/// 2. 构造 IdPk { id: 设备ID, pk: NaCl公钥 }，用 Ed25519 签名
/// 3. 发送 SignedId 消息（含签名后的 IdPk）
/// 4. 等待对端回复 PublicKey 消息
/// 5. 用 NaCl box 解密对称密钥，设置加密层
async fn setup_encrypted_stream(mut stream: Stream, device_id: &str) -> ResultType<Stream> {
    use hbb_common::sodiumoxide::crypto::box_;
    use hbb_common::sodiumoxide::crypto::sign;

    // 获取本机 Ed25519 密钥对（用于签名）
    let (sk_bytes, pk_bytes) = crate::sos_config::RegistryConfig::get_key_pair();
    if sk_bytes.len() != sign::SECRETKEYBYTES || pk_bytes.len() != sign::PUBLICKEYBYTES {
        anyhow::bail!(
            "Invalid Ed25519 key pair: sk={}, pk={} (expected {},{})",
            sk_bytes.len(),
            pk_bytes.len(),
            sign::SECRETKEYBYTES,
            sign::PUBLICKEYBYTES
        );
    }
    let mut sk_arr = [0u8; sign::SECRETKEYBYTES];
    sk_arr.copy_from_slice(&sk_bytes);
    let ed_sk = sign::SecretKey(sk_arr);

    // 生成临时 NaCl box 密钥对
    let (na_pk, na_sk) = box_::gen_keypair();

    // 构造 IdPk 并序列化
    let id_pk_bytes = hbb_common::protos::message::IdPk {
        id: device_id.to_string(),
        pk: hbb_common::bytes::Bytes::from(na_pk.0.to_vec()),
        ..Default::default()
    }
    .write_to_bytes()?;

    // 用 Ed25519 签名
    let signed_id = sign::sign(&id_pk_bytes, &ed_sk);

    // 发送 SignedId 消息
    let mut msg_out = hbb_common::protos::message::Message::new();
    msg_out.set_signed_id(hbb_common::protos::message::SignedId {
        id: signed_id.into(),
        ..Default::default()
    });
    stream.send(&msg_out).await?;

    // 等待 PublicKey 响应
    let pk_data = stream
        .next_timeout(10_000)
        .await
        .ok_or_else(|| anyhow::anyhow!("Timeout waiting for PublicKey"))??;
    let pk_msg = hbb_common::protos::message::Message::parse_from_bytes(&pk_data)?;
    let public_key = pk_msg.public_key();

    // 如果 asymmetric_value 为空，表示对端不认识本端公钥
    // （相当于 RustDesk 的 "Force to update pk" 分支）
    if public_key.asymmetric_value.is_empty() {
        log::warn!("Remote peer doesn't know our public key, connection cannot be secured");
        // 不 bail，与 RustDesk create_tcp_connection 一致（继续但不加密）
        // 对端会主动断开连接，调用方应触发 RegisterPk 重新注册
        return Err(anyhow::anyhow!("Peer doesn't know our public key"));
    }

    // 用 NaCl box 解密对称密钥
    stream.set_key(hbb_common::tcp::Encrypt::decode(
        &public_key.symmetric_value,
        &public_key.asymmetric_value,
        &na_sk,
    )?);

    log::debug!("Encrypted stream established");
    Ok(stream)
}

/// 登录失败追踪（指数退避暴力破解防护）
const BACKOFF_BASE_SECS: u64 = 2; // 2^failures 秒
const BACKOFF_MAX_SECS: u64 = 1800; // 30 分钟上限
const IDLE_RESET_SECS: u64 = 7200; // 2 小时无失败重置

struct LoginFailure {
    count: u32,
    last_fail: std::time::Instant,
}

static LOGIN_FAILURES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, LoginFailure>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 检查该地址是否被限流。返回等待秒数（0=允许登录）。
fn check_login_rate_limit(peer_addr: &str) -> u64 {
    let map = LOGIN_FAILURES.lock().unwrap();
    if let Some(state) = map.get(peer_addr) {
        let elapsed = state.last_fail.elapsed().as_secs();
        if elapsed > IDLE_RESET_SECS {
            return 0; // 空闲超时，重置
        }
        let wait = BACKOFF_BASE_SECS.min(BACKOFF_MAX_SECS) << (state.count - 1);
        let wait = wait.min(BACKOFF_MAX_SECS);
        if elapsed < wait {
            return wait - elapsed;
        }
    }
    0
}

/// 记录登录失败
fn record_login_failure(peer_addr: &str) {
    let mut map = LOGIN_FAILURES.lock().unwrap();
    let state = map.entry(peer_addr.to_string()).or_insert(LoginFailure {
        count: 0,
        last_fail: std::time::Instant::now(),
    });
    state.count = (state.count + 1).min(20); // 上限 20 次
    state.last_fail = std::time::Instant::now();
    log::info!("Login failure #{} from {}", state.count, peer_addr);
}

/// 登录成功清除失败记录
fn clear_login_failures(peer_addr: &str) {
    let mut map = LOGIN_FAILURES.lock().unwrap();
    map.remove(peer_addr);
}

/// 发送登录错误（不关闭连接，让客户端重试）
async fn send_login_error(stream: &mut Stream, err: &str) {
    let mut msg = Message::new();
    let mut res = hbb_common::protos::message::LoginResponse::new();
    res.set_error(err.to_string());
    msg.set_login_response(res);
    let _ = stream.send(&msg).await;
}

/// 发送登录成功响应
///
/// 填充 PeerInfo 以告知控制端本机信息，
/// 与 RustDesk 的 send_logon_response_and_keep_alive() 对齐。
async fn send_login_response(stream: &mut Stream) -> ResultType<()> {
    let mut peer_info = PeerInfo::new();
    // 获取主机名
    let hostname = get_hostname();
    if !hostname.is_empty() {
        peer_info.username = hostname;
    }
    peer_info.version = env!("CARGO_PKG_VERSION").to_string();
    peer_info.platform = std::env::consts::OS.to_string();

    // 填充显示器信息（RustDesk 客户端需要此信息来显示画面）
    if let Ok(displays) = scrap::Display::all() {
        for (i, display) in displays.iter().enumerate() {
            let mut info = DisplayInfo::new();
            info.width = display.width() as i32;
            info.height = display.height() as i32;
            info.name = format!("Display {}", i);
            info.online = true;
            peer_info.displays.push(info);
        }
        peer_info.current_display = 0;
        log::info!("Sent display info: {} displays", peer_info.displays.len());

        // 填充支持的分辨率列表（控制端据此显示"更改分辨率"菜单）
        if let Some(d) = displays.get(0) {
            use hbb_common::message_proto::SupportedResolutions;
            peer_info.resolutions = Some(SupportedResolutions {
                resolutions: librustdesk::platform::resolutions(&d.name()),
                ..Default::default()
            })
            .into();
        }
    }

    // 上报功能支持（客户端据此决定输入模式等行为）
    use hbb_common::message_proto::Features;
    peer_info.features = hbb_common::protobuf::MessageField::some(Features {
        privacy_mode: false,
        terminal: false,
        ..Default::default()
    });
    let mut encoding = scrap::codec::Encoder::supported_encoding();
    encoding.av1 = false;
    if let Some(i444) = encoding.i444.as_mut() {
        i444.av1 = false;
    }
    peer_info.encoding = hbb_common::protobuf::MessageField::some(encoding);

    let mut login_resp = LoginResponse::new();
    login_resp.set_peer_info(peer_info);

    let mut msg = Message::new();
    msg.set_login_response(login_resp);
    stream.send(&msg).await?;
    log::debug!("LoginResponse sent");
    Ok(())
}

/// 获取本机主机名
fn get_hostname() -> String {
    #[cfg(windows)]
    {
        // Windows 上使用 COMPUTERNAME 环境变量
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOSTNAME").unwrap_or_default()
    }
}

/// 运行主服务循环（视频 + 输入 + 剪贴板 + 文件传输）
async fn run_service_loop(mut stream: Stream, _config: SosConfig) -> ResultType<()> {
    use tokio::time::{sleep, Duration};

    // 文件传输
    let (ft_tx, mut ft_rx) =
        tokio::sync::mpsc::unbounded_channel::<hbb_common::message_proto::Message>();
    let mut file_transfer = crate::sos_file_transfer::FileTransferHandler::new(ft_tx);

    // ── 订阅上游 video_service + clipboard_service ──
    use hbb_common::tokio::time::Instant as TokioInstant;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(
        TokioInstant,
        std::sync::Arc<hbb_common::protos::message::Message>,
    )>();
    let (tx_video, mut rx_video) = tokio::sync::mpsc::unbounded_channel::<(
        TokioInstant,
        std::sync::Arc<hbb_common::protos::message::Message>,
    )>();
    let conn_id = 1;

    if let Some(video_svc) = crate::sos_config::VIDEO_SVC.get() {
        let inner = librustdesk::ConnInner::new(conn_id, Some(tx.clone()), Some(tx_video.clone()));
        librustdesk::service::Service::on_subscribe(video_svc, inner);
        log::info!("Subscribed to upstream video service as conn #{}", conn_id);
    }
    if let Some(clip_svc) = crate::sos_config::CLIPBOARD_SVC.get() {
        let inner = librustdesk::ConnInner::new(conn_id, Some(tx.clone()), None);
        librustdesk::service::Service::on_subscribe(clip_svc, inner);
        log::info!(
            "Subscribed to upstream clipboard service as conn #{}",
            conn_id
        );
    }

    // ── 订阅光标和位置服务（使客户端显示正常鼠标样式而非触控样式）──
    let cursor_svc = librustdesk::server::input_service::new_cursor();
    let inner = librustdesk::ConnInner::new(conn_id, Some(tx.clone()), None);
    librustdesk::service::Service::on_subscribe(&cursor_svc, inner);
    log::info!("Subscribed to cursor service as conn #{}", conn_id);

    let pos_svc = librustdesk::server::input_service::new_pos();
    let inner = librustdesk::ConnInner::new(conn_id, Some(tx.clone()), None);
    librustdesk::service::Service::on_subscribe(&pos_svc, inner);
    log::info!("Subscribed to position service as conn #{}", conn_id);

    // ── 注册 cliprdr 通道（文件剪贴板引擎的回调通道）──
    let rx_cliprdr = clipboard::get_rx_cliprdr_server(conn_id);
    log::info!("Registered cliprdr channel for conn #{}", conn_id);
    let mut rx_cliprdr_guard = rx_cliprdr.lock().await;

    // 通知 QoS 系统有新连接，并初始化延迟（否则 delay.fps=None → 卡 INIT_FPS=15）
    {
        let mut qos = librustdesk::video_service::VIDEO_QOS.lock().unwrap();
        qos.on_connection_open(conn_id);
        // 以 10ms 低延迟 seed QoS，使 FPS 能从 15 开始上调
        qos.user_network_delay(conn_id, 10);
    }

    let heartbeat_interval = Duration::from_secs(10);
    let mut test_delay_timer = tokio::time::interval(Duration::from_secs(1));
    let mut network_delay = 0u32;
    let mut last_test_delay: Option<std::time::Instant> = None;

    // ── 定期发送 portable_service_running = true ──
    // 上游 connection.rs:portable_check() 在 is_installed()=true 时直接 return，
    // 不会发送 CmShowElevation(false) 和 Misc.portable_service_running=true。
    // Flutter 的 onPeerInfo() 会重置 _running=false，因此我们需要持续发送 true。
    let mut running_timer = tokio::time::interval(Duration::from_secs(3));
    // 发送初始 portable_service_running=true（之后的定期刷新由 running_timer 完成）
    {
        let mut misc = Misc::new();
        misc.set_portable_service_running(true);
        let mut msg = Message::new();
        msg.set_misc(misc);
        let _ = stream.send(&msg).await;
    }

    loop {
        tokio::select! {
            // 视频帧（来自上游 video_service 的 tx_video 通道）
            Some((_ts, vf_msg)) = rx_video.recv() => {
                // 通知 video_service 帧已取出（避免 VideoFrameController 等待 3 秒超时）
                if let Some(hbb_common::message_proto::message::Union::VideoFrame(vf)) = &vf_msg.union {
                    librustdesk::video_service::notify_video_frame_fetched(
                        vf.display as usize, conn_id, None);
                }
                if let Err(e) = stream.send(&*vf_msg).await {
                    log::error!("Failed to send video frame: {}", e);
                    send_close_reason(&mut stream, "Send error").await;
                    break;
                }
            }

            // 普通消息（来自上游 video_service 的 tx 通道）
            Some((_ts, msg)) = rx.recv() => {
                if let Err(e) = stream.send(&*msg).await {
                    log::error!("Failed to send message: {}", e);
                    send_close_reason(&mut stream, "Send error").await;
                    break;
                }
            }

            // cliprdr 文件剪贴板消息（来自 C 引擎的回调，转发到远程客户端）
            clip_msg = rx_cliprdr_guard.recv() => {
                if let Some(clip) = clip_msg {
                    let msg = librustdesk::clipboard_file::clip_2_msg(clip);
                    if let Err(e) = stream.send(&msg).await {
                        log::error!("Failed to send cliprdr message: {}", e);
                        send_close_reason(&mut stream, "Send error").await;
                        break;
                    }
                }
            }

            // 接收远程消息
            msg = stream.next() => {
                match msg {
                    Some(Ok(data)) => {
                        // 先检查是否是 TestDelay（需要在主循环处理以访问 last_test_delay）
                        if hbb_common::message_proto::Message::parse_from_bytes(&data)
                            .ok()
                            .map(|m| m.has_test_delay())
                            .unwrap_or(false)
                        {
                            if let Some(tm) = last_test_delay.take() {
                                let rtt = tm.elapsed().as_millis() as u32;
                                if rtt > 0 {
                                    network_delay = rtt;
                                    librustdesk::video_service::VIDEO_QOS
                                        .lock().unwrap()
                                        .user_network_delay(conn_id, rtt);
                                }
                            }
                        } else if let Err(e) = handle_incoming_message(data, &mut file_transfer, conn_id, &mut stream).await {
                            log::error!("Error handling message: {}", e);
                        }
                    }
                    Some(Err(e)) => {
                        log::error!("Stream recv error: {}", e);
                        send_close_reason(&mut stream, "Stream error").await;
                        break;
                    }
                    None => {
                        log::info!("Stream closed by remote");
                        send_close_reason(&mut stream, "Remote close").await;
                        break;
                    }
                }
            }

            // 文件传输响应（tokio mpsc 直接 await）
            Some(resp) = ft_rx.recv() => {
                if let Err(e) = stream.send(&resp).await {
                    log::error!("Failed to send file response: {}", e);
                    send_close_reason(&mut stream, "File send error").await;
                    break;
                }
            }

            // 文件传输 send job 轮询
            _ = sleep(if file_transfer.has_send_jobs() { Duration::from_millis(10) } else { Duration::from_secs(1) }) => {
                file_transfer.poll_send_jobs().await;
            }

            // TestDelay：每 1 秒发送给客户端（供其显示延迟和码率）
            _ = test_delay_timer.tick() => {
                // 记录发送时间戳，供收到回复时计算 RTT
                if last_test_delay.is_none() {
                    last_test_delay = Some(std::time::Instant::now());
                    let mut td = TestDelay::new();
                    td.time = hbb_common::get_time();
                    td.last_delay = network_delay;
                    td.target_bitrate = librustdesk::video_service::VIDEO_QOS
                        .lock().unwrap().bitrate();
                    let mut msg = Message::new();
                    msg.set_test_delay(td);
                    let _ = stream.send(&msg).await;
                }
                // 每秒调用一次延迟回执检测（与上游一致）
                if let Some(tm) = last_test_delay {
                    librustdesk::video_service::VIDEO_QOS
                        .lock().unwrap()
                        .user_delay_response_elapsed(conn_id, tm.elapsed().as_millis() as u128);
                }
            }

            // 心跳超时检测
            _ = sleep(heartbeat_interval) => {
                log::trace!("Heartbeat tick");
            }

            // 定期刷新 portable_service_running=true（应对 Flutter 端 onPeerInfo 重置 _running=false）
            _ = running_timer.tick() => {
                let mut misc = Misc::new();
                misc.set_portable_service_running(true);
                let mut msg = Message::new();
                msg.set_misc(misc);
                let _ = stream.send(&msg).await;
            }
        }
    }

    // 取消订阅上游视频服务
    if let Some(video_svc) = crate::sos_config::VIDEO_SVC.get() {
        librustdesk::service::Service::on_unsubscribe(video_svc, conn_id);
        log::info!(
            "Unsubscribed from upstream video service (conn #{})",
            conn_id
        );
    }

    // 移除 cliprdr 通道
    clipboard::remove_channel_by_conn_id(conn_id);
    log::info!("Removed cliprdr channel for conn #{}", conn_id);

    // 通知 QoS 系统连接已关闭
    librustdesk::video_service::VIDEO_QOS
        .lock()
        .unwrap()
        .on_connection_close(conn_id);

    // 恢复控制端改过的分辨率
    librustdesk::server::display_service::restore_resolutions();

    Ok(())
}

/// 文件传输专用循环（不启动视频/剪贴板服务）
async fn run_file_transfer_loop(mut stream: Stream) -> ResultType<()> {
    use tokio::time::{sleep, Duration};

    let (ft_tx, mut ft_rx) =
        tokio::sync::mpsc::unbounded_channel::<hbb_common::message_proto::Message>();
    let mut file_transfer = crate::sos_file_transfer::FileTransferHandler::new(ft_tx);
    let mut keepalive_timer = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(data)) => {
                        if let Err(e) = handle_incoming_message(data, &mut file_transfer, 0, &mut stream).await {
                            log::error!("Error handling message: {}", e);
                        }
                    }
                    Some(Err(e)) => {
                        log::info!("Stream error: {}", e);
                        break;
                    }
                    None => {
                        log::info!("File transfer stream closed by remote");
                        break;
                    }
                }
            }
            Some(resp) = ft_rx.recv() => {
                if let Err(e) = stream.send(&resp).await {
                    log::error!("Failed to send file response: {}", e);
                    break;
                }
            }
            _ = sleep(if file_transfer.has_send_jobs() { Duration::from_millis(10) } else { Duration::from_secs(1) }) => {
                file_transfer.poll_send_jobs().await;
            }
            _ = keepalive_timer.tick() => {
                let mut misc = Misc::new();
                misc.set_portable_service_running(true);
                let mut msg = Message::new();
                msg.set_misc(misc);
                let _ = stream.send(&msg).await;
            }
        }
    }
    Ok(())
}

/// 发送关闭原因给远程端
async fn send_close_reason(stream: &mut Stream, reason: &str) {
    let mut misc = Misc::new();
    let reason = if reason.is_empty() {
        "Closed manually by the peer"
    } else {
        reason
    };
    misc.set_close_reason(reason.to_string());
    let mut msg = Message::new();
    msg.set_misc(misc);
    let _ = stream.send(&msg).await;
    log::info!("Sent close reason: {}", reason);
}

/// 处理接收到的远程消息
async fn handle_incoming_message(
    data: hbb_common::bytes::BytesMut,
    file_transfer: &mut crate::sos_file_transfer::FileTransferHandler,
    conn_id: i32,
    stream: &mut Stream,
) -> ResultType<()> {
    if data.is_empty() {
        return Ok(());
    }

    let msg = match Message::parse_from_bytes(&data) {
        Ok(m) => m,
        Err(_) => return Ok(()), // 忽略无法解析的消息
    };

    // 调试日志：打印键盘事件类型（用于排查 IME 问题）
    if msg.has_key_event() {
        let ke = msg.key_event();
        log::trace!(
            "[IME_DEBUG] KeyEvent down={} CtrlKey={} Chr={} Uni={} Seq(len={})",
            ke.down,
            ke.has_control_key(),
            ke.has_chr(),
            ke.has_unicode(),
            if ke.has_seq() { ke.seq().len() } else { 0 }
        );
    }

    if log::log_enabled!(log::Level::Trace) {
        log_msg_types(&msg);
    }

    if msg.has_mouse_event() {
        // 序列化 MouseEvent 原始字节 → 管道 → SYSTEM 子进程调上游 handle_mouse_
        let me = msg.mouse_event();
        let proto_bytes = me.write_to_bytes().unwrap_or_default();
        let mut data = Vec::with_capacity(4 + proto_bytes.len());
        data.extend_from_slice(&crate::sos_constants::MSG_MOUSE.to_ne_bytes());
        data.extend_from_slice(&proto_bytes);
        crate::sos_pipe::try_send_input(data);
    } else if msg.has_key_event() {
        // 序列化 KeyEvent 原始字节 → 管道 → SYSTEM 子进程调上游 handle_key
        let ke = msg.key_event();
        let proto_bytes = ke.write_to_bytes().unwrap_or_default();
        let mut data = Vec::with_capacity(4 + proto_bytes.len());
        data.extend_from_slice(&crate::sos_constants::MSG_KEY.to_ne_bytes());
        data.extend_from_slice(&proto_bytes);
        crate::sos_pipe::try_send_input(data);
    } else if msg.has_clipboard() {
        // 单个剪贴板（文本/图片）
        librustdesk::clipboard::update_clipboard(
            vec![msg.clipboard().clone()],
            librustdesk::clipboard::ClipboardSide::Host,
        );
    } else if msg.has_multi_clipboards() {
        // 多格式剪贴板（文本/图片/特殊格式）
        let mcb = msg.multi_clipboards();
        librustdesk::clipboard::update_clipboard(
            mcb.clipboards.clone(),
            librustdesk::clipboard::ClipboardSide::Host,
        );
    } else if msg.has_cliprdr() {
        // 文件剪贴板协议（Cliprdr）- 使用上游 cliprdr C 引擎处理
        #[cfg(windows)]
        {
            if let Some(clip) = librustdesk::clipboard_file::msg_2_clip(msg.cliprdr().clone()) {
                let _ = clipboard::ContextSend::proc(|context| {
                    context
                        .server_clip_file(conn_id, clip)
                        .map_err(|e| e.into())
                });
            }
        }
        #[cfg(not(windows))]
        log::warn!("Cliprdr messages not supported on this platform");
    } else if msg.has_misc() {
        let misc = msg.misc();
        // 调试日志
        if misc.has_option() {
            log::info!("[IME_DEBUG] Misc::Option fps={}", misc.option().custom_fps);
        }
        if misc.has_switch_display() {
            log::info!(
                "[IME_DEBUG] Misc::SwitchDisplay display={}",
                misc.switch_display().display
            );
        }
        if misc.has_video_received() {
            log::trace!("[IME_DEBUG] Misc::VideoReceived");
        }
        // 视频帧确认（VideoReceived）→ 通知 video_service 释放下一帧
        if misc.has_video_received() {
            librustdesk::video_service::notify_video_frame_fetched_by_conn_id(conn_id, None);
        }
        // 客户端选项更新（含 image_quality, custom_fps, supported_decoding 等）
        if misc.has_option() {
            let opt = misc.option();
            if opt.custom_fps > 0 {
                librustdesk::video_service::VIDEO_QOS
                    .lock()
                    .unwrap()
                    .user_custom_fps(conn_id, opt.custom_fps as _);
            }
            if let Ok(q) = opt.image_quality.enum_value() {
                use hbb_common::message_proto::ImageQuality;
                // SOS: VP9 在高分辨率下码率不足会丢帧，强制不低于 Best 画质
                let v = match q {
                    ImageQuality::NotSet if opt.custom_image_quality > 0 => {
                        opt.custom_image_quality.max(ImageQuality::Best as i32)
                    }
                    ImageQuality::Low | ImageQuality::Balanced => ImageQuality::Best as i32,
                    ImageQuality::Best => ImageQuality::Best as i32,
                    _ => q as i32,
                };
                if v > 0 {
                    librustdesk::video_service::VIDEO_QOS
                        .lock()
                        .unwrap()
                        .user_image_quality(conn_id, v);
                }
            }
            if let Some(sd) = opt.supported_decoding.clone().take() {
                scrap::codec::Encoder::update(scrap::codec::EncodingUpdate::Update(conn_id, sd));
            }
        }
        // 显示器切换请求
        if misc.has_switch_display() {
            let sd = misc.switch_display();
            let idx = sd.display as usize;
            log::info!("Switch display requested: #{}", idx);
        }
        // 分辨率变更请求（ChangeResolution 已废弃但仍需兼容；ChangeDisplayResolution 1.2.4+）
        if misc.has_change_resolution() {
            let r = misc.change_resolution();
            handle_change_resolution(None, r.width as usize, r.height as usize);
        }
        if misc.has_change_display_resolution() {
            let dr = misc.change_display_resolution();
            handle_change_resolution(
                Some(dr.display as usize),
                dr.resolution.width as usize,
                dr.resolution.height as usize,
            );
        }
    } else if msg.has_file_action() {
        file_transfer.handle_action(msg.file_action());
        // 响应由 tokio mpsc channel 经 select! 中 ft_rx.recv() 异步发送
    } else if msg.has_file_response() {
        use hbb_common::message_proto::file_response;
        let resp = msg.file_response();
        match resp.union {
            Some(file_response::Union::Block(ref block)) => {
                file_transfer.handle_data(block).await;
            }
            Some(file_response::Union::Done(ref d)) => {
                log::info!(
                    "[FT] File transfer done: id={} file_num={}",
                    d.id,
                    d.file_num
                );
                file_transfer.handle_done(d.id, d.file_num);
            }
            Some(file_response::Union::Error(ref e)) => {
                log::info!(
                    "[FT] File transfer error: id={} file_num={} error={}",
                    e.id,
                    e.file_num,
                    e.error
                );
                file_transfer.handle_error(e.id);
            }
            Some(file_response::Union::Digest(ref d)) => {
                log::info!("[FT] File digest: id={} file_num={}", d.id, d.file_num);
                // Digest handling for overwrite detection - not implemented yet
                file_transfer.handle_digest(d);
            }
            _ => {
                log::debug!("[FT] Received FileResponse (unhandled type)");
            }
        }
    } else {
        log::debug!("[IME_DEBUG] Unknown message type (no handler)");
    }

    Ok(())
}

/// 处理分辨率变更请求（来自控制端的 Misc::ChangeResolution / ChangeDisplayResolution）
fn handle_change_resolution(display_idx: Option<usize>, width: usize, height: usize) {
    match librustdesk::server::display_service::try_get_displays() {
        Ok(displays) => {
            let idx = display_idx.unwrap_or(0);
            if let Some(display) = displays.get(idx) {
                let cur_w = display.width() as usize;
                let cur_h = display.height() as usize;
                // 请求的分辨率与当前一致 → 跳过（控制端可能在连接握手时发送了兼容字段）
                if width == cur_w && height == cur_h {
                    log::debug!("Change resolution skipped: already {}x{}", width, height);
                    return;
                }
                log::info!(
                    "Change resolution requested: display={:?}, {}x{} (current: {}x{})",
                    display_idx,
                    width,
                    height,
                    cur_w,
                    cur_h,
                );
                let name = display.name();
                // 保存原始分辨率，以便控制端断开后恢复
                let original = (display.width() as i32, display.height() as i32);
                librustdesk::server::display_service::set_last_changed_resolution(
                    &name,
                    original,
                    (width as i32, height as i32),
                );
                // 通知 video_service 用新分辨率重建编码器
                if let Some(vs) = crate::sos_config::VIDEO_SVC.get() {
                    vs.set_option_bool(librustdesk::video_service::OPTION_REFRESH, true);
                }
                // 分辨率切换放在独立线程，避免阻塞当前 Tokio 任务
                // （video_service 的 src_stride 错误会自动恢复，无需手动等待）
                let name = name.to_string();
                std::thread::spawn(move || {
                    if let Err(e) = librustdesk::platform::change_resolution(&name, width, height) {
                        log::error!(
                            "Failed to change resolution '{}' to {}x{}: {:?}",
                            name,
                            width,
                            height,
                            e
                        );
                    }
                });
            } else {
                log::warn!("Display #{} not found", idx);
            }
        }
        Err(e) => log::warn!("Failed to enumerate displays: {}", e),
    }
}

/// 打印消息的所有 union 类型（用于调试客户端发送了什么）
fn log_msg_types(msg: &Message) {
    use hbb_common::message_proto::message::Union;
    if let Some(ref u) = msg.union {
        let name = match u {
            Union::LoginRequest(_) => "LoginRequest",
            Union::LoginResponse(_) => "LoginResponse",
            Union::Hash(_) => "Hash",
            Union::PeerInfo(_) => "PeerInfo",
            Union::MouseEvent(_) => "MouseEvent",
            Union::KeyEvent(_) => "KeyEvent",
            Union::Clipboard(_) => "Clipboard",
            Union::VideoFrame(_) => "VideoFrame",
            Union::Misc(_) => "Misc",
            Union::FileAction(_) => {
                // 展开 FileAction 子类型
                if let Some(fa) = msg.file_action().union.as_ref() {
                    let fa_name = match fa {
                        file_action::Union::ReadDir(_) => "FileAction::ReadDir",
                        file_action::Union::ReadEmptyDirs(_) => "FileAction::ReadEmptyDirs",
                        file_action::Union::Send(_) => "FileAction::Send",
                        file_action::Union::Receive(_) => "FileAction::Receive",
                        file_action::Union::Cancel(_) => "FileAction::Cancel",
                        file_action::Union::RemoveDir(_) => "FileAction::RemoveDir",
                        file_action::Union::RemoveFile(_) => "FileAction::RemoveFile",
                        file_action::Union::Create(_) => "FileAction::Create",
                        file_action::Union::Rename(_) => "FileAction::Rename",
                        file_action::Union::AllFiles(_) => "FileAction::AllFiles",
                        file_action::Union::SendConfirm(_) => "FileAction::SendConfirm",
                        _ => "FileAction::Other",
                    };
                    return log::trace!("[MSG] received: {}", fa_name);
                }
                "FileAction"
            }
            Union::FileResponse(_) => "FileResponse",
            Union::Cliprdr(_) => "Cliprdr",
            Union::MultiClipboards(_) => "MultiClipboards",
            Union::PublicKey(_) => "PublicKey",
            Union::SignedId(_) => "SignedId",
            Union::TestDelay(_) => "TestDelay",
            Union::MessageBox(_) => "MessageBox",
            Union::Auth2fa(_) => "Auth2fa",
            Union::CursorData(_) => "CursorData",
            Union::CursorPosition(_) => "CursorPosition",
            Union::CursorId(_) => "CursorId",
            Union::VoiceCallRequest(_) => "VoiceCallRequest",
            Union::VoiceCallResponse(_) => "VoiceCallResponse",
            Union::SwitchSidesResponse(_) => "SwitchSidesResponse",
            Union::PointerDeviceEvent(_) => "PointerDeviceEvent",
            Union::ScreenshotRequest(_) => "ScreenshotRequest",
            Union::ScreenshotResponse(_) => "ScreenshotResponse",
            Union::TerminalAction(_) => "TerminalAction",
            Union::TerminalResponse(_) => "TerminalResponse",
            _ => "Unknown/Other",
        };
        log::trace!("[MSG] received: {}", name);
    }
}
