//! SOS 信令注册与连接接入模块
//!
//! 与 RustDesk 信令服务器通信，负责：
//! 1. 设备注册（RegisterPeer 心跳）
//! 2. 公钥注册（RegisterPk）
//! 3. 监听 PunchHole（直连）和 RequestRelay（中继）消息
//! 4. 建立数据连接并派发到 sos_connection::handle()

use crate::sos_config::SosConfig;
use hbb_common::protobuf::Message as ProtobufMessage;
use hbb_common::rendezvous_proto::*;
use hbb_common::socket_client::{check_port, connect_tcp, new_udp_for};
use hbb_common::IntoTargetAddr;
use hbb_common::ResultType;
use std::time::Instant;

/// 运行信令注册与连接接入循环
///
/// 连接到信令服务器 → 注册设备 ID → 公钥注册 → 持续监听 PunchHole/RequestRelay
/// `password_refresh_tx`：连接断开后通知主进程刷新临时密码
pub async fn run(
    mut config: SosConfig,
    _tray_tx: tokio::sync::mpsc::UnboundedSender<crate::sos_tray::TrayCommand>,
    password_refresh_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> ResultType<()> {
    log::info!("[TRACE] sos_rendezvous::run() ENTERED");
    log::info!("[TRACE] config.id='{}' rendezvous='{}' password.len={}",
        config.id, config.rendezvous_server, config.password.len());
    let host = check_port(
        &config.rendezvous_server,
        crate::sos_constants::RENDEZVOUS_PORT,
    );
    log::info!("Connecting to rendezvous server: {}", host);

    let (mut socket, target_addr) =
        new_udp_for(&host, crate::sos_constants::CONNECT_TIMEOUT).await?;
    let mut peer_addr: std::net::SocketAddr = target_addr.into_target_addr()?.into();
    log::info!("UDP connection to rendezvous server established");

    // 首次注册
    send_register_peer(&mut socket, &peer_addr, &config.id, 0).await?;

    // 主动发送 RegisterPk（不等待服务器请求）
    // SOS 每次启动生成新的 Ed25519 密钥对，必须主动注册到服务器
    let (_sk, pk) = crate::sos_config::RegistryConfig::get_key_pair();
    if !pk.is_empty() {
        if let Err(e) = send_register_pk(&mut socket, &peer_addr, &config, &pk).await {
            log::warn!("Proactive RegisterPk failed: {}", e);
        } else {
            log::info!("Proactive RegisterPk sent");
        }
    }

    // NAT 类型测试（异步，不阻塞主循环）
    let rz_host = host.clone();
    tokio::spawn(async move {
        test_nat_type(&rz_host).await;
    });

    let mut last_reg = Instant::now();
    let reg_interval = std::time::Duration::from_millis(crate::sos_constants::REG_INTERVAL);
    let listen_timeout = std::time::Duration::from_secs(5);
    let serial = std::sync::atomic::AtomicU32::new(1);

    let mut loop_count = 0u64;
    loop {
        loop_count += 1;
        log::info!("[TRACE] rendezvous loop iteration #{} start", loop_count);
        // 定时重新注册（心跳）
        if last_reg.elapsed() >= reg_interval {
            log::info!("[TRACE] heartbeat due, sending RegisterPeer");
            let s = serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Err(e) = send_register_peer(&mut socket, &peer_addr, &config.id, s).await {
                log::warn!("RegisterPeer heartbeat failed: {}", e);
                // 不退出，下次循环重试
            } else {
                last_reg = Instant::now();
            }
        }

        // 监听信令消息
        log::info!("[NET_DEBUG] Waiting for UDP message (timeout={}ms)...", listen_timeout.as_millis());
        match hbb_common::timeout(listen_timeout.as_millis() as u64, socket.next()).await {
            Ok(Some(Ok((bytes, _from)))) => {
                log::info!("[NET_DEBUG] Received {} bytes via UDP", bytes.len());
                log::info!("[NET_DEBUG] Raw bytes hex (first 32): {}", hex::encode(&bytes[..bytes.len().min(32)]));
                match RendezvousMessage::parse_from_bytes(&bytes) {
                    Ok(rm) => {
                        if let Err(e) = handle_rendezvous_message(
                            rm,
                            &mut config,
                            &mut socket,
                            &peer_addr,
                            &password_refresh_tx,
                        )
                        .await
                        {
                            log::warn!("Handle rendezvous message error: {}", e);
                        }
                    }
                    Err(e) => {
                        log::warn!("[RV_DEBUG] Failed to parse rendezvous message ({} bytes): {}", bytes.len(), e);
                    }
                }
            }
            Ok(Some(Err(e))) => {
                log::warn!("Rendezvous UDP recv error: {}", e);
            }
            Ok(None) => {
                // 连接关闭
                log::warn!("Rendezvous connection closed, reconnecting...");
                match new_udp_for(&host, crate::sos_constants::CONNECT_TIMEOUT).await {
                    Ok((new_sock, new_addr)) => {
                        socket = new_sock;
                        peer_addr = new_addr
                            .into_target_addr()
                            .map(|a| a.into())
                            .unwrap_or_else(|_| {
                                log::warn!("Failed to resolve target addr, using previous");
                                peer_addr
                            });
                        let s = serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) =
                            send_register_peer(&mut socket, &peer_addr, &config.id, s).await
                        {
                            log::warn!("Re-register after reconnection failed: {}", e);
                        }
                        last_reg = Instant::now();
                    }
                    Err(e) => {
                        log::error!("Reconnect failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
            Err(_) => {
                // 超时，正常循环
                log::info!("[NET_DEBUG] UDP recv timeout (no data in {}ms) [TRACE]", listen_timeout.as_millis());
            }
        }
        log::info!("[TRACE] rendezvous loop iteration #{} complete", loop_count);
    }
}

/// 发送 RegisterPeer 消息
async fn send_register_peer(
    socket: &mut hbb_common::udp::FramedSocket,
    peer_addr: &std::net::SocketAddr,
    device_id: &str,
    serial: u32,
) -> ResultType<()> {
    let mut msg = RendezvousMessage::new();
    msg.set_register_peer(RegisterPeer {
        id: device_id.to_owned(),
        serial: serial as i32,
        ..Default::default()
    });
    socket.send(&msg, *peer_addr).await?;
    log::info!("RegisterPeer sent for id={} serial={}", device_id, serial);
    Ok(())
}

/// 处理信令消息
async fn handle_rendezvous_message(
    rm: RendezvousMessage,
    config: &mut SosConfig,
    socket: &mut hbb_common::udp::FramedSocket,
    peer_addr: &std::net::SocketAddr,
    password_refresh_tx: &tokio::sync::mpsc::UnboundedSender<()>,
) -> ResultType<()> {
    // 记录收到的消息类型名称
    let msg_type = match rm.union {
        Some(rendezvous_message::Union::PunchHole(_)) => "PunchHole",
        Some(rendezvous_message::Union::RequestRelay(_)) => "RequestRelay",
        Some(rendezvous_message::Union::RegisterPeerResponse(_)) => "RegisterPeerResponse",
        Some(rendezvous_message::Union::RegisterPkResponse(_)) => "RegisterPkResponse",
        Some(rendezvous_message::Union::FetchLocalAddr(_)) => "FetchLocalAddr",
        _ => "Other",
    };
    log::info!("[RV_DEBUG] handle_rendezvous_message: type={}", msg_type);
    match rm.union {
        Some(rendezvous_message::Union::PunchHole(ph)) => {
            log::info!("收到 PunchHole（直连请求），处理传入连接...");
            let config = (*config).clone();
            let refresh_tx = password_refresh_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_punch_hole(ph, config, refresh_tx).await {
                    log::error!("PunchHole connection failed: {}", e);
                }
            });
        }
        Some(rendezvous_message::Union::RequestRelay(rr)) => {
            log::info!("收到 RequestRelay（中继请求），建立中继连接...");
            let config = (*config).clone();
            let refresh_tx = password_refresh_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_request_relay(rr, config, refresh_tx).await {
                    log::error!("Relay connection failed: {}", e);
                }
            });
        }
        Some(rendezvous_message::Union::RegisterPeerResponse(rpr)) => {
            if rpr.request_pk {
                log::info!("信令服务器请求 RegisterPk（公钥注册）");
                let (_sk, pk) = crate::sos_config::RegistryConfig::get_key_pair();
                if !pk.is_empty() {
                    if let Err(e) = send_register_pk(socket, peer_addr, config, &pk).await {
                        log::warn!("Send RegisterPk failed: {}", e);
                    }
                } else {
                    log::warn!("密钥对未初始化，跳过 RegisterPk");
                }
            }
        }
        Some(rendezvous_message::Union::RegisterPkResponse(rpr)) => {
            log::info!("RegisterPk response: {:?}", rpr.result);
            match rpr.result.enum_value_or_default() {
                register_pk_response::Result::OK => {
                    crate::sos_config::RegistryConfig::set_key_confirmed(true);
                    log::info!("公钥注册成功");
                }
                register_pk_response::Result::UUID_MISMATCH => {
                    log::warn!("UUID_MISMATCH，设备身份冲突，更换 ID 后重新注册");
                    // 1. 标记 key_confirmed = false
                    crate::sos_config::RegistryConfig::set_key_confirmed(false);
                    // 2. 生成新 ID 并写入注册表，同时更新内存 config
                    config.id = crate::sos_config::RegistryConfig::update_id();
                    // 3. 用新 ID 重新注册公钥
                    let (_sk, pk) = crate::sos_config::RegistryConfig::get_key_pair();
                    if !pk.is_empty() {
                        if let Err(e) = send_register_pk(socket, peer_addr, config, &pk).await {
                            log::warn!("Re-register after UUID_MISMATCH failed: {}", e);
                        } else {
                            log::info!("Re-register after UUID_MISMATCH succeeded");
                        }
                    }
                }
                other => {
                    log::warn!("公钥注册失败: {:?}", other);
                }
            }
        }
        Some(rendezvous_message::Union::FetchLocalAddr(fla)) => {
            log::info!("FetchLocalAddr received, connecting back via TCP...");
            let config = (*config).clone();
            let refresh_tx = password_refresh_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = send_local_addr_fla(fla, config, refresh_tx).await {
                    log::error!("LocalAddr/TCP connection failed: {}", e);
                }
            });
        }
        _ => {
            log::info!("收到未处理的消息类型");
        }
    }
    Ok(())
}

/// 发送 RegisterPk（公钥注册）消息
async fn send_register_pk(
    socket: &mut hbb_common::udp::FramedSocket,
    peer_addr: &std::net::SocketAddr,
    config: &SosConfig,
    pk: &[u8],
) -> ResultType<()> {
    // 与 RustDesk 主库一致：发送设备 UUID 用于服务器端设备身份识别
    let uuid = hbb_common::get_uuid();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: config.id.clone(),
        uuid: uuid.into(),
        pk: pk.to_vec().into(),
        ..Default::default()
    });
    socket.send(&msg, *peer_addr).await?;
    log::info!("RegisterPk sent");
    Ok(())
}

/// 回复 LocalAddr + 建立数据连接
///
/// 与 RustDesk 主库一致：建立一条 TCP 连接到信令服务器，
/// 通过 AddrMangle 编码本端 socket 地址后以 protobuf 响应，
/// 然后丢弃此 TCP 连接，在同一端口监听对端直连。
///
/// 信令服务器收到 LocalAddr 后会将本端的 LAN 地址转发给对端，
/// 对端尝试直连本端。本端 accept 对端的 TCP 连接后作为数据通道。
async fn send_local_addr_fla(
    fla: FetchLocalAddr,
    config: SosConfig,
    password_refresh_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> ResultType<()> {
    log::info!("[CONN_DEBUG] >>> send_local_addr_fla called: relay_server='{}'", fla.relay_server);
    use hbb_common::socket_client::connect_tcp;

    // 连接到信令服务器
    let rendezvous_host = check_port(
        &config.rendezvous_server,
        crate::sos_constants::RENDEZVOUS_PORT,
    );
    let mut tcp_stream =
        connect_tcp(rendezvous_host, crate::sos_constants::CONNECT_TIMEOUT).await?;

    // 获取本端 TCP socket 地址，用 AddrMangle 编码
    let local_sock_addr = tcp_stream.local_addr();
    let local_encoded = hbb_common::AddrMangle::encode(local_sock_addr);

    // 从 FetchLocalAddr 解码对端地址，再重新编码（与 RustDesk 主库一致）
    let peer_addr = hbb_common::AddrMangle::decode(&fla.socket_addr);
    let socket_addr_encoded = hbb_common::AddrMangle::encode(peer_addr);

    // 构造 LocalAddr 响应（使用 RendezvousMessage）
    let mut msg = hbb_common::rendezvous_proto::RendezvousMessage::new();
    msg.set_local_addr(hbb_common::rendezvous_proto::LocalAddr {
        id: config.id.clone(),
        socket_addr: socket_addr_encoded.into(),
        local_addr: local_encoded.into(),
        relay_server: fla.relay_server.clone(),
        version: "1.4.4".to_string(),
        socket_addr_v6: Default::default(),
        special_fields: hbb_common::protobuf::SpecialFields::new(),
    });

    // 通过 TCP 发送响应（序列化为 bytes 后用 send_raw）
    let bytes = msg.write_to_bytes()?;
    tcp_stream.send_raw(bytes).await?;
    log::info!("LocalAddr sent via TCP, local_addr={}", local_sock_addr);

    // ---- 与 RustDesk accept_connection 一致 ----
    // 信令服务器已处理 LocalAddr 并关闭连接。本端在同一端口监听，
    // 对端（远程客户端）会主动连接本端进行直连。
    drop(tcp_stream);

    let listener = hbb_common::tcp::new_listener(local_sock_addr, true).await?;
    log::info!(
        "Listening on {} for incoming intranet connection...",
        local_sock_addr
    );

    // 等待对端连接（超时 10 秒）
    let (stream, _accept_addr) = hbb_common::timeout(10_000, listener.accept())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for incoming connection"))?
        .map_err(|e| anyhow::anyhow!("Accept error: {}", e))?;
    stream.set_nodelay(true).ok();
    let stream_local_addr = stream.local_addr()?;
    log::info!("Accepted intranet connection from {}", stream_local_addr);

    crate::sos_connection::handle(
        hbb_common::Stream::from(stream, stream_local_addr),
        "0.0.0.0:0".parse().unwrap(),
        config.clone(),
        Some(&password_refresh_tx),
    )
    .await
}

/// 测试 NAT 类型（异步，应仅在启动时调用一次）
///
/// 通过向信令服务器主端口和主端口 ±1 建立 TCP 连接，
/// 发送 TestNatRequest 并对比服务器看到的源端口来判断 NAT 类型。
/// 结果存入注册表，供后续打洞决策使用。
async fn test_nat_type(rendezvous_host: &str) {
    use hbb_common::rendezvous_proto::{rendezvous_message, TestNatRequest};
    use hbb_common::socket_client::increase_port;

    let servers = [
        rendezvous_host.to_string(),
        increase_port(rendezvous_host, 1), // port+1
    ];

    let mut ports = [0i32; 2];
    for (i, server) in servers.iter().enumerate() {
        let server = server.clone(); // owned String for connect_tcp
        let result = async {
            let mut stream = connect_tcp(server, crate::sos_constants::CONNECT_TIMEOUT).await?;

            let mut msg = hbb_common::rendezvous_proto::RendezvousMessage::new();
            msg.set_test_nat_request(TestNatRequest {
                serial: 1,
                ..Default::default()
            });
            stream.send(&msg).await?;

            // 读取响应，超时 5 秒
            let bytes = match hbb_common::timeout(5_000, stream.next()).await {
                Ok(Some(Ok(b))) => b,
                Ok(Some(Err(e))) => Err(anyhow::anyhow!("recv: {}", e))?,
                Ok(None) => Err(anyhow::anyhow!("stream closed"))?,
                Err(_) => Err(anyhow::anyhow!("timeout"))?,
            };

            if let Ok(rm) =
                hbb_common::rendezvous_proto::RendezvousMessage::parse_from_bytes(&bytes)
            {
                if let Some(rendezvous_message::Union::TestNatResponse(tnr)) = rm.union {
                    log::info!("TestNat[{}] server saw port: {}", i, tnr.port);
                    ports[i] = tnr.port;
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            log::warn!("TestNat attempt[{}] failed: {}", i, e);
        }
    }

    let nat_type = if ports[0] > 0 && ports[1] > 0 && ports[0] == ports[1] {
        NatType::ASYMMETRIC
    } else {
        NatType::SYMMETRIC
    };
    crate::sos_config::set_nat_type(nat_type as i32);
    log::info!(
        "NAT type test result: {:?} (ports={}:{})",
        nat_type,
        ports[0],
        ports[1]
    );
}

/// 处理 PunchHole（直连打洞请求）
///
/// 对端想通过直连 TCP 连接。我们从 PunchHole 中提取对端地址
/// 并尝试建立 TCP 连接。
///
/// 如果任意一方为 SYMMETRIC NAT，直接走中继（打洞无效）。
async fn handle_punch_hole(
    ph: PunchHole,
    config: SosConfig,
    password_refresh_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> ResultType<()> {
    log::info!("[CONN_DEBUG] >>> handle_punch_hole called: relay_server='{}' socket_addr.len={}",
        ph.relay_server, ph.socket_addr.len());
    use hbb_common::protobuf::Enum;
    use hbb_common::rendezvous_proto::NatType;

    // 检查双方 NAT 类型：如果任意一方为 SYMMETRIC，打洞无效，直接中继
    let remote_nat = ph.nat_type.enum_value().unwrap_or(NatType::UNKNOWN_NAT);
    let our_nat =
        NatType::from_i32(crate::sos_config::get_nat_type()).unwrap_or(NatType::UNKNOWN_NAT);

    log::info!("[CONN_DEBUG] PunchHole NAT check: remote={:?} us={:?}", remote_nat, our_nat);
    if remote_nat == NatType::SYMMETRIC || our_nat == NatType::SYMMETRIC {
        log::info!(
            "NAT 类型不兼容 (remote={:?}, us={:?})，直接走中继",
            remote_nat,
            our_nat
        );
        return handle_relay_fallback(
            &ph.relay_server,
            &config,
            &password_refresh_tx,
            ph.socket_addr.clone(),
            None,
            "",
        )
        .await;
    }

    // 尝试从 socket_addr 解析对端地址
    let peer_addr: &str = &String::from_utf8_lossy(&ph.socket_addr);

    if peer_addr.is_empty() {
        log::warn!("PunchHole 缺少对端地址，尝试中继");
        return handle_relay_fallback(
            &ph.relay_server,
            &config,
            &password_refresh_tx,
            ph.socket_addr.clone(),
            None,
            "",
        )
        .await;
    }

    log::info!("[CONN_DEBUG] 尝试直连对端: {}", peer_addr);
    // 先尝试 IPv4
    let result = connect_tcp(peer_addr, crate::sos_constants::CONNECT_TIMEOUT).await;
    log::info!("[CONN_DEBUG] IPv4 direct connect result: {:?}", result.as_ref().map(|_| "OK").unwrap_or("FAIL"));
    match result {
        Ok(stream) => {
            log::info!("IPv4 直连成功，启动连接处理...");
            return crate::sos_connection::handle(
                stream,
                "0.0.0.0:0".parse().unwrap(),
                config,
                Some(&password_refresh_tx),
            )
            .await;
        }
        Err(e) => {
            // 如果 PunchHole 包含 IPv6 地址，尝试 IPv6 直连
            let v6_addr = String::from_utf8_lossy(&ph.socket_addr_v6);
            if !v6_addr.is_empty() {
                log::info!("IPv4 失败 ({}), 尝试 IPv6: {}", e, v6_addr);
                match connect_tcp(v6_addr.as_ref(), crate::sos_constants::CONNECT_TIMEOUT).await {
                    Ok(stream) => {
                        log::info!("IPv6 直连成功，启动连接处理...");
                        return crate::sos_connection::handle(
                            stream,
                            "0.0.0.0:0".parse().unwrap(),
                            config,
                            Some(&password_refresh_tx),
                        )
                        .await;
                    }
                    Err(e2) => {
                        log::warn!("IPv6 直连也失败 ({}), 尝试中继", e2);
                    }
                }
            } else {
                log::warn!("IPv4 直连失败 ({}), 尝试中继", e);
            }
            handle_relay_fallback(
                &ph.relay_server,
                &config,
                &password_refresh_tx,
                ph.socket_addr.clone(),
                None,
                "",
            )
            .await
        }
    }
}

/// 处理 RequestRelay（中继请求）
///
/// 对端要求通过中继服务器建立连接。
/// 关键：必须复用客户端的 uuid，否则中继服务器无法配对双方连接。
async fn handle_request_relay(
    rr: RequestRelay,
    config: SosConfig,
    password_refresh_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> ResultType<()> {
    log::info!("[CONN_DEBUG] >>> handle_request_relay called: relay='{}' uuid.len={} id='{}'",
        rr.relay_server, rr.uuid.len(), rr.id);
    let relay_host = &rr.relay_server;
    if relay_host.is_empty() {
        return Err(anyhow::anyhow!("Relay server address is empty"));
    }
    // 使用客户端的 uuid（客户端已用它连接中继服务器，必须一致）
    let uuid = if rr.uuid.is_empty() {
        None
    } else {
        Some(rr.uuid.clone())
    };
    let peer_id = if rr.id.is_empty() {
        String::new()
    } else {
        rr.id.clone()
    };
    handle_relay_fallback(
        relay_host,
        &config,
        &password_refresh_tx,
        rr.socket_addr.clone(),
        uuid,
        &peer_id,
    )
    .await
}

/// 通过中继服务器建立连接
///
/// 与 RustDesk 主库一致：
/// 1. TCP 连接到信令服务器，发送 RelayResponse（含 uuid、对端地址、中继地址）
/// 2. 信令服务器收到后关闭连接
/// 3. TCP 连接中继服务器，发送 RequestRelay（含 uuid）
/// 4. 中继服务器桥接本端与对端，随后进行密钥交换
///
/// `peer_socket_addr` 是对端（远程客户端）的地址，来自 PunchHole 或 RequestRelay
/// `uuid` 为客户端生成的共享 uuid（来自 RequestRelay），若为 None 则随机生成（PunchHole 回退场景）
/// `peer_id` 为对端设备 ID（来自 RequestRelay），PunchHole 场景下为空字符串
async fn handle_relay_fallback(
    relay_host: &str,
    config: &SosConfig,
    password_refresh_tx: &tokio::sync::mpsc::UnboundedSender<()>,
    peer_socket_addr: hbb_common::bytes::Bytes,
    uuid: Option<String>,
    peer_id: &str,
) -> ResultType<()> {
    log::info!("[CONN_DEBUG] >>> handle_relay_fallback: relay='{}' uuid={:?} peer_id='{}'", relay_host, uuid, peer_id);
    // 1. 向信令服务器发送 RelayResponse
    let rendezvous_host = check_port(
        &config.rendezvous_server,
        crate::sos_constants::RENDEZVOUS_PORT,
    );
    log::info!(
        "[CONN_DEBUG] Step1: connecting to rendezvous server for RelayResponse: {}",
        rendezvous_host
    );

    // uuid：优先使用客户端提供的（RequestRelay 场景），否则随机生成（PunchHole 回退场景）
    let uuid_str = uuid.unwrap_or_else(|| {
        use hbb_common::rand::Rng;
        hbb_common::rand::thread_rng()
            .sample_iter(&hbb_common::rand::distributions::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect()
    });

    {
        let mut stream =
            connect_tcp(rendezvous_host, crate::sos_constants::CONNECT_TIMEOUT).await?;

        // 构造 RelayResponse（与 RustDesk create_relay 一致）
        let mut rr = hbb_common::rendezvous_proto::RelayResponse::new();
        rr.uuid = uuid_str.clone();
        rr.socket_addr = peer_socket_addr;
        rr.relay_server = relay_host.to_string();
        rr.set_id(config.id.clone());
        rr.version = "1.4.4".to_string();
        let mut msg = hbb_common::rendezvous_proto::RendezvousMessage::new();
        msg.set_relay_response(rr);

        let bytes = msg.write_to_bytes()?;
        stream.send_raw(bytes).await?;
        log::info!(
            "[CONN_DEBUG] RelayResponse sent to rendezvous server (uuid={})",
            uuid_str
        );
    } // 信令服务器关闭连接，stream 自动断开

    // 2. 连接中继服务器，发送 RequestRelay（与 RustDesk create_relay_connection 一致）
    let relay_host_port =
        hbb_common::socket_client::check_port(relay_host, hbb_common::config::RELAY_PORT);
    log::info!("[CONN_DEBUG] Step2: connecting to relay server: {}", relay_host_port);

    let mut relay_stream =
        connect_tcp(relay_host_port, crate::sos_constants::CONNECT_TIMEOUT).await?;
    log::info!("[CONN_DEBUG] Relay TCP connection established");

    // 构造 RequestRelay 消息（与上游 create_relay_connection_ 和 client::create_relay 对齐）
    // licence_key：优先使用配置中的 server_pub_key，空则回退 RS_PUB_KEY
    let licence_key = if !config.server_pub_key.is_empty() {
        config.server_pub_key.clone()
    } else {
        hbb_common::config::RS_PUB_KEY.to_string()
    };
    let mut msg = hbb_common::rendezvous_proto::RendezvousMessage::new();
    let mut rr = hbb_common::rendezvous_proto::RequestRelay::new();
    rr.uuid = uuid_str.clone();
    rr.licence_key = licence_key;
    rr.id = peer_id.to_string();
    rr.conn_type = hbb_common::rendezvous_proto::ConnType::DEFAULT_CONN.into();
    msg.set_request_relay(rr);

    let bytes = msg.write_to_bytes()?;
    relay_stream.send_raw(bytes).await?;
    log::info!(
        "[CONN_DEBUG] RequestRelay sent to relay server (uuid={}, peer_id={}), waiting for bridge...",
        uuid_str,
        peer_id
    );

    log::info!("[CONN_DEBUG] Step3: calling sos_connection::handle() via relay stream");
    let ret = crate::sos_connection::handle(
        relay_stream,
        "0.0.0.0:0".parse().unwrap(),
        config.clone(),
        Some(&password_refresh_tx),
    )
    .await;
    log::info!("[CONN_DEBUG] sos_connection::handle() returned: {:?}", ret.as_ref().map(|_| "OK").unwrap_or("ERR"));
    ret
}
