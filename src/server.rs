use std::{
    collections::{HashMap, HashSet},
    future::{Future, IntoFuture, pending},
    sync::{
        Arc, Mutex as StdMutex, OnceLock, RwLock as StdRwLock, Weak,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes, BytesMut};
use h3::server::Connection as H3Connection;
use http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use quinn::{Endpoint, EndpointConfig, Runtime, TokioRuntime, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::{debug, info, warn};

use crate::{
    brutal::Hy2CongestionConfig,
    config::{Config, MasqueradeConfig},
    masquerade,
    outbound::{OutboundConnector, OutboundUdpSession},
    protocol::{
        FRAME_TYPE_TCP_REQUEST, HEADER_CC_RX, REQUEST_HEADER_AUTH, STATUS_AUTH_OK, TcpRequest,
        TcpResponse, TcpResponseStatus, decode_varint,
    },
    salamander_socket::SalamanderSocket,
};

const AUTHORITY: &str = "hysteria";
const AUTH_PATH: &str = "/auth";
const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_MASQUERADE_BODY_SIZE: usize = 8 * 1024 * 1024;
const RELAY_BUFFER_SIZE: usize = 32 * 1024;
const MAX_POOLED_RELAY_BUFFERS: usize = 16;
static RELAY_BUFFER_POOL: OnceLock<StdMutex<Vec<Vec<u8>>>> = OnceLock::new();

#[derive(Default)]
pub struct TrafficRegistry {
    users: StdRwLock<HashMap<String, Arc<UserTraffic>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserTrafficSnapshot {
    pub username: String,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub active_connections: u64,
}

#[derive(Default)]
pub(crate) struct UserTraffic {
    uploaded_bytes: AtomicU64,
    downloaded_bytes: AtomicU64,
    active_connections: AtomicU64,
}

impl TrafficRegistry {
    pub fn sync_users(&self, usernames: impl IntoIterator<Item = String>) {
        let usernames = usernames.into_iter().collect::<HashSet<_>>();
        let mut users = self.users.write().expect("traffic registry lock poisoned");
        users.retain(|username, _| usernames.contains(username));
        for username in usernames {
            users.entry(username).or_default();
        }
    }

    pub fn snapshots(&self) -> Vec<UserTrafficSnapshot> {
        let users = self.users.read().expect("traffic registry lock poisoned");
        let mut snapshots = users
            .iter()
            .map(|(username, traffic)| UserTrafficSnapshot {
                username: username.clone(),
                uploaded_bytes: traffic.uploaded_bytes.load(Ordering::Relaxed),
                downloaded_bytes: traffic.downloaded_bytes.load(Ordering::Relaxed),
                active_connections: traffic.active_connections.load(Ordering::Relaxed),
            })
            .collect::<Vec<_>>();
        snapshots.sort_unstable_by(|left, right| left.username.cmp(&right.username));
        snapshots
    }

    pub(crate) fn user(&self, username: &str) -> Arc<UserTraffic> {
        if let Some(traffic) = self
            .users
            .read()
            .expect("traffic registry lock poisoned")
            .get(username)
            .cloned()
        {
            return traffic;
        }
        let mut users = self.users.write().expect("traffic registry lock poisoned");
        Arc::clone(users.entry(username.to_owned()).or_default())
    }
}

impl UserTraffic {
    pub(crate) fn connection(self: &Arc<Self>) -> ActiveConnection {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveConnection(Arc::clone(self))
    }

    pub(crate) fn record_upload(&self, bytes: usize) {
        self.uploaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_download(&self, bytes: usize) {
        self.downloaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

pub(crate) struct ActiveConnection(Arc<UserTraffic>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn run(config: Config) -> Result<()> {
    run_until(config, pending()).await
}

pub async fn run_until<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    run_until_with_traffic(config, Arc::new(TrafficRegistry::default()), shutdown).await
}

pub async fn run_until_with_traffic<F>(
    config: Config,
    traffic: Arc<TrafficRegistry>,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    let listen = config.listen;
    traffic.sync_users(config.users.iter().map(|user| user.name.clone()));
    let users = Arc::new(
        config
            .users
            .iter()
            .map(|user| (user.password.clone(), user.name.clone()))
            .collect::<HashMap<_, _>>(),
    );
    let congestion = Arc::new(Hy2CongestionConfig::new(
        config.bandwidth.up_mbps.saturating_mul(125_000),
    ));
    let server_config = make_server_config(&config, Arc::clone(&congestion))?;
    let endpoint = make_endpoint(server_config, &config)
        .with_context(|| format!("bind HY2 UDP listener on {listen}"))?;
    let tcp_listener = crate::tcp_server::bind_listener(listen)
        .with_context(|| format!("bind VLESS TCP listener on {listen}"))?;
    let tcp_acceptor = crate::tcp_server::tls_acceptor(&config)?;
    let vless_users = Arc::new(crate::vless_server::users(&config.users));
    let outbound = OutboundConnector::new(&config.outbound);
    info!(%listen, users = users.len(), "HY2 server listening");
    info!(%listen, users = vless_users.len(), "VLESS TLS/TCP server listening");
    if config.ssh.enabled {
        info!(%listen, upstream = %config.ssh.upstream, "SSH/TCP protocol sharing enabled");
    }

    tokio::pin!(shutdown);
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => Some((incoming, None)),
            accepted = tcp_listener.accept() => Some((None, Some(accepted))),
            () = &mut shutdown => {
                endpoint.close(0_u32.into(), b"server reload");
                endpoint.wait_idle().await;
                return Ok(());
            }
        };
        let Some((incoming, accepted)) = incoming else {
            return Ok(());
        };
        if let Some(accepted) = accepted {
            let (socket, remote) = accepted.context("accept TCP proxy connection")?;
            let acceptor = tcp_acceptor.clone();
            let vless_users = Arc::clone(&vless_users);
            let ssh_upstream = config.ssh.enabled.then_some(config.ssh.upstream);
            let traffic = Arc::clone(&traffic);
            let outbound = outbound.clone();
            let udp_timeout = Duration::from_secs(config.udp.timeout_secs);
            tokio::spawn(async move {
                if let Err(error) = crate::tcp_server::serve(
                    socket,
                    remote,
                    crate::tcp_server::ConnectionOptions {
                        acceptor,
                        vless_users,
                        ssh_upstream,
                        outbound,
                        udp_timeout,
                        traffic,
                    },
                )
                .await
                {
                    debug!(%remote, %error, "TCP proxy connection closed");
                }
            });
            continue;
        }
        let Some(incoming) = incoming else {
            return Ok(());
        };
        let mut connecting = Box::pin(incoming.into_future());
        let (send_rate, connection) = tokio::select! {
            send_rate = congestion.take_pending_rate() => (send_rate, None),
            connection = &mut connecting => {
                let send_rate = congestion.take_pending_rate().await;
                (send_rate, Some(connection))
            }
        };
        let congestion = Arc::clone(&congestion);
        let users = Arc::clone(&users);
        let traffic = Arc::clone(&traffic);
        let udp_enabled = config.udp.enabled;
        let udp_timeout = Duration::from_secs(config.udp.timeout_secs);
        let receive_bps = config.bandwidth.down_mbps.saturating_mul(125_000);
        let ignore_client_bandwidth = config.bandwidth.ignore_client_bandwidth;
        let receive_auto =
            config.bandwidth.ignore_client_bandwidth && config.bandwidth.down_mbps == 0;
        let masquerade = config.masquerade.clone();
        let outbound = outbound.clone();
        tokio::spawn(async move {
            let connection = match match connection {
                Some(connection) => connection,
                None => connecting.await,
            } {
                Ok(connection) => connection,
                Err(error) => {
                    warn!(%error, "reject QUIC connection");
                    return;
                }
            };
            let remote = connection.remote_address();
            let authentication = AuthenticationOptions {
                users,
                udp_enabled,
                receive_bps,
                receive_auto,
                ignore_client_bandwidth,
                congestion,
                send_rate: Some(send_rate),
                masquerade,
            };
            match authenticate_connection(connection, authentication).await {
                Ok((session, user)) => {
                    info!(%remote, %user, "HY2 client authenticated");
                    let traffic = traffic.user(&user);
                    let _active_connection = traffic.connection();
                    if let Err(error) =
                        serve_connection(session, udp_enabled, udp_timeout, outbound, traffic).await
                    {
                        warn!(%remote, %error, "HY2 connection closed during TCP relay");
                    }
                }
                Err(error) => {
                    warn!(%remote, %error, "HY2 connection closed during authentication");
                }
            }
        });
    }
}

fn make_endpoint(server_config: quinn::ServerConfig, config: &Config) -> Result<Endpoint> {
    let socket = bind_server_socket(config.listen)?;
    socket.set_nonblocking(true)?;
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let Some(obfs) = &config.obfs else {
        return Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(Into::into);
    };
    let socket = runtime.wrap_udp_socket(socket)?;
    let socket = Arc::new(SalamanderSocket::new(socket, obfs.password.as_bytes()));
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(Into::into)
}

fn bind_server_socket(listen: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    if listen.is_ipv6() && listen.ip().is_unspecified() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.bind(&listen.into())?;
        Ok(socket.into())
    } else {
        std::net::UdpSocket::bind(listen)
    }
}

fn make_server_config(
    config: &Config,
    congestion: Arc<Hy2CongestionConfig>,
) -> Result<quinn::ServerConfig> {
    let certificates = CertificateDer::pem_file_iter(&config.tls.certificate)
        .with_context(|| format!("read TLS certificate {}", config.tls.certificate))?
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS certificate PEM")?;
    if certificates.is_empty() {
        bail!("TLS certificate file does not contain a certificate");
    }
    let private_key = PrivateKeyDer::from_pem_file(&config.tls.private_key)
        .with_context(|| format!("read TLS private key {}", config.tls.private_key))?;
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("configure TLS certificate")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(tls).context("configure QUIC TLS")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport =
        Arc::get_mut(&mut server_config.transport).expect("new QUIC transport configuration");
    transport.datagram_receive_buffer_size(Some(1 << 20));
    transport.congestion_controller_factory(congestion);
    Ok(server_config)
}

struct AuthenticationOptions {
    users: Arc<HashMap<String, String>>,
    udp_enabled: bool,
    receive_bps: u64,
    receive_auto: bool,
    ignore_client_bandwidth: bool,
    congestion: Arc<Hy2CongestionConfig>,
    send_rate: Option<Arc<AtomicU64>>,
    masquerade: Option<MasqueradeConfig>,
}

async fn authenticate_connection(
    connection: quinn::Connection,
    options: AuthenticationOptions,
) -> Result<(AuthenticatedSession, String)> {
    let AuthenticationOptions {
        users,
        udp_enabled,
        receive_bps,
        receive_auto,
        ignore_client_bandwidth,
        congestion,
        send_rate,
        masquerade,
    } = options;
    let raw_connection = connection.clone();
    let mut h3 = H3Connection::new(h3_quinn::Connection::new(connection))
        .await
        .context("initialize HTTP/3 connection")?;
    loop {
        let resolver = h3
            .accept()
            .await
            .context("accept HTTP/3 request")?
            .context("HY2 client closed before authentication")?;
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .context("read HTTP/3 request")?;
        let password = request
            .headers()
            .get(REQUEST_HEADER_AUTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let user = users.get(password).cloned();
        let client_receive_bps = request
            .headers()
            .get(HEADER_CC_RX)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        let authorized = request.method() == Method::POST
            && request.uri().host() == Some(AUTHORITY)
            && request.uri().path() == AUTH_PATH
            && user.is_some()
            && !(ignore_client_bandwidth && receive_bps > 0 && client_receive_bps == 0);
        if !authorized {
            let mut body = BytesMut::new();
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .context("read masquerade request body")?
            {
                if body.len().saturating_add(chunk.remaining()) > MAX_MASQUERADE_BODY_SIZE {
                    bail!("masquerade request body exceeds {MAX_MASQUERADE_BODY_SIZE} bytes");
                }
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            let response = masquerade::response(masquerade.as_ref(), &request, body.freeze())
                .await
                .unwrap_or_else(|error| {
                    warn!(%error, "masquerade handler failed");
                    masquerade::MasqueradeResponse {
                        status: StatusCode::BAD_GATEWAY,
                        headers: Default::default(),
                        body: Bytes::new(),
                    }
                });
            let mut h3_response = Response::builder().status(response.status).body(())?;
            *h3_response.headers_mut() = response.headers;
            stream
                .send_response(h3_response)
                .await
                .context("send masquerade response")?;
            if !response.body.is_empty() {
                stream
                    .send_data(response.body)
                    .await
                    .context("send masquerade response body")?;
            }
            stream
                .finish()
                .await
                .context("finish masquerade response")?;
            continue;
        }

        let negotiated_send_bps = congestion.negotiated_rate(client_receive_bps);
        if let Some(send_rate) = &send_rate {
            send_rate.store(negotiated_send_bps, Ordering::Relaxed);
        } else {
            warn!(
                negotiated_send_bps,
                "missing congestion controller for HY2 connection"
            );
        }

        let mut response = Response::builder()
            .status(StatusCode::from_u16(STATUS_AUTH_OK)?)
            .body(())?;
        response.headers_mut().insert(
            HeaderName::from_static("hysteria-udp"),
            HeaderValue::from_static(if udp_enabled { "true" } else { "false" }),
        );
        let receive_header = if receive_auto {
            "auto".to_owned()
        } else {
            receive_bps.to_string()
        };
        response.headers_mut().insert(
            HeaderName::from_static("hysteria-cc-rx"),
            HeaderValue::from_str(&receive_header)?,
        );
        response.headers_mut().insert(
            HeaderName::from_static("hysteria-padding"),
            HeaderValue::from_bytes(&random_padding(256, 2048)?)?,
        );
        stream
            .send_response(response)
            .await
            .context("send HY2 authentication response")?;
        stream
            .send_data(Bytes::new())
            .await
            .context("write HY2 authentication body")?;
        stream
            .finish()
            .await
            .context("finish HY2 authentication response")?;
        tracing::debug!(
            client_receive_bps,
            negotiated_send_bps,
            receive_bps,
            receive_auto,
            "HY2 bandwidth negotiated"
        );
        return Ok((
            AuthenticatedSession {
                connection: raw_connection,
                h3,
            },
            user.expect("authorized user"),
        ));
    }
}

struct AuthenticatedSession {
    connection: quinn::Connection,
    // Kept alive until the data plane has finished. Dropping h3 earlier sends
    // H3_NO_ERROR and closes the QUIC connection before HY2 streams can run.
    h3: H3Connection<h3_quinn::Connection, Bytes>,
}

async fn serve_tcp_streams(
    connection: quinn::Connection,
    outbound: OutboundConnector,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let traffic = Arc::clone(&traffic);
        let outbound = outbound.clone();
        tokio::spawn(async move {
            if let Err(error) = relay_tcp_stream(send, recv, outbound, traffic).await {
                if is_peer_stream_close(&error) {
                    debug!(%error, "HY2 TCP stream closed by peer");
                } else {
                    warn!(%error, "HY2 TCP stream failed");
                }
            }
        });
    }
}

async fn serve_connection(
    session: AuthenticatedSession,
    udp_enabled: bool,
    udp_timeout: Duration,
    outbound: OutboundConnector,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let AuthenticatedSession {
        connection,
        h3: _h3,
    } = session;
    if !udp_enabled {
        return serve_tcp_streams(connection, outbound, traffic).await;
    }
    let tcp = serve_tcp_streams(connection.clone(), outbound.clone(), Arc::clone(&traffic));
    let udp = serve_udp_datagrams(connection, udp_timeout, outbound, traffic);
    tokio::try_join!(tcp, udp)?;
    Ok(())
}

struct UdpSession {
    socket: Arc<OutboundUdpSession>,
    next_packet_id: AtomicU16,
}

struct UdpSessionOptions<'a> {
    connection: &'a quinn::Connection,
    udp_timeout: Duration,
    expiration_tx: &'a mpsc::UnboundedSender<(u32, Weak<UdpSession>)>,
    traffic: &'a Arc<UserTraffic>,
    outbound: &'a OutboundConnector,
}

async fn serve_udp_datagrams(
    connection: quinn::Connection,
    udp_timeout: Duration,
    outbound: OutboundConnector,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let mut sessions = HashMap::<u32, Arc<UdpSession>>::new();
    let (expiration_tx, mut expiration_rx) = mpsc::unbounded_channel::<(u32, Weak<UdpSession>)>();
    let mut reassembler = crate::protocol::UdpReassembler::default();
    loop {
        let datagram = tokio::select! {
            datagram = connection.read_datagram() => datagram,
            expired = expiration_rx.recv() => {
                if let Some((session_id, expired)) = expired {
                    let should_remove = sessions.get(&session_id).is_some_and(|current| {
                        expired.upgrade().is_some_and(|expired| Arc::ptr_eq(current, &expired))
                    });
                    if should_remove {
                        sessions.remove(&session_id);
                    }
                }
                continue;
            }
        };
        let datagram = match datagram {
            Ok(datagram) => datagram,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return Ok(()),
            Err(error) => return Err(error).context("receive QUIC datagram"),
        };
        let fragment =
            crate::protocol::UdpMessage::decode(&datagram).context("decode HY2 UDP datagram")?;
        let Some(message) = reassembler
            .push(fragment)
            .context("reassemble HY2 UDP datagram")?
        else {
            continue;
        };
        let session = get_udp_session(
            &mut sessions,
            message.session_id,
            UdpSessionOptions {
                connection: &connection,
                udp_timeout,
                expiration_tx: &expiration_tx,
                traffic: &traffic,
                outbound: &outbound,
            },
        )
        .await?;
        session
            .socket
            .send_to(&message.payload, &message.destination)
            .await
            .with_context(|| format!("send UDP packet to {}", message.destination))?;
        traffic.record_upload(message.payload.len());
    }
}

async fn get_udp_session(
    sessions: &mut HashMap<u32, Arc<UdpSession>>,
    session_id: u32,
    options: UdpSessionOptions<'_>,
) -> Result<Arc<UdpSession>> {
    if let Some(session) = sessions.get(&session_id).cloned() {
        return Ok(session);
    }
    let socket = Arc::new(
        options
            .outbound
            .open_udp()
            .await
            .context("bind UDP session socket")?,
    );
    let session = Arc::new(UdpSession {
        socket: Arc::clone(&socket),
        next_packet_id: AtomicU16::new(0),
    });
    sessions.insert(session_id, Arc::clone(&session));
    let connection = options.connection.clone();
    let maximum_datagram_size = connection.max_datagram_size().unwrap_or(1200);
    let response_session = Arc::clone(&session);
    let expiration_tx = options.expiration_tx.clone();
    let expiration_session = Arc::downgrade(&session);
    let traffic = Arc::clone(options.traffic);
    let udp_timeout = options.udp_timeout;
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(crate::protocol::MAX_UDP_SIZE);
        'receive: loop {
            let (length, source) = match socket.recv_from(udp_timeout, &mut buffer).await {
                Ok(value) => value,
                Err(error) => {
                    warn!(%error, session_id, "UDP session socket failed");
                    break;
                }
            };
            let packet_id = response_session
                .next_packet_id
                .fetch_add(1, Ordering::Relaxed);
            let fragments = match crate::protocol::UdpMessage::encode_fragments(
                session_id,
                packet_id,
                &source,
                &buffer[..length],
                maximum_datagram_size,
            ) {
                Ok(fragments) => fragments,
                Err(error) => {
                    warn!(%error, session_id, "encode HY2 UDP response fragments");
                    continue;
                }
            };
            for encoded in fragments {
                if let Err(error) = connection.send_datagram(Bytes::from(encoded)) {
                    warn!(%error, session_id, "send HY2 UDP response");
                    break 'receive;
                }
            }
            traffic.record_download(length);
        }
        let _ = expiration_tx.send((session_id, expiration_session));
    });
    Ok(session)
}

async fn relay_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    outbound: OutboundConnector,
    traffic: Arc<UserTraffic>,
) -> Result<()> {
    let frame_type = read_varint(&mut recv).await?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        bail!("unexpected HY2 stream frame type {frame_type:#x}");
    }
    let request = read_tcp_request(&mut recv).await?;
    let mut upstream = match outbound.connect_tcp(&request.destination).await {
        Ok(stream) => stream,
        Err(error) => {
            let response = TcpResponse {
                status: TcpResponseStatus::Error,
                message: error.to_string(),
                payload: Vec::new(),
            };
            send.write_all(&response.encode(&random_padding(128, 1024)?)?)
                .await?;
            send.finish()?;
            return Ok(());
        }
    };
    let response = TcpResponse {
        status: TcpResponseStatus::Ok,
        message: String::new(),
        payload: Vec::new(),
    };
    send.write_all(&response.encode(&random_padding(128, 1024)?)?)
        .await?;
    upstream.write_all(&request.payload).await?;
    traffic.record_upload(request.payload.len());
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let upload_traffic = Arc::clone(&traffic);
    let to_upstream = async move {
        copy_with_reused_buffer(
            &mut recv,
            &mut upstream_write,
            &upload_traffic.uploaded_bytes,
        )
        .await
        .context("relay client data to destination")?;
        upstream_write
            .shutdown()
            .await
            .context("finish destination write half")?;
        Ok::<(), anyhow::Error>(())
    };
    let from_upstream = async move {
        copy_with_reused_buffer(&mut upstream_read, &mut send, &traffic.downloaded_bytes)
            .await
            .context("relay destination data to client")?;
        send.finish().context("finish HY2 response stream")?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(to_upstream, from_upstream)?;
    Ok(())
}

async fn read_tcp_request(recv: &mut quinn::RecvStream) -> Result<TcpRequest> {
    let address_length = read_varint(recv).await? as usize;
    if address_length == 0 || address_length > crate::protocol::MAX_ADDRESS_LENGTH {
        bail!("invalid HY2 destination address length {address_length}");
    }
    let mut address = vec![0; address_length];
    recv.read_exact(&mut address).await?;
    let padding_length = read_varint(recv).await? as usize;
    if padding_length > crate::protocol::MAX_PADDING_LENGTH {
        bail!("invalid HY2 TCP padding length {padding_length}");
    }
    let mut padding = vec![0; padding_length];
    recv.read_exact(&mut padding).await?;
    let payload = recv
        .read_chunk(usize::MAX, true)
        .await?
        .map_or_else(Vec::new, |chunk| chunk.bytes.to_vec());
    Ok(TcpRequest {
        destination: String::from_utf8(address).context("HY2 destination is not UTF-8")?,
        payload,
    })
}

async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0_u8; 1];
    recv.read_exact(&mut first).await?;
    let length = 1_usize << (first[0] >> 6);
    let mut bytes = vec![first[0]];
    bytes.resize(length, 0);
    if length > 1 {
        recv.read_exact(&mut bytes[1..]).await?;
    }
    Ok(decode_varint(&mut bytes.as_slice())?)
}

fn random_padding(minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    let mut selector = [0_u8; 2];
    getrandom::fill(&mut selector).context("generate HY2 padding length")?;
    let range = maximum - minimum;
    let length = minimum + usize::from(u16::from_le_bytes(selector)) % range;
    let mut padding = vec![0_u8; length];
    getrandom::fill(&mut padding).context("generate HY2 padding")?;
    for byte in &mut padding {
        *byte = PADDING_ALPHABET[usize::from(*byte) % PADDING_ALPHABET.len()];
    }
    Ok(padding)
}

fn is_peer_stream_close(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                )
            })
    })
}

struct RelayBuffer(Option<Vec<u8>>);

impl RelayBuffer {
    fn take() -> Self {
        let buffer = RELAY_BUFFER_POOL
            .get_or_init(Default::default)
            .lock()
            .expect("relay buffer pool")
            .pop()
            .unwrap_or_else(|| vec![0_u8; RELAY_BUFFER_SIZE]);
        Self(Some(buffer))
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_deref_mut().expect("relay buffer is present")
    }
}

impl Drop for RelayBuffer {
    fn drop(&mut self) {
        let mut pool = RELAY_BUFFER_POOL
            .get_or_init(Default::default)
            .lock()
            .expect("relay buffer pool");
        if pool.len() < MAX_POOLED_RELAY_BUFFERS {
            pool.push(self.0.take().expect("relay buffer is present"));
        }
    }
}

async fn copy_with_reused_buffer<R, W>(
    reader: &mut R,
    writer: &mut W,
    counter: &AtomicU64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = RelayBuffer::take();
    let mut copied = 0_u64;
    loop {
        let read = reader.read(buffer.as_mut_slice()).await?;
        if read == 0 {
            return Ok(copied);
        }
        writer.write_all(&buffer.as_mut_slice()[..read]).await?;
        copied = copied.saturating_add(read as u64);
        counter.fetch_add(read as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_wildcard_socket_accepts_ipv4_packets() {
        let receiver = bind_server_socket("[::]:0".parse().unwrap()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"dual-stack", ("127.0.0.1", port)).unwrap();

        let mut buffer = [0_u8; 16];
        let (received, _) = receiver.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..received], b"dual-stack");
    }

    #[test]
    fn traffic_registry_tracks_users_and_preserves_existing_counters() {
        let registry = TrafficRegistry::default();
        registry.sync_users(["poetry".to_owned(), "amamiya".to_owned()]);
        let poetry = registry.user("poetry");
        poetry.record_upload(1_024);
        poetry.record_download(2_048);
        let active = poetry.connection();

        assert_eq!(
            registry.snapshots(),
            vec![
                UserTrafficSnapshot {
                    username: "amamiya".to_owned(),
                    uploaded_bytes: 0,
                    downloaded_bytes: 0,
                    active_connections: 0,
                },
                UserTrafficSnapshot {
                    username: "poetry".to_owned(),
                    uploaded_bytes: 1_024,
                    downloaded_bytes: 2_048,
                    active_connections: 1,
                },
            ]
        );

        registry.sync_users(["poetry".to_owned(), "new-user".to_owned()]);
        drop(active);
        assert_eq!(
            registry.snapshots(),
            vec![
                UserTrafficSnapshot {
                    username: "new-user".to_owned(),
                    uploaded_bytes: 0,
                    downloaded_bytes: 0,
                    active_connections: 0,
                },
                UserTrafficSnapshot {
                    username: "poetry".to_owned(),
                    uploaded_bytes: 1_024,
                    downloaded_bytes: 2_048,
                    active_connections: 0,
                },
            ]
        );
    }
}
