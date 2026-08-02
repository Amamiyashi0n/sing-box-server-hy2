use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use blake2::{
    Blake2bMac512,
    digest::{KeyInit, Mac},
};
use serde::Serialize;
use socket2::{SockRef, TcpKeepalive};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tracing::{debug, info, warn};

const MAGIC: &[u8; 8] = b"SBMNAT03";
const CHALLENGE_LENGTH: usize = 32;
const MAC_LENGTH: usize = 64;
const MAX_NODE_NAME_LENGTH: usize = 128;
const MAX_SUBSCRIPTION_URL_LENGTH: usize = 2048;
const START: u8 = 1;
const READY: u8 = 2;
const PING: u8 = 3;
const PONG: u8 = 4;
const AUTH_OK: u8 = 0;
const AUTH_FAILED: u8 = 1;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TUNNEL_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(2);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const COPY_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct GatewayOptions {
    pub tunnel_listen: String,
    pub public_listen: String,
    pub token: Arc<[u8]>,
    pub queue_capacity: usize,
    pub tracker: GatewayTracker,
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub gateway: String,
    pub local: String,
    pub token: Arc<[u8]>,
    pub pool_size: usize,
    pub node_name: String,
    pub subscription_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GatewayNodeStatus {
    pub name: String,
    pub online: bool,
    pub tunnel_count: usize,
    pub connected_since: u64,
    pub last_seen: u64,
    pub subscription_url: String,
}

#[derive(Debug, Default)]
struct GatewayNodeRuntime {
    tunnel_count: AtomicUsize,
    connected_since: AtomicU64,
    last_seen: AtomicU64,
    subscription_url: StdRwLock<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GatewayTracker {
    nodes: Arc<RwLock<HashMap<String, Arc<GatewayNodeRuntime>>>>,
}

impl GatewayTracker {
    async fn connect(&self, name: String, subscription_url: String) -> GatewayNodeConnection {
        let node = {
            let mut nodes = self.nodes.write().await;
            Arc::clone(nodes.entry(name.clone()).or_default())
        };
        if !subscription_url.is_empty()
            && let Ok(mut current) = node.subscription_url.write()
        {
            *current = subscription_url;
        }
        let now = unix_time();
        if node.tunnel_count.fetch_add(1, Ordering::AcqRel) == 0 {
            node.connected_since.store(now, Ordering::Release);
        }
        node.last_seen.store(now, Ordering::Release);
        GatewayNodeConnection { node }
    }

    pub async fn snapshot(&self) -> Vec<GatewayNodeStatus> {
        let nodes = self.nodes.read().await;
        let mut snapshot = nodes
            .iter()
            .map(|(name, node)| {
                let tunnel_count = node.tunnel_count.load(Ordering::Acquire);
                GatewayNodeStatus {
                    name: name.clone(),
                    online: tunnel_count > 0,
                    tunnel_count,
                    connected_since: node.connected_since.load(Ordering::Acquire),
                    last_seen: node.last_seen.load(Ordering::Acquire),
                    subscription_url: node
                        .subscription_url
                        .read()
                        .map(|value| value.clone())
                        .unwrap_or_default(),
                }
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| {
            right
                .online
                .cmp(&left.online)
                .then_with(|| left.name.cmp(&right.name))
        });
        snapshot
    }

    pub async fn clear(&self) {
        self.nodes.write().await.clear();
    }
}

struct GatewayNodeConnection {
    node: Arc<GatewayNodeRuntime>,
}

impl Drop for GatewayNodeConnection {
    fn drop(&mut self) {
        self.node.tunnel_count.fetch_sub(1, Ordering::AcqRel);
        self.node.last_seen.store(unix_time(), Ordering::Release);
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

type AssignmentResult = std::result::Result<TcpStream, String>;

struct IdleTunnel {
    alive: AtomicBool,
    assignments: mpsc::Sender<oneshot::Sender<AssignmentResult>>,
}

struct TunnelPool {
    idle: Mutex<VecDeque<Arc<IdleTunnel>>>,
    available: Notify,
    capacity: usize,
}

impl TunnelPool {
    fn new(capacity: usize) -> Self {
        Self {
            idle: Mutex::new(VecDeque::with_capacity(capacity)),
            available: Notify::new(),
            capacity,
        }
    }

    async fn register(
        self: &Arc<Self>,
        stream: TcpStream,
        node_connection: GatewayNodeConnection,
    ) -> bool {
        let (assignments, assignment_rx) = mpsc::channel(1);
        let handle = Arc::new(IdleTunnel {
            alive: AtomicBool::new(true),
            assignments,
        });
        {
            let mut idle = self.idle.lock().await;
            idle.retain(|tunnel| tunnel.alive.load(Ordering::Acquire));
            if idle.len() >= self.capacity {
                return false;
            }
            idle.push_back(Arc::clone(&handle));
        }
        self.available.notify_one();
        tokio::spawn(manage_idle_tunnel(
            stream,
            handle,
            assignment_rx,
            node_connection,
        ));
        true
    }

    async fn acquire(&self) -> Result<Arc<IdleTunnel>> {
        timeout(IDLE_TUNNEL_TIMEOUT, async {
            loop {
                let notified = self.available.notified();
                {
                    let mut idle = self.idle.lock().await;
                    idle.retain(|tunnel| tunnel.alive.load(Ordering::Acquire));
                    if let Some(tunnel) = idle.pop_front() {
                        return tunnel;
                    }
                }
                notified.await;
            }
        })
        .await
        .context("wait for an idle NAT tunnel timed out")
    }
}

pub fn read_token(path: &std::path::Path) -> Result<Arc<[u8]>> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("read NAT tunnel token {}", path.display()))?;
    let token = token.trim();
    ensure!(
        token.len() >= 16,
        "NAT tunnel token must contain at least 16 characters"
    );
    Ok(Arc::from(token.as_bytes()))
}

pub fn system_device_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| validate_node_name(name).is_ok())
        .unwrap_or_else(|| "sing-box-ser-mini".to_owned())
}

pub async fn run_gateway(options: GatewayOptions) -> Result<()> {
    ensure!(
        options.queue_capacity > 0,
        "NAT tunnel queue capacity must be positive"
    );
    ensure!(
        options.queue_capacity <= 1024,
        "NAT tunnel queue capacity must not exceed 1024"
    );
    let tunnel_listener = TcpListener::bind(&options.tunnel_listen)
        .await
        .with_context(|| format!("bind NAT tunnel listener on {}", options.tunnel_listen))?;
    let public_listener = TcpListener::bind(&options.public_listen)
        .await
        .with_context(|| format!("bind public TCP listener on {}", options.public_listen))?;
    info!(listen = %options.tunnel_listen, "NAT tunnel gateway listening");
    info!(listen = %options.public_listen, "NAT tunnel public TCP entry listening");

    let pool = Arc::new(TunnelPool::new(options.queue_capacity));
    let token = Arc::clone(&options.token);
    let tracker = options.tracker.clone();
    let tunnel_pool = Arc::clone(&pool);
    let tunnel_task = async move {
        loop {
            let (mut stream, remote) = tunnel_listener.accept().await?;
            configure_stream(&stream)?;
            let tunnel_pool = Arc::clone(&tunnel_pool);
            let token = Arc::clone(&token);
            let tracker = tracker.clone();
            tokio::spawn(async move {
                match gateway_authenticate(&mut stream, &token).await {
                    Ok(node) => {
                        debug!(%remote, node_name = %node.name, "NAT tunnel authenticated");
                        let node_connection =
                            tracker.connect(node.name, node.subscription_url).await;
                        if !tunnel_pool.register(stream, node_connection).await {
                            debug!(%remote, "NAT tunnel pool is full");
                        }
                    }
                    Err(error) => warn!(%remote, %error, "reject NAT tunnel"),
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let public_task = async move {
        loop {
            let (public, remote) = public_listener.accept().await?;
            configure_stream(&public)?;
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                if let Err(error) = serve_public_connection(public, pool).await {
                    debug!(%remote, %error, "NAT tunnel public connection closed");
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(tunnel_task, public_task)?;
    Ok(())
}

pub async fn run_client(options: ClientOptions) -> Result<()> {
    ensure!(
        options.pool_size > 0,
        "NAT tunnel pool size must be positive"
    );
    ensure!(
        options.pool_size <= 64,
        "NAT tunnel pool size must not exceed 64"
    );
    info!(gateway = %options.gateway, local = %options.local, pool = options.pool_size, "NAT tunnel client starting");
    validate_node_name(&options.node_name)?;
    validate_subscription_url(&options.subscription_url)?;
    let options = Arc::new(options);
    let mut workers = tokio::task::JoinSet::new();
    for worker in 0..options.pool_size {
        let options = Arc::clone(&options);
        workers.spawn(async move { client_worker(worker, options).await });
    }
    while let Some(result) = workers.join_next().await {
        result.context("NAT tunnel worker panicked")??;
    }
    bail!("all NAT tunnel workers stopped")
}

async fn client_worker(worker: usize, options: Arc<ClientOptions>) -> Result<()> {
    loop {
        if let Err(error) = client_session(worker, &options).await {
            debug!(worker, %error, "NAT tunnel client session closed");
        }
        sleep(RETRY_DELAY).await;
    }
}

async fn client_session(worker: usize, options: &ClientOptions) -> Result<()> {
    let mut tunnel = timeout(CONNECT_TIMEOUT, TcpStream::connect(&options.gateway))
        .await
        .context("NAT tunnel gateway connection timed out")?
        .with_context(|| format!("connect NAT tunnel gateway {}", options.gateway))?;
    configure_stream(&tunnel)?;
    client_authenticate(
        &mut tunnel,
        &options.token,
        &options.node_name,
        &options.subscription_url,
    )
    .await?;
    debug!(worker, "NAT tunnel ready");

    loop {
        let command = tunnel
            .read_u8()
            .await
            .context("wait for NAT tunnel assignment")?;
        match command {
            PING => {
                tunnel.write_u8(PONG).await?;
                tunnel.flush().await?;
            }
            START => break,
            _ => bail!("invalid NAT tunnel command {command}"),
        }
    }
    let mut local = timeout(CONNECT_TIMEOUT, TcpStream::connect(&options.local))
        .await
        .context("local proxy connection timed out")?
        .with_context(|| format!("connect local proxy {}", options.local))?;
    configure_stream(&local)?;
    tunnel.write_u8(READY).await?;
    tunnel.flush().await?;
    tokio::io::copy_bidirectional_with_sizes(
        &mut tunnel,
        &mut local,
        COPY_BUFFER_SIZE,
        COPY_BUFFER_SIZE,
    )
    .await
    .context("forward NAT tunnel connection")?;
    Ok(())
}

async fn serve_public_connection(mut public: TcpStream, pool: Arc<TunnelPool>) -> Result<()> {
    let mut attempts = 0;
    let mut tunnel = loop {
        attempts += 1;
        let candidate = pool.acquire().await?;
        let (response_tx, response_rx) = oneshot::channel();
        if candidate.assignments.send(response_tx).await.is_ok()
            && let Ok(Ok(Ok(stream))) = timeout(CONNECT_TIMEOUT, response_rx).await
        {
            break stream;
        }
        if attempts >= 8 {
            bail!("no usable NAT tunnel was available");
        }
    };
    tokio::io::copy_bidirectional_with_sizes(
        &mut public,
        &mut tunnel,
        COPY_BUFFER_SIZE,
        COPY_BUFFER_SIZE,
    )
    .await
    .context("forward public TCP connection")?;
    Ok(())
}

async fn manage_idle_tunnel(
    mut stream: TcpStream,
    handle: Arc<IdleTunnel>,
    mut assignments: mpsc::Receiver<oneshot::Sender<AssignmentResult>>,
    _node_connection: GatewayNodeConnection,
) {
    let mut heartbeat = interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            assignment = assignments.recv() => {
                let Some(assignment) = assignment else { break };
                let activation = async {
                    stream.write_u8(START).await?;
                    stream.flush().await?;
                    let command = timeout(CONNECT_TIMEOUT, stream.read_u8())
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NAT tunnel assignment timed out"))??;
                    if command != READY {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NAT tunnel ready response"));
                    }
                    Ok::<(), io::Error>(())
                }.await;
                handle.alive.store(false, Ordering::Release);
                match activation {
                    Ok(()) => { let _ = assignment.send(Ok(stream)); }
                    Err(error) => { let _ = assignment.send(Err(error.to_string())); }
                }
                return;
            }
            _ = heartbeat.tick() => {
                let alive = async {
                    stream.write_u8(PING).await?;
                    stream.flush().await?;
                    let command = timeout(CONNECT_TIMEOUT, stream.read_u8())
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NAT tunnel heartbeat timed out"))??;
                    if command != PONG {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid NAT tunnel heartbeat response"));
                    }
                    Ok::<(), io::Error>(())
                }.await;
                if alive.is_err() {
                    break;
                }
            }
        }
    }
    handle.alive.store(false, Ordering::Release);
}

#[derive(Debug, Eq, PartialEq)]
struct AuthenticatedNode {
    name: String,
    subscription_url: String,
}

async fn gateway_authenticate<S>(stream: &mut S, token: &[u8]) -> Result<AuthenticatedNode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut challenge = [0_u8; CHALLENGE_LENGTH];
    getrandom::fill(&mut challenge).context("generate NAT tunnel challenge")?;
    stream.write_all(MAGIC).await?;
    stream.write_all(&challenge).await?;
    stream.flush().await?;

    let node_name_length = stream.read_u16().await? as usize;
    ensure!(
        (1..=MAX_NODE_NAME_LENGTH).contains(&node_name_length),
        "invalid NAT tunnel node name length"
    );
    let mut node_name = vec![0_u8; node_name_length];
    stream.read_exact(&mut node_name).await?;
    let node_name = String::from_utf8(node_name).context("invalid NAT tunnel node name")?;
    validate_node_name(&node_name)?;
    let subscription_url_length = stream.read_u16().await? as usize;
    ensure!(
        subscription_url_length <= MAX_SUBSCRIPTION_URL_LENGTH,
        "invalid NAT tunnel subscription URL length"
    );
    let mut subscription_url = vec![0_u8; subscription_url_length];
    stream.read_exact(&mut subscription_url).await?;
    let subscription_url =
        String::from_utf8(subscription_url).context("invalid NAT tunnel subscription URL")?;
    validate_subscription_url(&subscription_url)?;
    let mut provided = [0_u8; MAC_LENGTH];
    stream.read_exact(&mut provided).await?;
    let expected = challenge_mac(
        token,
        &challenge,
        node_name.as_bytes(),
        subscription_url.as_bytes(),
    )?;
    if !bool::from(provided.ct_eq(&expected)) {
        stream.write_u8(AUTH_FAILED).await?;
        stream.flush().await?;
        bail!("invalid NAT tunnel authentication response");
    }
    stream.write_u8(AUTH_OK).await?;
    stream.flush().await?;
    Ok(AuthenticatedNode {
        name: node_name,
        subscription_url,
    })
}

async fn client_authenticate<S>(
    stream: &mut S,
    token: &[u8],
    node_name: &str,
    subscription_url: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut magic = [0_u8; MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    ensure!(magic == *MAGIC, "invalid NAT tunnel protocol magic");
    validate_node_name(node_name)?;
    validate_subscription_url(subscription_url)?;
    let mut challenge = [0_u8; CHALLENGE_LENGTH];
    stream.read_exact(&mut challenge).await?;
    stream.write_u16(node_name.len() as u16).await?;
    stream.write_all(node_name.as_bytes()).await?;
    stream.write_u16(subscription_url.len() as u16).await?;
    stream.write_all(subscription_url.as_bytes()).await?;
    stream
        .write_all(&challenge_mac(
            token,
            &challenge,
            node_name.as_bytes(),
            subscription_url.as_bytes(),
        )?)
        .await?;
    stream.flush().await?;
    ensure!(
        stream.read_u8().await? == AUTH_OK,
        "NAT tunnel authentication failed"
    );
    Ok(())
}

fn challenge_mac(
    token: &[u8],
    challenge: &[u8; CHALLENGE_LENGTH],
    node_name: &[u8],
    subscription_url: &[u8],
) -> Result<[u8; MAC_LENGTH]> {
    let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(token)
        .map_err(|_| anyhow::anyhow!("invalid NAT tunnel token"))?;
    Mac::update(&mut mac, MAGIC);
    Mac::update(&mut mac, challenge);
    Mac::update(&mut mac, node_name);
    Mac::update(&mut mac, subscription_url);
    Ok(mac.finalize().into_bytes().into())
}

fn validate_node_name(node_name: &str) -> Result<()> {
    ensure!(
        !node_name.is_empty()
            && node_name.len() <= MAX_NODE_NAME_LENGTH
            && !node_name.chars().any(char::is_control),
        "NAT tunnel node name must contain 1-128 non-control characters"
    );
    Ok(())
}

fn validate_subscription_url(subscription_url: &str) -> Result<()> {
    if subscription_url.is_empty() {
        return Ok(());
    }
    ensure!(
        subscription_url.len() <= MAX_SUBSCRIPTION_URL_LENGTH
            && !subscription_url.chars().any(char::is_control),
        "NAT tunnel subscription URL must contain at most 2048 non-control characters"
    );
    let parsed =
        url::Url::parse(subscription_url).context("invalid NAT tunnel subscription URL")?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "NAT tunnel subscription URL must use HTTP or HTTPS"
    );
    Ok(())
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    SockRef::from(stream).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(20))
            .with_interval(Duration::from_secs(10)),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticates_with_a_fresh_challenge() {
        let token = b"a-long-random-test-token";
        let (mut gateway, mut client) = tokio::io::duplex(256);
        let (gateway_result, client_result) = tokio::join!(
            gateway_authenticate(&mut gateway, token),
            client_authenticate(
                &mut client,
                token,
                "test-exit",
                "https://exit.example/sub/code",
            ),
        );
        assert_eq!(
            gateway_result.unwrap(),
            AuthenticatedNode {
                name: "test-exit".into(),
                subscription_url: "https://exit.example/sub/code".into(),
            }
        );
        client_result.unwrap();
    }

    #[tokio::test]
    async fn rejects_an_incorrect_token() {
        let (mut gateway, mut client) = tokio::io::duplex(256);
        let (gateway_result, client_result) = tokio::join!(
            gateway_authenticate(&mut gateway, b"correct-test-token"),
            client_authenticate(&mut client, b"incorrect-test-token", "test-exit", "",),
        );
        assert!(gateway_result.is_err());
        assert!(client_result.is_err());
    }

    #[test]
    fn challenge_response_changes_with_the_challenge() {
        let first = challenge_mac(
            b"a-long-random-test-token",
            &[1; CHALLENGE_LENGTH],
            b"test-exit",
            b"",
        )
        .unwrap();
        let second = challenge_mac(
            b"a-long-random-test-token",
            &[2; CHALLENGE_LENGTH],
            b"test-exit",
            b"",
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn tracks_connected_gateway_nodes() {
        let tracker = GatewayTracker::default();
        let connection = tracker
            .connect("test-exit".into(), "https://exit.example/sub/code".into())
            .await;
        let online = tracker.snapshot().await;
        assert_eq!(online.len(), 1);
        assert!(online[0].online);
        assert_eq!(online[0].tunnel_count, 1);
        assert_eq!(online[0].subscription_url, "https://exit.example/sub/code");

        drop(connection);
        let offline = tracker.snapshot().await;
        assert!(!offline[0].online);
        assert_eq!(offline[0].tunnel_count, 0);
        assert!(offline[0].last_seen > 0);
    }
}
