use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};

use crate::nat_tunnel::{self, ClientOptions, GatewayNodeStatus, GatewayOptions, GatewayTracker};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseProxyRole {
    Gateway,
    Client,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ReverseProxySettings {
    pub enabled: bool,
    pub role: ReverseProxyRole,
    pub gateway: String,
    pub tunnel_port: u16,
    pub public_port: u16,
    pub local_port: u16,
    pub pool_size: usize,
    pub queue_capacity: usize,
    pub token: String,
    pub subscription_url: String,
}

impl Default for ReverseProxySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ReverseProxyRole::Client,
            gateway: String::new(),
            tunnel_port: 7000,
            public_port: 51400,
            local_port: 51400,
            pool_size: 4,
            queue_capacity: 64,
            token: generate_token().unwrap_or_default(),
            subscription_url: String::new(),
        }
    }
}

impl ReverseProxySettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (16..=256).contains(&self.token.len()) && !self.token.chars().any(char::is_control),
            "reverse proxy token must contain 16-256 non-control characters"
        );
        ensure!(
            (1..=64).contains(&self.pool_size),
            "reverse proxy pool size must be between 1 and 64"
        );
        ensure!(
            (1..=1024).contains(&self.queue_capacity),
            "reverse proxy queue capacity must be between 1 and 1024"
        );
        if !self.subscription_url.is_empty() {
            let subscription_url = url::Url::parse(&self.subscription_url)
                .context("reverse proxy subscription URL is invalid")?;
            ensure!(
                matches!(subscription_url.scheme(), "http" | "https"),
                "reverse proxy subscription URL must use HTTP or HTTPS"
            );
            ensure!(
                self.subscription_url.len() <= 2048
                    && !self.subscription_url.chars().any(char::is_control),
                "reverse proxy subscription URL is too long"
            );
        }
        if !self.enabled {
            return Ok(());
        }
        match self.role {
            ReverseProxyRole::Gateway => {
                ensure!(
                    self.tunnel_port != self.public_port,
                    "tunnel and public ports must be different"
                );
                Ok(())
            }
            ReverseProxyRole::Client => {
                validate_endpoint(&self.gateway)?;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ReverseProxyStatus {
    pub settings: ReverseProxySettings,
    pub running: bool,
    pub uptime_secs: u64,
    pub last_error: Option<String>,
    pub local_node_name: String,
    pub connected_nodes: Vec<GatewayNodeStatus>,
}

#[derive(Default)]
struct RuntimeState {
    running: bool,
    started_at: Option<Instant>,
    last_error: Option<String>,
}

struct ControllerInner {
    path: PathBuf,
    settings: RwLock<ReverseProxySettings>,
    runtime: Arc<RwLock<RuntimeState>>,
    tracker: GatewayTracker,
    task: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct ReverseProxyController {
    inner: Arc<ControllerInner>,
}

impl ReverseProxyController {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let settings = load_or_create(&path)?;
        let controller = Self {
            inner: Arc::new(ControllerInner {
                path,
                settings: RwLock::new(settings),
                runtime: Arc::new(RwLock::new(RuntimeState::default())),
                tracker: GatewayTracker::default(),
                task: Mutex::new(None),
            }),
        };
        controller.restart().await;
        Ok(controller)
    }

    pub async fn status(&self) -> ReverseProxyStatus {
        let settings = self.inner.settings.read().await.clone();
        let runtime = self.inner.runtime.read().await;
        let connected_nodes = self.inner.tracker.snapshot().await;
        ReverseProxyStatus {
            settings,
            running: runtime.running,
            uptime_secs: runtime
                .started_at
                .filter(|_| runtime.running)
                .map_or(0, |started| started.elapsed().as_secs()),
            last_error: runtime.last_error.clone(),
            local_node_name: nat_tunnel::system_device_name(),
            connected_nodes,
        }
    }

    pub async fn update(&self, settings: ReverseProxySettings) -> Result<ReverseProxyStatus> {
        settings.validate()?;
        save(&self.inner.path, &settings)?;
        let changed = {
            let mut current = self.inner.settings.write().await;
            if *current == settings {
                false
            } else {
                *current = settings;
                true
            }
        };
        if changed {
            self.restart().await;
        }
        Ok(self.status().await)
    }

    async fn restart(&self) {
        let mut task_slot = self.inner.task.lock().await;
        if let Some(task) = task_slot.take() {
            task.abort();
            let _ = task.await;
        }
        self.inner.tracker.clear().await;

        let settings = self.inner.settings.read().await.clone();
        {
            let mut runtime = self.inner.runtime.write().await;
            runtime.running = false;
            runtime.started_at = None;
            runtime.last_error = None;
        }
        if !settings.enabled {
            return;
        }

        {
            let mut runtime = self.inner.runtime.write().await;
            runtime.running = true;
            runtime.started_at = Some(Instant::now());
        }
        let runtime = Arc::clone(&self.inner.runtime);
        let tracker = self.inner.tracker.clone();
        *task_slot = Some(tokio::spawn(async move {
            let token: Arc<[u8]> = Arc::from(settings.token.as_bytes());
            let result = match settings.role {
                ReverseProxyRole::Gateway => {
                    nat_tunnel::run_gateway(GatewayOptions {
                        tunnel_listen: format!("0.0.0.0:{}", settings.tunnel_port),
                        public_listen: format!("0.0.0.0:{}", settings.public_port),
                        token,
                        queue_capacity: settings.queue_capacity,
                        tracker,
                    })
                    .await
                }
                ReverseProxyRole::Client => {
                    nat_tunnel::run_client(ClientOptions {
                        gateway: settings.gateway,
                        local: format!("127.0.0.1:{}", settings.local_port),
                        token,
                        pool_size: settings.pool_size,
                        node_name: nat_tunnel::system_device_name(),
                        subscription_url: settings.subscription_url,
                    })
                    .await
                }
            };
            let mut runtime = runtime.write().await;
            runtime.running = false;
            runtime.started_at = None;
            runtime.last_error = result.err().map(|error| error.to_string());
        }));
    }
}

fn load_or_create(path: &Path) -> Result<ReverseProxySettings> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let settings: ReverseProxySettings = toml::from_str(&contents)
                .with_context(|| format!("parse reverse proxy configuration {}", path.display()))?;
            settings.validate()?;
            Ok(settings)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let settings = ReverseProxySettings::default();
            save(path, &settings)?;
            Ok(settings)
        }
        Err(error) => Err(error)
            .with_context(|| format!("read reverse proxy configuration {}", path.display())),
    }
}

fn save(path: &Path, settings: &ReverseProxySettings) -> Result<()> {
    settings.validate()?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create reverse proxy directory {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    let contents = toml::to_string_pretty(settings).context("serialize reverse proxy settings")?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("write reverse proxy configuration {}", temporary.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)
        .with_context(|| format!("replace reverse proxy configuration {}", path.display()))?;
    Ok(())
}

fn generate_token() -> Result<String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).context("generate reverse proxy token")?;
    Ok(random
        .iter()
        .fold(String::with_capacity(64), |mut token, byte| {
            let _ = write!(token, "{byte:02x}");
            token
        }))
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            bail!("gateway must use [IPv6]:port format");
        };
        (host, port)
    } else {
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("gateway must include a port"))?;
        ensure!(
            !host.contains(':'),
            "IPv6 gateways must use [IPv6]:port format"
        );
        (host, port)
    };
    ensure!(!host.trim().is_empty(), "gateway host must not be empty");
    let port = port
        .parse::<u16>()
        .context("gateway port must be between 1 and 65535")?;
    ensure!(port > 0, "gateway port must be between 1 and 65535");
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn validates_role_specific_settings() {
        let mut settings = ReverseProxySettings::default();
        settings.enabled = true;
        assert!(settings.validate().is_err());
        settings.gateway = "gateway.example.com:7000".into();
        assert!(settings.validate().is_ok());
        settings.role = ReverseProxyRole::Gateway;
        settings.public_port = settings.tunnel_port;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn persists_private_configuration() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("reverse-proxy.toml");
        let mut settings = ReverseProxySettings::default();
        settings.gateway = "198.51.100.10:7000".into();
        save(&path, &settings).unwrap();
        assert_eq!(load_or_create(&path).unwrap(), settings);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn accepts_bracketed_ipv6_gateway() {
        assert!(validate_endpoint("[2001:db8::10]:7000").is_ok());
        assert!(validate_endpoint("2001:db8::10:7000").is_err());
    }
}
