use std::{
    collections::VecDeque,
    env,
    fmt::Write as _,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use blake2::{Blake2s256, Digest};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use url::Url;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_NODES: usize = 128;
const MAX_NESTING: usize = 2;
const DEFAULT_SHORT_LINKS: usize = 512;
const DEFAULT_SHORT_TTL: Duration = Duration::from_secs(86_400);
const FORMATS: [&str; 4] = ["singbox", "clash", "surge", "xray"];

#[derive(Debug, Clone)]
struct Node {
    kind: String,
    name: String,
    server: String,
    port: u16,
    username: String,
    password: String,
    method: String,
    uuid: String,
    network: String,
    path: String,
    host: String,
    service_name: String,
    sni: String,
    obfs: String,
    obfs_password: String,
    flow: String,
    original: String,
    tls: bool,
    insecure: bool,
}

impl Node {
    fn empty(kind: &str, original: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            name: String::new(),
            server: String::new(),
            port: 443,
            username: String::new(),
            password: String::new(),
            method: String::new(),
            uuid: String::new(),
            network: "tcp".to_owned(),
            path: String::new(),
            host: String::new(),
            service_name: String::new(),
            sni: String::new(),
            obfs: String::new(),
            obfs_password: String::new(),
            flow: String::new(),
            original: original.to_owned(),
            tls: false,
            insecure: false,
        }
    }
}

#[derive(Debug)]
struct ShortEntry {
    code: String,
    query: String,
    expires_at: Instant,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentShortLink {
    code: String,
    query: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct PersistentShortLinks {
    links: Vec<PersistentShortLink>,
}

#[derive(Debug)]
struct ShortStore {
    entries: VecDeque<ShortEntry>,
    permanent: Vec<PersistentShortLink>,
    persistence_path: Option<PathBuf>,
    limit: usize,
    ttl: Duration,
    disabled: bool,
}

impl ShortStore {
    fn from_env(persistence_path: Option<PathBuf>) -> Result<Self> {
        let permanent = match persistence_path.as_ref() {
            Some(path) => match fs::read_to_string(path) {
                Ok(contents) => toml::from_str::<PersistentShortLinks>(&contents)?.links,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            },
            None => Vec::new(),
        };
        Ok(Self {
            entries: VecDeque::new(),
            permanent,
            persistence_path,
            limit: positive_env("MAX_SHORT_LINKS", DEFAULT_SHORT_LINKS),
            ttl: Duration::from_secs(positive_env(
                "SHORT_LINK_TTL_SECONDS",
                DEFAULT_SHORT_TTL.as_secs() as usize,
            ) as u64),
            disabled: env::var("DISABLE_MEMORY_KV")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|entry| entry.expires_at > now);
    }

    fn put(&mut self, code: String, query: String) -> Result<()> {
        ensure!(!self.disabled, "memory short-link storage is disabled");
        self.prune();
        if let Some(position) = self.entries.iter().position(|entry| entry.code == code) {
            self.entries.remove(position);
        }
        while self.entries.len() >= self.limit {
            self.entries.pop_back();
        }
        self.entries.push_front(ShortEntry {
            code,
            query,
            expires_at: Instant::now() + self.ttl,
        });
        Ok(())
    }

    fn put_permanent(&mut self, code: String, query: String) -> Result<()> {
        ensure!(!self.disabled, "memory short-link storage is disabled");
        if let Some(entry) = self.permanent.iter_mut().find(|entry| entry.code == code) {
            entry.query = query;
        } else {
            self.permanent.push(PersistentShortLink { code, query });
        }
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = self.persistence_path.as_ref() else {
            return Ok(());
        };
        let contents = toml::to_string(&PersistentShortLinks {
            links: self.permanent.clone(),
        })?;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write as _;
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    fn get(&mut self, code: &str) -> Option<String> {
        self.prune();
        self.permanent
            .iter()
            .find(|entry| entry.code == code)
            .map(|entry| entry.query.clone())
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|entry| entry.code == code)
                    .map(|entry| entry.query.clone())
            })
    }
}

pub struct SublinkService {
    store: Mutex<ShortStore>,
}

impl Default for SublinkService {
    fn default() -> Self {
        Self {
            store: Mutex::new(ShortStore::from_env(None).expect("initialize short-link store")),
        }
    }
}

impl SublinkService {
    pub fn with_persistence(path: PathBuf) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(ShortStore::from_env(Some(path))?),
        })
    }

    pub fn convert(&self, format: &str, input: &str) -> Result<SublinkOutput> {
        let nodes = parse_input(input)?;
        match format {
            "singbox" => Ok(SublinkOutput::new(
                "application/json; charset=utf-8",
                render_singbox(&nodes)?,
            )),
            "clash" => Ok(SublinkOutput::new(
                "text/yaml; charset=utf-8",
                render_clash(&nodes),
            )),
            "surge" => Ok(SublinkOutput::new(
                "text/plain; charset=utf-8",
                render_surge(&nodes),
            )),
            "xray" => Ok(SublinkOutput::new(
                "text/plain; charset=utf-8",
                STANDARD.encode(
                    nodes
                        .iter()
                        .map(|node| node.original.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            )),
            _ => bail!("unsupported output format"),
        }
    }

    pub async fn shorten(&self, raw_url: &str, requested_code: Option<&str>) -> Result<String> {
        let url = Url::parse(raw_url).map_err(|_| anyhow!("invalid URL parameter"))?;
        ensure!(
            FORMATS
                .iter()
                .any(|format| url.path() == format!("/{format}")),
            "invalid URL parameter"
        );
        let query = url
            .query()
            .filter(|query| !query.is_empty())
            .ok_or_else(|| anyhow!("invalid URL parameter"))?;
        ensure!(query.len() <= MAX_INPUT_BYTES, "URL parameter is too large");
        let code = match requested_code {
            Some(code) => {
                ensure!(valid_code(code), "invalid short code");
                code.to_owned()
            }
            None => random_code()?,
        };
        self.store
            .lock()
            .await
            .put(code.clone(), format!("?{query}"))?;
        Ok(code)
    }

    pub async fn shorten_hy2(&self, raw_url: &str) -> Result<String> {
        let url = Url::parse(raw_url).map_err(|_| anyhow!("invalid URL parameter"))?;
        ensure!(url.path() == "/xray", "invalid HY2 URL parameter");
        let raw_config = raw_url
            .split_once("?config=")
            .map(|(_, value)| value)
            .ok_or_else(|| anyhow!("invalid HY2 URL parameter"))?;
        let config = percent_decode_str(raw_config)
            .decode_utf8()
            .map_err(|_| anyhow!("invalid HY2 URL parameter"))?
            .into_owned();
        ensure!(
            config.starts_with("hysteria2://"),
            "invalid HY2 URL parameter"
        );
        ensure!(
            config.len() <= MAX_INPUT_BYTES,
            "URL parameter is too large"
        );
        let code = stable_code(config.as_bytes());
        let encoded_config =
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>();
        self.store
            .lock()
            .await
            .put_permanent(code.clone(), format!("?config={encoded_config}"))?;
        Ok(code)
    }

    pub async fn shorten_auto(&self, raw_url: &str) -> Result<String> {
        let url = Url::parse(raw_url).map_err(|_| anyhow!("invalid URL parameter"))?;
        ensure!(
            FORMATS
                .iter()
                .any(|format| url.path() == format!("/{format}")),
            "invalid URL parameter"
        );
        let raw_config = raw_url
            .split_once("?config=")
            .map(|(_, value)| value)
            .ok_or_else(|| anyhow!("invalid URL parameter"))?;
        let config = percent_decode_str(raw_config)
            .decode_utf8()
            .map_err(|_| anyhow!("invalid URL parameter"))?
            .into_owned();
        ensure!(!config.is_empty(), "invalid URL parameter");
        ensure!(
            config.len() <= MAX_INPUT_BYTES,
            "URL parameter is too large"
        );
        let encoded_config =
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>();
        let code = random_code()?;
        self.store
            .lock()
            .await
            .put(code.clone(), format!("?config={encoded_config}"))?;
        Ok(code)
    }

    pub async fn redirect(&self, prefix: &str, code: &str) -> Result<String> {
        let format = format_for_prefix(prefix).ok_or_else(|| anyhow!("invalid short URL"))?;
        ensure!(valid_code(code), "invalid short URL");
        let query = self
            .store
            .lock()
            .await
            .get(code)
            .ok_or_else(|| anyhow!("short URL not found"))?;
        Ok(format!("/{format}{query}"))
    }

    pub async fn auto(&self, code: &str, user_agent: &str, accept: &str) -> Result<SublinkOutput> {
        ensure!(valid_code(code), "invalid short URL");
        let query = self
            .store
            .lock()
            .await
            .get(code)
            .ok_or_else(|| anyhow!("short URL not found"))?;
        let url = Url::parse(&format!("https://short.local/xray{query}"))
            .map_err(|_| anyhow!("invalid short URL"))?;
        let config = query_value(&url, &["config"]);
        self.convert(auto_format(user_agent, accept), &config)
    }

    pub async fn resolve(&self, raw_url: &str) -> Result<String> {
        let url = Url::parse(raw_url).map_err(|_| anyhow!("invalid short URL"))?;
        let (prefix, code) = split_short_path(url.path())?;
        let format = format_for_prefix(prefix).ok_or_else(|| anyhow!("invalid short URL"))?;
        let query = self
            .store
            .lock()
            .await
            .get(code)
            .ok_or_else(|| anyhow!("short URL not found"))?;
        let origin = url.origin().ascii_serialization();
        Ok(json!({ "originalUrl": format!("{origin}/{format}{query}") }).to_string())
    }
}

pub struct SublinkOutput {
    pub content_type: &'static str,
    pub body: String,
}

impl SublinkOutput {
    fn new(content_type: &'static str, body: String) -> Self {
        Self { content_type, body }
    }
}

fn positive_env(name: &str, fallback: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn query_value(url: &Url, names: &[&str]) -> String {
    url.query_pairs()
        .find(|(key, _)| names.iter().any(|name| key.eq_ignore_ascii_case(name)))
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn parse_input(input: &str) -> Result<Vec<Node>> {
    let trimmed = input.trim();
    ensure!(!trimmed.is_empty(), "no supported proxy nodes found");
    if trimmed.starts_with('{')
        || trimmed.to_ascii_lowercase().starts_with("proxies:")
        || trimmed.to_ascii_lowercase().starts_with("[proxy]")
    {
        bail!("only proxy URIs and Base64 subscriptions are supported");
    }
    let mut nodes = Vec::new();
    parse_input_recursive(trimmed, 0, &mut nodes)?;
    ensure!(!nodes.is_empty(), "no supported proxy nodes found");
    Ok(nodes)
}

fn parse_input_recursive(input: &str, depth: usize, nodes: &mut Vec<Node>) -> Result<()> {
    ensure!(depth <= MAX_NESTING, "input nesting is too deep");
    ensure!(input.len() <= MAX_INPUT_BYTES, "config input is too large");
    if let Some(decoded) = decoded_subscription(input) {
        return parse_input_recursive(&decoded, depth + 1, nodes);
    }
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("http://") || line.starts_with("https://") {
            bail!("remote HTTP(S) subscriptions are not supported");
        }
        if !line.contains("://") {
            parse_input_recursive(line, depth + 1, nodes)?;
            continue;
        }
        ensure!(nodes.len() < MAX_NODES, "too many proxy nodes");
        nodes.push(parse_node(line)?);
    }
    Ok(())
}

fn decoded_subscription(input: &str) -> Option<String> {
    if input.contains("://") {
        return None;
    }
    String::from_utf8(decode_base64(input)?)
        .ok()
        .filter(|decoded| decoded.contains("://"))
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let compact = value
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(&compact).ok())
}

fn parse_node(uri: &str) -> Result<Node> {
    let scheme = uri
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("invalid proxy URI"))?;
    match scheme.as_str() {
        "ss" => parse_shadowsocks(uri),
        "vmess" => parse_vmess(uri),
        "vless" | "trojan" | "hysteria2" | "tuic" | "anytls" => parse_url_node(uri, &scheme),
        "hy2" | "hysteria" => parse_url_node(uri, "hysteria2"),
        _ => bail!("unsupported proxy URI"),
    }
}

fn parse_url_node(uri: &str, kind: &str) -> Result<Node> {
    let url = Url::parse(uri).map_err(|_| anyhow!("invalid proxy URI"))?;
    let server = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy server is missing"))?;
    let mut node = Node::empty(kind, uri);
    node.server = server.to_owned();
    node.port = url.port().unwrap_or(443);
    node.name = url
        .fragment()
        .map(decode_component)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| server.to_owned());
    node.username = decode_component(url.username());
    let url_password = url.password().map(decode_component).unwrap_or_default();
    match kind {
        "vless" => node.uuid = node.username.clone(),
        "tuic" => {
            node.uuid = node.username.clone();
            node.password = url_password;
        }
        "trojan" | "hysteria2" | "anytls" => {
            node.password = if url_password.is_empty() {
                node.username.clone()
            } else {
                format!("{}:{}", node.username, url_password)
            };
        }
        _ => {}
    }
    node.network = {
        let value = query_value(&url, &["type"]);
        if value.is_empty() {
            "tcp".to_owned()
        } else {
            value
        }
    };
    node.path = query_value(&url, &["path"]);
    node.host = query_value(&url, &["host"]);
    node.service_name = query_value(&url, &["serviceName"]);
    node.sni = query_value(&url, &["sni"]);
    node.flow = query_value(&url, &["flow"]);
    node.obfs = query_value(&url, &["obfs"]);
    node.obfs_password = query_value(&url, &["obfs-password", "obfsPassword"]);
    let security = query_value(&url, &["security"]);
    node.tls = !matches!(kind, "vless" | "vmess");
    if !security.is_empty() {
        node.tls = !matches!(security.to_ascii_lowercase().as_str(), "none" | "false");
    }
    let insecure = query_value(&url, &["allowInsecure", "insecure"]);
    node.insecure = insecure == "1" || insecure.eq_ignore_ascii_case("true");
    if node.sni.is_empty() && !node.host.is_empty() {
        node.sni = node.host.clone();
    }
    if node.sni.is_empty() && node.tls {
        node.sni = node.server.clone();
    }
    ensure!(
        !(matches!(kind, "vless" | "tuic") && node.uuid.is_empty()
            || matches!(kind, "trojan" | "hysteria2" | "anytls") && node.password.is_empty()),
        "proxy credentials are missing"
    );
    Ok(node)
}

fn parse_shadowsocks(uri: &str) -> Result<Node> {
    let rest = uri
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow!("invalid Shadowsocks URI"))?;
    let fragment = rest
        .split_once('#')
        .map(|(_, value)| decode_component(value));
    let without_fragment = rest.split('#').next().unwrap_or_default();
    let authority = without_fragment.split('?').next().unwrap_or_default();
    let (credentials, server_port) = if let Some((credentials, server)) = authority.rsplit_once('@')
    {
        let decoded = decode_component(credentials);
        let credentials = if decoded.contains(':') {
            decoded
        } else {
            String::from_utf8(
                decode_base64(&decoded)
                    .ok_or_else(|| anyhow!("invalid Shadowsocks credentials"))?,
            )?
        };
        (credentials, server.to_owned())
    } else {
        let decoded = String::from_utf8(
            decode_base64(authority).ok_or_else(|| anyhow!("invalid Shadowsocks URI"))?,
        )?;
        decoded
            .rsplit_once('@')
            .map(|(credentials, server)| (credentials.to_owned(), server.to_owned()))
            .ok_or_else(|| anyhow!("invalid Shadowsocks URI"))?
    };
    let (method, password) = credentials
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid Shadowsocks credentials"))?;
    let (server, port) = split_server_port(&server_port)?;
    let mut node = Node::empty("shadowsocks", uri);
    node.name = fragment
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| server.clone());
    node.server = server;
    node.port = port;
    node.method = method.to_owned();
    node.password = password.to_owned();
    ensure!(
        !node.method.is_empty() && !node.password.is_empty(),
        "invalid Shadowsocks credentials"
    );
    Ok(node)
}

fn split_server_port(value: &str) -> Result<(String, u16)> {
    let url = Url::parse(&format!("tcp://{value}"))
        .map_err(|_| anyhow!("invalid proxy server address"))?;
    Ok((
        url.host_str()
            .ok_or_else(|| anyhow!("proxy server is missing"))?
            .to_owned(),
        url.port().unwrap_or(443),
    ))
}

fn parse_vmess(uri: &str) -> Result<Node> {
    let encoded = uri
        .strip_prefix("vmess://")
        .ok_or_else(|| anyhow!("invalid VMess URI"))?;
    let encoded = encoded.split('#').next().unwrap_or_default();
    let decoded = decode_base64(encoded).ok_or_else(|| anyhow!("invalid VMess payload"))?;
    let value: Value =
        serde_json::from_slice(&decoded).map_err(|_| anyhow!("invalid VMess JSON"))?;
    let string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut node = Node::empty("vmess", uri);
    node.server = string("add");
    node.port = value
        .get("port")
        .and_then(|port| {
            port.as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .or_else(|| port.as_str().and_then(|port| port.parse().ok()))
        })
        .unwrap_or(443);
    node.uuid = string("id");
    node.name = uri
        .split_once('#')
        .map(|(_, name)| decode_component(name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| string("ps"));
    if node.name.is_empty() {
        node.name = node.server.clone();
    }
    node.network = string("net");
    if node.network.is_empty() {
        node.network = "tcp".to_owned();
    }
    node.path = string("path");
    node.host = string("host");
    node.sni = string("sni");
    node.tls = !matches!(string("tls").to_ascii_lowercase().as_str(), "" | "none");
    if node.sni.is_empty() && node.tls {
        node.sni = node.server.clone();
    }
    ensure!(
        !node.server.is_empty() && !node.uuid.is_empty(),
        "VMess server or UUID is missing"
    );
    Ok(node)
}

fn render_singbox(nodes: &[Node]) -> Result<String> {
    let mut outbounds = nodes.iter().map(singbox_node).collect::<Vec<_>>();
    outbounds.push(json!({
        "type": "selector",
        "tag": "PROXY",
        "outbounds": nodes.iter().map(|node| node.name.clone()).collect::<Vec<_>>()
    }));
    outbounds.push(json!({ "type": "direct", "tag": "DIRECT" }));
    Ok(serde_json::to_string(&json!({
        "log": { "level": "warn" },
        "dns": { "servers": [{ "type": "udp", "tag": "dns", "server": "223.5.5.5" }], "final": "dns" },
        "inbounds": [],
        "outbounds": outbounds,
        "route": { "final": "PROXY" }
    }))?)
}

fn singbox_node(node: &Node) -> Value {
    let mut output = serde_json::Map::from_iter([
        ("type".to_owned(), json!(node.kind)),
        ("tag".to_owned(), json!(node.name)),
        ("server".to_owned(), json!(node.server)),
        ("server_port".to_owned(), json!(node.port)),
    ]);
    match node.kind.as_str() {
        "shadowsocks" => {
            output.insert("method".to_owned(), json!(node.method));
            output.insert("password".to_owned(), json!(node.password));
        }
        "vmess" => {
            output.insert("uuid".to_owned(), json!(node.uuid));
        }
        "vless" => {
            output.insert("uuid".to_owned(), json!(node.uuid));
            if !node.flow.is_empty() {
                output.insert("flow".to_owned(), json!(node.flow));
            }
        }
        "tuic" => {
            output.insert("uuid".to_owned(), json!(node.uuid));
            output.insert("password".to_owned(), json!(node.password));
        }
        _ => {
            output.insert("password".to_owned(), json!(node.password));
        }
    }
    if node.tls {
        output.insert(
            "tls".to_owned(),
            json!({
                "enabled": true,
                "server_name": node.sni,
                "insecure": node.insecure
            }),
        );
    }
    if node.kind == "hysteria2" && node.obfs == "salamander" {
        output.insert(
            "obfs".to_owned(),
            json!({ "type": "salamander", "password": node.obfs_password }),
        );
    }
    if node.network != "tcp" && node.kind != "shadowsocks" {
        let mut transport = serde_json::Map::from_iter([("type".to_owned(), json!(node.network))]);
        if !node.path.is_empty() {
            transport.insert("path".to_owned(), json!(node.path));
        }
        if !node.host.is_empty() {
            transport.insert("headers".to_owned(), json!({ "Host": node.host }));
        }
        if !node.service_name.is_empty() {
            transport.insert("service_name".to_owned(), json!(node.service_name));
        }
        output.insert("transport".to_owned(), Value::Object(transport));
    }
    Value::Object(output)
}

fn render_clash(nodes: &[Node]) -> String {
    let mut output =
        String::from("mixed-port: 7890\nmode: rule\nallow-lan: false\nlog-level: warn\nproxies:\n");
    for node in nodes {
        let _ = writeln!(output, "  - name: {}", yaml_quote(&node.name));
        let kind = if node.kind == "shadowsocks" {
            "ss"
        } else {
            &node.kind
        };
        yaml_field(&mut output, "type", kind);
        yaml_field(&mut output, "server", &node.server);
        let _ = writeln!(output, "    port: {}", node.port);
        match node.kind.as_str() {
            "shadowsocks" => {
                yaml_field(&mut output, "cipher", &node.method);
                yaml_field(&mut output, "password", &node.password);
            }
            "vmess" | "vless" => yaml_field(&mut output, "uuid", &node.uuid),
            "tuic" => {
                yaml_field(&mut output, "uuid", &node.uuid);
                yaml_field(&mut output, "password", &node.password);
            }
            _ => yaml_field(&mut output, "password", &node.password),
        }
        if node.tls {
            output.push_str("    tls: true\n");
            if node.kind == "hysteria2" {
                yaml_field(&mut output, "sni", &node.sni);
            } else {
                yaml_field(&mut output, "servername", &node.sni);
            }
            if node.insecure {
                output.push_str("    skip-cert-verify: true\n");
            }
        }
        if node.kind == "hysteria2" && node.obfs == "salamander" {
            yaml_field(&mut output, "obfs", &node.obfs);
            yaml_field(&mut output, "obfs-password", &node.obfs_password);
        }
        if node.network != "tcp" && node.kind != "shadowsocks" {
            yaml_field(&mut output, "network", &node.network);
            if matches!(node.network.as_str(), "ws" | "http") {
                let _ = writeln!(output, "    {}-opts:", node.network);
                if !node.path.is_empty() {
                    let _ = writeln!(output, "      path: {}", yaml_quote(&node.path));
                }
                if !node.host.is_empty() {
                    let _ = writeln!(
                        output,
                        "      headers:\n        Host: {}",
                        yaml_quote(&node.host)
                    );
                }
            }
        }
    }
    output.push_str("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n");
    for node in nodes {
        let _ = writeln!(output, "      - {}", yaml_quote(&node.name));
    }
    output.push_str("      - DIRECT\nrules:\n  - MATCH,PROXY\n");
    output
}

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''").replace(['\r', '\n'], " "))
}

fn yaml_field(output: &mut String, key: &str, value: &str) {
    let _ = writeln!(output, "    {key}: {}", yaml_quote(value));
}

fn render_surge(nodes: &[Node]) -> String {
    let mut output = String::from("[General]\nloglevel = notify\n\n[Proxy]\n");
    for node in nodes {
        let kind = if node.kind == "shadowsocks" {
            "ss"
        } else {
            &node.kind
        };
        let _ = write!(
            output,
            "{} = {},{},{}",
            surge_value(&node.name),
            kind,
            surge_value(&node.server),
            node.port
        );
        match node.kind.as_str() {
            "shadowsocks" => {
                let _ = write!(
                    output,
                    ",encrypt-method={},password={}",
                    surge_value(&node.method),
                    surge_value(&node.password)
                );
            }
            "vmess" | "vless" => {
                let _ = write!(output, ",username={}", surge_value(&node.uuid));
            }
            _ => {
                let _ = write!(output, ",password={}", surge_value(&node.password));
            }
        }
        if node.tls {
            output.push_str(",tls=true");
        }
        if !node.sni.is_empty() {
            let _ = write!(output, ",sni={}", surge_value(&node.sni));
        }
        output.push('\n');
    }
    output.push_str("\n[Proxy Group]\nPROXY = select,");
    output.push_str(
        &nodes
            .iter()
            .map(|node| surge_value(&node.name))
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push_str(",DIRECT\n\n[Rule]\nFINAL,PROXY\n");
    output
}

fn surge_value(value: &str) -> String {
    value.replace(['\r', '\n', ','], "_")
}

fn format_for_prefix(prefix: &str) -> Option<&'static str> {
    match prefix {
        "b" => Some("singbox"),
        "c" => Some("clash"),
        "s" => Some("surge"),
        "x" => Some("xray"),
        _ => None,
    }
}

fn auto_format(user_agent: &str, accept: &str) -> &'static str {
    let user_agent = user_agent.to_ascii_lowercase();
    let accept = accept.to_ascii_lowercase();
    if user_agent.contains("clash-meta")
        || user_agent.contains("clash verge")
        || user_agent.contains("clash")
        || user_agent.contains("mihomo")
        || accept.contains("yaml")
    {
        "clash"
    } else if user_agent.contains("surge") {
        "surge"
    } else if user_agent.contains("sing-box")
        || user_agent.contains("singbox")
        || accept.contains("json")
    {
        "singbox"
    } else {
        "xray"
    }
}

fn split_short_path(path: &str) -> Result<(&str, &str)> {
    let mut parts = path.trim_start_matches('/').split('/');
    let prefix = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    ensure!(
        !prefix.is_empty() && valid_code(code) && parts.next().is_none(),
        "invalid short URL"
    );
    Ok((prefix, code))
}

fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 32
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn random_code() -> Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut random = [0_u8; 7];
    getrandom::fill(&mut random)?;
    Ok(random
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect())
}

fn stable_code(value: &[u8]) -> String {
    let digest = Blake2s256::digest(value);
    digest[..10]
        .iter()
        .fold(String::with_capacity(20), |mut code, byte| {
            let _ = write!(code, "{byte:02x}");
            code
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLESS: &str = "vless://12345678-1234-1234-1234-123456789012@example.com:443?type=ws&security=tls&path=%2Fws&host=edge.example.com#smoke";

    #[test]
    fn converts_vless_to_singbox_and_clash() {
        let service = SublinkService::default();
        let singbox = service.convert("singbox", VLESS).unwrap().body;
        let parsed: Value = serde_json::from_str(&singbox).unwrap();
        assert_eq!(parsed["outbounds"][0]["type"], "vless");
        assert_eq!(parsed["outbounds"][0]["transport"]["path"], "/ws");
        let clash = service.convert("clash", VLESS).unwrap().body;
        assert!(clash.contains("type: 'vless'"));
        assert!(clash.contains("Host: 'edge.example.com'"));
    }

    #[test]
    fn accepts_base64_subscriptions_and_rejects_remote_urls() {
        let service = SublinkService::default();
        let encoded = STANDARD.encode(VLESS);
        assert!(service.convert("xray", &encoded).is_ok());
        assert!(
            service
                .convert("singbox", "https://example.com/sub")
                .is_err()
        );
    }

    #[test]
    fn parses_every_supported_proxy_scheme() {
        let vmess = STANDARD.encode(
            br#"{"v":"2","ps":"vmess","add":"vmess.example.com","port":"443","id":"12345678-1234-1234-1234-123456789012","net":"tcp","tls":"tls"}"#,
        );
        let shadowsocks = STANDARD.encode("aes-128-gcm:secret");
        let input = format!(
            "ss://{shadowsocks}@ss.example.com:8388#ss\nvmess://{vmess}\n{VLESS}\ntrojan://secret@trojan.example.com:443#trojan\nhysteria2://secret@hy2.example.com:443#hy2\ntuic://12345678-1234-1234-1234-123456789012:secret@tuic.example.com:443#tuic\nanytls://secret@anytls.example.com:443#anytls"
        );
        let output = SublinkService::default()
            .convert("singbox", &input)
            .unwrap()
            .body;
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let types = parsed["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .take(7)
            .map(|outbound| outbound["type"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            [
                "shadowsocks",
                "vmess",
                "vless",
                "trojan",
                "hysteria2",
                "tuic",
                "anytls"
            ]
        );
    }

    #[tokio::test]
    async fn creates_redirects_and_resolves_short_links() {
        let service = SublinkService::default();
        let long = format!(
            "https://example.com/singbox?config={}",
            url::form_urlencoded::byte_serialize(VLESS.as_bytes()).collect::<String>()
        );
        let code = service.shorten(&long, Some("sample")).await.unwrap();
        assert_eq!(code, "sample");
        assert!(
            service
                .redirect("b", &code)
                .await
                .unwrap()
                .starts_with("/singbox?")
        );
        let resolved = service
            .resolve("https://example.com/b/sample")
            .await
            .unwrap();
        assert!(resolved.contains("https://example.com/singbox?"));
    }

    #[tokio::test]
    async fn permanent_hy2_short_links_survive_service_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hy2-short-links.toml");
        let config = "hysteria2://password@example.com:443/?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret#user";
        let raw = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>()
        );
        let expected = raw.strip_prefix("https://example.com").unwrap();
        let first = SublinkService::with_persistence(path.clone()).unwrap();
        let code = first.shorten_hy2(&raw).await.unwrap();
        assert_eq!(first.redirect("x", &code).await.unwrap(), expected);

        let second = SublinkService::with_persistence(path).unwrap();
        assert_eq!(second.redirect("x", &code).await.unwrap(), expected);
    }

    #[tokio::test]
    async fn automatic_hy2_short_links_match_client_format() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret#user";
        let raw = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>()
        );
        let code = service.shorten_hy2(&raw).await.unwrap();
        for user_agent in ["Clash Meta", "Clash Verge Rev"] {
            let body = service.auto(&code, user_agent, "").await.unwrap().body;
            assert!(body.contains("proxies:"));
            assert!(body.contains("sni: 'example.com'"));
            assert!(body.contains("obfs: 'salamander'"));
        }
        assert!(
            service
                .auto(&code, "sing-box", "")
                .await
                .unwrap()
                .body
                .contains("outbounds")
        );
        assert_eq!(
            service.auto(&code, "xray", "").await.unwrap().content_type,
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn automatic_converter_short_links_keep_full_proxy_query() {
        let service = SublinkService::default();
        let raw = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(VLESS.as_bytes()).collect::<String>()
        );
        let code = service.shorten_auto(&raw).await.unwrap();
        let output = service.auto(&code, "Clash Meta", "").await.unwrap();
        assert!(output.body.contains("edge.example.com"));
    }
}
