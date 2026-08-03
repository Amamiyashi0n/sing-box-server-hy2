use std::{
    collections::{HashSet, VecDeque},
    env,
    fmt::Write as _,
    fs,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use url::{Host, Url};

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_NODES: usize = 128;
const MAX_NESTING: usize = 2;
const DEFAULT_SHORT_LINKS: usize = 512;
const DEFAULT_SHORT_TTL: Duration = Duration::from_secs(86_400);
const FORMATS: [&str; 4] = ["singbox", "clash", "surge", "xray"];
const SITE_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/";
const IP_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geoip/";
const SINGBOX_SITE_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/";
const SINGBOX_IP_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/";
const SURGE_SITE_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/NSZA156/surge-geox-rules/raw/refs/heads/release/geo/geosite/";
const SURGE_IP_RULE_BASE: &str = "https://gh-proxy.com/https://github.com/NSZA156/surge-geox-rules/raw/refs/heads/release/geo/geoip/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RulePreset {
    Minimal,
    Balanced,
    Comprehensive,
    China,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleAction {
    Proxy,
    Direct,
    Reject,
}

#[derive(Clone, Copy, Debug)]
struct RuleSpec {
    name: &'static str,
    sites: &'static [&'static str],
    ips: &'static [&'static str],
    action: RuleAction,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum DomainRule {
    Exact(String),
    Suffix(String),
}

#[derive(Debug, Default)]
struct CustomRules {
    whitelist: Vec<DomainRule>,
    blacklist: Vec<DomainRule>,
}

const RULES: &[RuleSpec] = &[
    RuleSpec {
        name: "Ad Block",
        sites: &["category-ads-all"],
        ips: &[],
        action: RuleAction::Reject,
    },
    RuleSpec {
        name: "AI Services",
        sites: &["category-ai-!cn"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Bilibili",
        sites: &["bilibili"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Youtube",
        sites: &["youtube"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Google",
        sites: &["google"],
        ips: &["google"],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Private",
        sites: &[],
        ips: &["private"],
        action: RuleAction::Direct,
    },
    RuleSpec {
        name: "Location:CN",
        sites: &["geolocation-cn", "cn"],
        ips: &["cn"],
        action: RuleAction::Direct,
    },
    RuleSpec {
        name: "Telegram",
        sites: &[],
        ips: &["telegram"],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Github",
        sites: &["github", "gitlab"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Microsoft",
        sites: &["microsoft"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Apple",
        sites: &["apple"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Social Media",
        sites: &["facebook", "instagram", "twitter", "tiktok", "linkedin"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Streaming",
        sites: &["netflix", "hulu", "disney", "hbo", "amazon", "bahamut"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Gaming",
        sites: &["steam", "epicgames", "ea", "ubisoft", "blizzard"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Education",
        sites: &[
            "coursera",
            "edx",
            "udemy",
            "khanacademy",
            "category-scholar-!cn",
        ],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Financial",
        sites: &["paypal", "visa", "mastercard", "stripe", "wise"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Cloud Services",
        sites: &["aws", "azure", "digitalocean", "heroku", "dropbox"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Non-China",
        sites: &["geolocation-!cn"],
        ips: &[],
        action: RuleAction::Proxy,
    },
];

const CHINA_RULES: &[RuleSpec] = &[
    RuleSpec {
        name: "Ad Block",
        sites: &["category-ads-all"],
        ips: &[],
        action: RuleAction::Reject,
    },
    RuleSpec {
        name: "Private",
        sites: &["private"],
        ips: &["private"],
        action: RuleAction::Direct,
    },
    RuleSpec {
        name: "China Services",
        sites: &[
            "apple-cn",
            "microsoft@cn",
            "steam@cn",
            "category-games@cn",
            "bilibili",
        ],
        ips: &[],
        action: RuleAction::Direct,
    },
    RuleSpec {
        name: "AI Services",
        sites: &["category-ai-!cn"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Youtube",
        sites: &["youtube"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Google",
        sites: &["google"],
        ips: &["google"],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Telegram",
        sites: &[],
        ips: &["telegram"],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Github",
        sites: &["github", "gitlab"],
        ips: &[],
        action: RuleAction::Proxy,
    },
    RuleSpec {
        name: "Location:CN",
        sites: &["geolocation-cn", "cn"],
        ips: &["cn"],
        action: RuleAction::Direct,
    },
    RuleSpec {
        name: "Non-China",
        sites: &["geolocation-!cn"],
        ips: &[],
        action: RuleAction::Proxy,
    },
];

#[derive(Debug, Clone)]
struct Node {
    kind: String,
    name: String,
    server: String,
    port: u16,
    username: String,
    password: String,
    private_key: String,
    host_key: String,
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
    packet_encoding: String,
    udp: bool,
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
            private_key: String::new(),
            host_key: String::new(),
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
            packet_encoding: String::new(),
            udp: false,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<u64>,
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
            entry.expires_at_unix = None;
        } else {
            self.permanent.push(PersistentShortLink {
                code,
                query,
                expires_at_unix: None,
            });
        }
        self.persist()
    }

    fn put_persisted_expiring(&mut self, code: String, query: String) -> Result<()> {
        ensure!(!self.disabled, "memory short-link storage is disabled");
        let now = unix_time();
        self.permanent.retain(|entry| {
            entry
                .expires_at_unix
                .is_none_or(|expires_at| expires_at > now)
        });
        let expires_at_unix = now.saturating_add(self.ttl.as_secs());
        if let Some(entry) = self.permanent.iter_mut().find(|entry| entry.code == code) {
            entry.query = query;
            entry.expires_at_unix = Some(expires_at_unix);
        } else {
            while self
                .permanent
                .iter()
                .filter(|entry| entry.expires_at_unix.is_some())
                .count()
                >= self.limit
            {
                let Some((index, _)) = self
                    .permanent
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| {
                        entry.expires_at_unix.map(|expiry| (index, expiry))
                    })
                    .min_by_key(|(_, expiry)| *expiry)
                else {
                    break;
                };
                self.permanent.remove(index);
            }
            self.permanent.push(PersistentShortLink {
                code,
                query,
                expires_at_unix: Some(expires_at_unix),
            });
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
            .find(|entry| {
                entry.code == code
                    && entry
                        .expires_at_unix
                        .is_none_or(|expires_at| expires_at > unix_time())
            })
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
        self.convert_with_rules(format, input, None, false)
    }

    pub fn convert_with_rules(
        &self,
        format: &str,
        input: &str,
        selected_rules: Option<&str>,
        ad_block: bool,
    ) -> Result<SublinkOutput> {
        self.convert_with_custom_rules(format, input, selected_rules, ad_block, None, None)
    }

    pub fn convert_with_custom_rules(
        &self,
        format: &str,
        input: &str,
        selected_rules: Option<&str>,
        ad_block: bool,
        whitelist: Option<&str>,
        blacklist: Option<&str>,
    ) -> Result<SublinkOutput> {
        self.convert_with_rule_format(
            format,
            input,
            selected_rules,
            ad_block,
            whitelist,
            blacklist,
            true,
        )
    }

    fn convert_with_rule_format(
        &self,
        format: &str,
        input: &str,
        selected_rules: Option<&str>,
        ad_block: bool,
        whitelist: Option<&str>,
        blacklist: Option<&str>,
        clash_mrs: bool,
    ) -> Result<SublinkOutput> {
        let nodes = parse_input(input)?;
        let compatible_nodes = if format == "clash" {
            nodes.clone()
        } else {
            nodes
                .iter()
                .filter(|node| node.kind != "ssh")
                .cloned()
                .collect::<Vec<_>>()
        };
        ensure!(
            !compatible_nodes.is_empty(),
            "output format does not support any subscription nodes"
        );
        let preset = selected_rules.map(parse_rule_preset).transpose()?;
        let rules = selected_rule_specs(preset, ad_block);
        let custom_rules = parse_custom_rules(whitelist, blacklist)?;
        let china_optimized = preset == Some(RulePreset::China);
        let profile_name = subscription_name(&nodes);
        match format {
            "singbox" => Ok(SublinkOutput::new(
                "application/json; charset=utf-8",
                render_singbox(&compatible_nodes, &rules, &custom_rules, china_optimized)?,
                profile_name,
                "json",
            )),
            "clash" => Ok(SublinkOutput::new(
                "text/yaml; charset=utf-8",
                render_clash(
                    &compatible_nodes,
                    &rules,
                    &custom_rules,
                    clash_mrs,
                    china_optimized,
                ),
                profile_name,
                "yaml",
            )),
            "surge" => Ok(SublinkOutput::new(
                "text/plain; charset=utf-8",
                render_surge(&compatible_nodes, &rules, &custom_rules, china_optimized),
                profile_name,
                "conf",
            )),
            "xray" => Ok(SublinkOutput::new(
                "text/plain; charset=utf-8",
                STANDARD.encode(
                    compatible_nodes
                        .iter()
                        .map(|node| node.original.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                profile_name,
                "txt",
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
        let config = query_value(&url, &["config"]);
        let nodes = parse_input(&config).map_err(|_| anyhow!("invalid HY2 URL parameter"))?;
        ensure!(
            !nodes.is_empty()
                && nodes
                    .iter()
                    .all(|node| matches!(node.kind.as_str(), "hysteria2" | "vless" | "ssh")),
            "invalid HY2 URL parameter"
        );
        ensure!(
            config.len() <= MAX_INPUT_BYTES,
            "URL parameter is too large"
        );
        let identity = query_value_optional(&url, &["identity"]);
        let primary_hy2 = match identity.as_deref() {
            Some(identity) => {
                let identity_nodes =
                    parse_input(identity).map_err(|_| anyhow!("invalid HY2 identity parameter"))?;
                ensure!(
                    identity_nodes.len() == 1 && identity_nodes[0].kind == "hysteria2",
                    "invalid HY2 identity parameter"
                );
                identity.trim()
            }
            None => config
                .lines()
                .map(str::trim)
                .find(|line| line.starts_with("hysteria2://"))
                .ok_or_else(|| anyhow!("invalid HY2 URL parameter"))?,
        };
        let code = stable_code(primary_hy2.as_bytes());
        let selected_rules = query_value_optional(&url, &["selectedRules"]);
        if let Some(selected_rules) = selected_rules.as_deref() {
            parse_rule_preset(selected_rules)?;
        }
        let ad_block = query_bool(&url, &["adblock"]);
        let whitelist = query_value_optional(&url, &["whitelist"]);
        let blacklist = query_value_optional(&url, &["blacklist"]);
        parse_custom_rules(whitelist.as_deref(), blacklist.as_deref())?;
        let query = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("config", &config);
            if let Some(selected_rules) = selected_rules {
                serializer.append_pair("selectedRules", &selected_rules);
            }
            if ad_block {
                serializer.append_pair("adblock", "true");
            }
            if let Some(whitelist) = whitelist.filter(|value| !value.trim().is_empty()) {
                serializer.append_pair("whitelist", &whitelist);
            }
            if let Some(blacklist) = blacklist.filter(|value| !value.trim().is_empty()) {
                serializer.append_pair("blacklist", &blacklist);
            }
            serializer.finish()
        };
        self.store
            .lock()
            .await
            .put_permanent(code.clone(), format!("?{query}"))?;
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
        let config = query_value(&url, &["config"]);
        ensure!(!config.is_empty(), "invalid URL parameter");
        ensure!(
            config.len() <= MAX_INPUT_BYTES,
            "URL parameter is too large"
        );
        if let Some(selected_rules) = query_value_optional(&url, &["selectedRules"]) {
            parse_rule_preset(&selected_rules)?;
        }
        parse_custom_rules(
            query_value_optional(&url, &["whitelist"]).as_deref(),
            query_value_optional(&url, &["blacklist"]).as_deref(),
        )?;
        let query = url
            .query()
            .filter(|query| !query.is_empty())
            .ok_or_else(|| anyhow!("invalid URL parameter"))?;
        ensure!(query.len() <= MAX_INPUT_BYTES, "URL parameter is too large");
        let code = stable_code(query.as_bytes());
        self.store
            .lock()
            .await
            .put_persisted_expiring(code.clone(), format!("?{query}"))?;
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
        self.auto_with_format(code, user_agent, accept, None).await
    }

    pub async fn auto_with_format(
        &self,
        code: &str,
        user_agent: &str,
        accept: &str,
        requested_format: Option<&str>,
    ) -> Result<SublinkOutput> {
        self.auto_with_overrides(
            code,
            user_agent,
            accept,
            requested_format,
            None,
            None,
            false,
        )
        .await
    }

    pub async fn auto_with_overrides(
        &self,
        code: &str,
        user_agent: &str,
        accept: &str,
        requested_format: Option<&str>,
        server_override: Option<&str>,
        port_override: Option<u16>,
        tcp_only: bool,
    ) -> Result<SublinkOutput> {
        ensure!(valid_code(code), "invalid short URL");
        let query = self
            .store
            .lock()
            .await
            .get(code)
            .ok_or_else(|| anyhow!("short URL not found"))?;
        let url = Url::parse(&format!("https://short.local/xray{query}"))
            .map_err(|_| anyhow!("invalid short URL"))?;
        let mut config = query_value(&url, &["config"]);
        if server_override.is_some() || port_override.is_some() || tcp_only {
            config = rewrite_subscription_input(&config, server_override, port_override, tcp_only)?;
        }
        let selected_rules = query_value_optional(&url, &["selectedRules"]);
        let ad_block = query_bool(&url, &["adblock"]);
        let whitelist = query_value_optional(&url, &["whitelist"]);
        let blacklist = query_value_optional(&url, &["blacklist"]);
        let format = requested_format
            .map(normalize_format)
            .transpose()?
            .unwrap_or_else(|| auto_format(user_agent, accept));
        self.convert_with_rule_format(
            format,
            &config,
            selected_rules.as_deref(),
            ad_block,
            whitelist.as_deref(),
            blacklist.as_deref(),
            supports_mrs_format(user_agent),
        )
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

fn rewrite_subscription_input(
    input: &str,
    server_override: Option<&str>,
    port_override: Option<u16>,
    tcp_only: bool,
) -> Result<String> {
    ensure!(
        server_override.is_some() == port_override.is_some(),
        "subscription server and port overrides must be used together"
    );
    let nodes = parse_input(input)?;
    let mut rewritten = Vec::with_capacity(nodes.len());
    for node in nodes {
        if tcp_only && !matches!(node.kind.as_str(), "vless" | "ssh") {
            continue;
        }
        let mut url = Url::parse(&node.original).map_err(|_| anyhow!("invalid proxy URI"))?;
        if let (Some(server), Some(port)) = (server_override, port_override) {
            url.set_host(Some(server))
                .map_err(|_| anyhow!("invalid subscription server override"))?;
            url.set_port(Some(port))
                .map_err(|_| anyhow!("invalid subscription port override"))?;
        }
        rewritten.push(url.to_string());
    }
    ensure!(
        !rewritten.is_empty(),
        "subscription contains no compatible TCP nodes"
    );
    Ok(rewritten.join("\n"))
}

pub struct SublinkOutput {
    pub content_type: &'static str,
    pub body: String,
    pub profile_name: String,
    pub file_extension: &'static str,
}

impl SublinkOutput {
    fn new(
        content_type: &'static str,
        body: String,
        profile_name: String,
        file_extension: &'static str,
    ) -> Self {
        Self {
            content_type,
            body,
            profile_name,
            file_extension,
        }
    }
}

fn subscription_name(nodes: &[Node]) -> String {
    let name = nodes
        .iter()
        .find(|node| node.kind == "hysteria2")
        .or_else(|| nodes.first())
        .map(|node| node.name.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or("subscription");
    name.strip_suffix("-VLESS")
        .or_else(|| name.strip_suffix("-SSH"))
        .unwrap_or(name)
        .to_owned()
}

fn positive_env(name: &str, fallback: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn query_value(url: &Url, names: &[&str]) -> String {
    query_value_optional(url, names).unwrap_or_default()
}

fn query_value_optional(url: &Url, names: &[&str]) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| names.iter().any(|name| key.eq_ignore_ascii_case(name)))
        .map(|(_, value)| value.into_owned())
}

fn query_bool(url: &Url, names: &[&str]) -> bool {
    query_value(url, names).trim().eq_ignore_ascii_case("true")
        || query_value(url, names).trim() == "1"
}

fn parse_custom_rules(whitelist: Option<&str>, blacklist: Option<&str>) -> Result<CustomRules> {
    Ok(CustomRules {
        whitelist: parse_domain_rules(whitelist.unwrap_or_default(), "whitelist")?,
        blacklist: parse_domain_rules(blacklist.unwrap_or_default(), "blacklist")?,
    })
}

fn parse_domain_rules(value: &str, label: &str) -> Result<Vec<DomainRule>> {
    ensure!(value.len() <= 8 * 1024, "{label} is too large");
    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    for raw in value.split([',', '\n', '\r']) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (suffix, domain) = if let Some(domain) = raw.strip_prefix("*.") {
            (true, domain)
        } else if let Some(domain) = raw.strip_prefix('.') {
            (true, domain)
        } else {
            (false, raw)
        };
        let domain = domain.trim_end_matches('.');
        ensure!(
            !domain.is_empty() && !domain.contains('*') && !domain.chars().any(char::is_whitespace),
            "invalid {label} domain: {raw}"
        );
        let domain =
            match Host::parse(domain).map_err(|_| anyhow!("invalid {label} domain: {raw}"))? {
                Host::Domain(domain) => domain,
                Host::Ipv4(_) | Host::Ipv6(_) => bail!("{label} only supports domain names: {raw}"),
            };
        let rule = if suffix {
            DomainRule::Suffix(domain)
        } else {
            DomainRule::Exact(domain)
        };
        if seen.insert(rule.clone()) {
            rules.push(rule);
        }
    }
    ensure!(rules.len() <= 128, "too many {label} domains");
    Ok(rules)
}

pub(crate) fn validate_custom_rule_values(values: &[String], label: &str) -> Result<()> {
    let joined = values.join("\n");
    parse_domain_rules(&joined, label)?;
    Ok(())
}

fn parse_rule_preset(value: &str) -> Result<RulePreset> {
    match value.trim().to_ascii_lowercase().as_str() {
        "minimal" => Ok(RulePreset::Minimal),
        "balanced" => Ok(RulePreset::Balanced),
        "comprehensive" => Ok(RulePreset::Comprehensive),
        "china" => Ok(RulePreset::China),
        _ => bail!("invalid selectedRules preset"),
    }
}

fn selected_rule_specs(preset: Option<RulePreset>, ad_block: bool) -> Vec<&'static RuleSpec> {
    if preset == Some(RulePreset::China) {
        return CHINA_RULES
            .iter()
            .filter(|rule| ad_block || rule.name != "Ad Block")
            .collect();
    }
    let mut selected = Vec::new();
    for rule in RULES {
        let included = match preset {
            None => false,
            Some(RulePreset::Minimal) => {
                matches!(rule.name, "Location:CN" | "Private" | "Non-China")
            }
            Some(RulePreset::Balanced) => matches!(
                rule.name,
                "Location:CN"
                    | "Private"
                    | "Non-China"
                    | "Github"
                    | "Google"
                    | "Youtube"
                    | "AI Services"
                    | "Telegram"
            ),
            Some(RulePreset::Comprehensive) => true,
            Some(RulePreset::China) => unreachable!(),
        };
        if included || ad_block && rule.name == "Ad Block" {
            selected.push(rule);
        }
    }
    selected
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
        "vless" | "hysteria2" | "tuic" | "ssh" => parse_url_node(uri, &scheme),
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
        "hysteria2" => {
            node.password = if url_password.is_empty() {
                node.username.clone()
            } else {
                format!("{}:{}", node.username, url_password)
            };
        }
        "ssh" => {
            node.password = url_password;
            node.private_key = query_value(&url, &["private-key", "privateKey"]);
            node.host_key = query_value(&url, &["host-key", "hostKey"]);
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
    if let Some(packet_encoding) =
        query_value_optional(&url, &["packetEncoding", "packet-encoding"])
    {
        node.packet_encoding = packet_encoding;
        node.udp = true;
    }
    node.obfs = query_value(&url, &["obfs"]);
    node.obfs_password = query_value(&url, &["obfs-password", "obfsPassword"]);
    let security = query_value(&url, &["security"]);
    node.tls = !matches!(kind, "vless" | "vmess" | "ssh");
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
            || kind == "hysteria2" && node.password.is_empty()
            || kind == "ssh" && (node.username.is_empty() || node.private_key.is_empty())),
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

fn render_singbox(
    nodes: &[Node],
    selected_rules: &[&RuleSpec],
    custom_rules: &CustomRules,
    china_optimized: bool,
) -> Result<String> {
    let mut outbounds = nodes.iter().map(singbox_node).collect::<Vec<_>>();
    let proxy_names = proxy_node_names(nodes);
    outbounds.push(json!({
        "type": "selector",
        "tag": "PROXY",
        "outbounds": proxy_names
    }));
    outbounds.push(json!({ "type": "direct", "tag": "DIRECT" }));
    let mut route_rules = Vec::new();
    push_singbox_custom_rule(
        &mut route_rules,
        &custom_rules.blacklist,
        RuleAction::Reject,
    );
    push_singbox_custom_rule(
        &mut route_rules,
        &custom_rules.whitelist,
        RuleAction::Direct,
    );
    let mut rule_sets = Vec::new();
    for rule in selected_rules {
        let mut tags = Vec::new();
        for site in rule.sites {
            tags.push((*site).to_owned());
            rule_sets.push(json!({
                "type": "remote",
                "tag": site,
                "format": "binary",
                "url": format!("{SINGBOX_SITE_RULE_BASE}{site}.srs"),
                "download_detour": "DIRECT"
            }));
        }
        for ip in rule.ips {
            let tag = format!("{ip}-ip");
            tags.push(tag.clone());
            rule_sets.push(json!({
                "type": "remote",
                "tag": tag,
                "format": "binary",
                "url": format!("{SINGBOX_IP_RULE_BASE}{ip}.srs"),
                "download_detour": "DIRECT"
            }));
        }
        let mut route_rule = serde_json::Map::from_iter([("rule_set".to_owned(), json!(tags))]);
        match rule.action {
            RuleAction::Proxy => {
                route_rule.insert("outbound".to_owned(), json!("PROXY"));
            }
            RuleAction::Direct => {
                route_rule.insert("outbound".to_owned(), json!("DIRECT"));
            }
            RuleAction::Reject => {
                route_rule.insert("action".to_owned(), json!("reject"));
            }
        }
        route_rules.push(Value::Object(route_rule));
    }
    let dns = if china_optimized {
        let mut dns_rules = Vec::new();
        push_singbox_dns_rule(&mut dns_rules, &custom_rules.blacklist, "reject", None);
        push_singbox_dns_rule(
            &mut dns_rules,
            &custom_rules.whitelist,
            "route",
            Some("dns-cn-ali"),
        );
        dns_rules.extend([
            json!({ "rule_set": "private", "action": "route", "server": "dns-local" }),
            json!({
                "rule_set": [
                    "apple-cn",
                    "microsoft@cn",
                    "steam@cn",
                    "category-games@cn",
                    "bilibili"
                ],
                "action": "route",
                "server": "dns-cn-ali"
            }),
            json!({
                "rule_set": ["geolocation-cn", "cn"],
                "action": "route",
                "server": "dns-cn-tencent"
            }),
        ]);
        json!({
            "servers": [
                { "type": "local", "tag": "dns-local" },
                {
                    "type": "https",
                    "tag": "dns-cn-ali",
                    "server": "dns.alidns.com",
                    "domain_resolver": "dns-local"
                },
                {
                    "type": "https",
                    "tag": "dns-cn-tencent",
                    "server": "doh.pub",
                    "domain_resolver": "dns-local"
                },
                {
                    "type": "https",
                    "tag": "dns-global",
                    "server": "1.1.1.1",
                    "tls": { "enabled": true, "server_name": "cloudflare-dns.com" },
                    "detour": "PROXY"
                }
            ],
            "rules": dns_rules,
            "final": "dns-global"
        })
    } else {
        json!({
            "servers": [{ "type": "udp", "tag": "dns", "server": "223.5.5.5" }],
            "final": "dns"
        })
    };
    let route = if china_optimized {
        json!({
            "rules": route_rules,
            "rule_set": rule_sets,
            "final": "PROXY",
            "default_domain_resolver": "dns-local"
        })
    } else {
        json!({ "rules": route_rules, "rule_set": rule_sets, "final": "PROXY" })
    };
    Ok(serde_json::to_string(&json!({
        "log": { "level": "warn" },
        "dns": dns,
        "inbounds": [],
        "outbounds": outbounds,
        "route": route
    }))?)
}

fn domain_rule_fields(rules: &[DomainRule]) -> (Vec<&str>, Vec<&str>) {
    let mut exact = Vec::new();
    let mut suffix = Vec::new();
    for rule in rules {
        match rule {
            DomainRule::Exact(domain) => exact.push(domain.as_str()),
            DomainRule::Suffix(domain) => suffix.push(domain.as_str()),
        }
    }
    (exact, suffix)
}

fn push_singbox_custom_rule(output: &mut Vec<Value>, rules: &[DomainRule], action: RuleAction) {
    if rules.is_empty() {
        return;
    }
    let (exact, suffix) = domain_rule_fields(rules);
    let mut rule = serde_json::Map::new();
    if !exact.is_empty() {
        rule.insert("domain".to_owned(), json!(exact));
    }
    if !suffix.is_empty() {
        rule.insert("domain_suffix".to_owned(), json!(suffix));
    }
    match action {
        RuleAction::Direct => {
            rule.insert("outbound".to_owned(), json!("DIRECT"));
        }
        RuleAction::Reject => {
            rule.insert("action".to_owned(), json!("reject"));
        }
        RuleAction::Proxy => {
            rule.insert("outbound".to_owned(), json!("PROXY"));
        }
    }
    output.push(Value::Object(rule));
}

fn push_singbox_dns_rule(
    output: &mut Vec<Value>,
    rules: &[DomainRule],
    action: &str,
    server: Option<&str>,
) {
    if rules.is_empty() {
        return;
    }
    let (exact, suffix) = domain_rule_fields(rules);
    let mut rule = serde_json::Map::from_iter([("action".to_owned(), json!(action))]);
    if !exact.is_empty() {
        rule.insert("domain".to_owned(), json!(exact));
    }
    if !suffix.is_empty() {
        rule.insert("domain_suffix".to_owned(), json!(suffix));
    }
    if let Some(server) = server {
        rule.insert("server".to_owned(), json!(server));
    }
    output.push(Value::Object(rule));
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
            if node.udp {
                let packet_encoding = if node.packet_encoding.eq_ignore_ascii_case("none") {
                    ""
                } else {
                    &node.packet_encoding
                };
                output.insert("packet_encoding".to_owned(), json!(packet_encoding));
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

fn render_clash(
    nodes: &[Node],
    selected_rules: &[&RuleSpec],
    custom_rules: &CustomRules,
    use_mrs: bool,
    china_optimized: bool,
) -> String {
    let mut output = String::from(
        "mixed-port: 7890\nmode: rule\nallow-lan: false\nlog-level: warning\nproxies:\n",
    );
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
            "ssh" => {
                yaml_field(&mut output, "username", &node.username);
                yaml_block_field(&mut output, "private-key", &node.private_key);
                if !node.host_key.trim().is_empty() {
                    output.push_str("    host-key:\n");
                    for host_key in node
                        .host_key
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                    {
                        let _ = writeln!(output, "      - {}", yaml_quote(host_key));
                    }
                }
                output.push_str("    udp: false\n");
            }
            "shadowsocks" => {
                yaml_field(&mut output, "cipher", &node.method);
                yaml_field(&mut output, "password", &node.password);
            }
            "vmess" | "vless" => {
                yaml_field(&mut output, "uuid", &node.uuid);
                if node.kind == "vless" {
                    let _ = writeln!(output, "    udp: {}", node.udp);
                    if node.udp {
                        let packet_encoding = if node.packet_encoding.eq_ignore_ascii_case("none") {
                            ""
                        } else {
                            &node.packet_encoding
                        };
                        yaml_field(&mut output, "packet-encoding", packet_encoding);
                    }
                }
            }
            "tuic" => {
                yaml_field(&mut output, "uuid", &node.uuid);
                yaml_field(&mut output, "password", &node.password);
            }
            _ => yaml_field(&mut output, "password", &node.password),
        }
        if node.tls {
            if node.kind == "hysteria2" {
                yaml_field(&mut output, "sni", &node.sni);
                output.push_str("    alpn:\n      - h3\n");
            } else {
                output.push_str("    tls: true\n");
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
    for name in proxy_node_names(nodes) {
        let _ = writeln!(output, "      - {}", yaml_quote(&name));
    }
    output.push_str("      - DIRECT\n");
    if china_optimized && use_mrs {
        output.push_str(
            "dns:\n  enable: true\n  ipv6: true\n  cache-algorithm: arc\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter-mode: rule\n  fake-ip-filter:\n    - RULE-SET,private,real-ip\n    - RULE-SET,cn,real-ip\n",
        );
        for rule in &custom_rules.whitelist {
            write_clash_domain_rule(&mut output, rule, "real-ip", "    - ");
        }
        output.push_str(
            "    - MATCH,fake-ip\n  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n  proxy-server-nameserver:\n    - https://dns.alidns.com/dns-query\n    - https://doh.pub/dns-query\n  direct-nameserver:\n    - https://dns.alidns.com/dns-query\n    - https://doh.pub/dns-query\n  direct-nameserver-follow-policy: true\n  nameserver:\n    - https://1.1.1.1/dns-query#PROXY\n    - https://8.8.8.8/dns-query#PROXY\n  nameserver-policy:\n    'rule-set:private':\n      - system\n    'rule-set:apple-cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:microsoft@cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:steam@cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:category-games@cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:bilibili':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:geolocation-cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:cn':\n      - https://dns.alidns.com/dns-query\n      - https://doh.pub/dns-query\n    'rule-set:geolocation-!cn':\n      - https://1.1.1.1/dns-query#PROXY\n      - https://8.8.8.8/dns-query#PROXY\n",
        );
    }
    if !selected_rules.is_empty() {
        let rule_format = if use_mrs { "mrs" } else { "yaml" };
        output.push_str("rule-providers:\n");
        for rule in selected_rules {
            for site in rule.sites {
                let _ = writeln!(
                    output,
                    "  {site}:\n    type: http\n    behavior: domain\n    format: {rule_format}\n    url: {}\n    path: {}\n    interval: 86400",
                    yaml_quote(&format!("{SITE_RULE_BASE}{site}.{rule_format}")),
                    yaml_quote(&format!("./ruleset/{site}.{rule_format}"))
                );
                if china_optimized {
                    output.push_str("    proxy: DIRECT\n");
                }
            }
            for ip in rule.ips {
                let _ = writeln!(
                    output,
                    "  {ip}-ip:\n    type: http\n    behavior: ipcidr\n    format: {rule_format}\n    url: {}\n    path: {}\n    interval: 86400",
                    yaml_quote(&format!("{IP_RULE_BASE}{ip}.{rule_format}")),
                    yaml_quote(&format!("./ruleset/{ip}-ip.{rule_format}"))
                );
                if china_optimized {
                    output.push_str("    proxy: DIRECT\n");
                }
            }
        }
    }
    output.push_str("rules:\n");
    for rule in &custom_rules.blacklist {
        write_clash_domain_rule(&mut output, rule, "REJECT", "  - ");
    }
    for rule in &custom_rules.whitelist {
        write_clash_domain_rule(&mut output, rule, "DIRECT", "  - ");
    }
    for rule in selected_rules {
        let policy = rule_policy(rule.action);
        for site in rule.sites {
            let _ = writeln!(output, "  - RULE-SET,{site},{policy}");
        }
        for ip in rule.ips {
            let _ = writeln!(output, "  - RULE-SET,{ip}-ip,{policy},no-resolve");
        }
    }
    output.push_str("  - MATCH,PROXY\n");
    output
}

fn write_clash_domain_rule(output: &mut String, rule: &DomainRule, policy: &str, prefix: &str) {
    let (kind, domain) = match rule {
        DomainRule::Exact(domain) => ("DOMAIN", domain),
        DomainRule::Suffix(domain) => ("DOMAIN-SUFFIX", domain),
    };
    let _ = writeln!(output, "{prefix}{kind},{domain},{policy}");
}

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''").replace(['\r', '\n'], " "))
}

fn yaml_field(output: &mut String, key: &str, value: &str) {
    let _ = writeln!(output, "    {key}: {}", yaml_quote(value));
}

fn yaml_block_field(output: &mut String, key: &str, value: &str) {
    let _ = writeln!(output, "    {key}: |-");
    for line in value.replace('\r', "").lines() {
        let _ = writeln!(output, "      {line}");
    }
}

fn render_surge(
    nodes: &[Node],
    selected_rules: &[&RuleSpec],
    custom_rules: &CustomRules,
    china_optimized: bool,
) -> String {
    let mut output = String::from("[General]\nloglevel = notify\n");
    if china_optimized {
        output.push_str("dns-server = 223.5.5.5, 119.29.29.29\n");
    }
    output.push_str("\n[Proxy]\n");
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
        &proxy_node_names(nodes)
            .iter()
            .map(|name| surge_value(name))
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push_str(",DIRECT\n\n[Rule]\n");
    for rule in &custom_rules.blacklist {
        write_clash_domain_rule(&mut output, rule, "REJECT", "");
    }
    for rule in &custom_rules.whitelist {
        write_clash_domain_rule(&mut output, rule, "DIRECT", "");
    }
    for rule in selected_rules {
        let policy = rule_policy(rule.action);
        for site in rule.sites {
            let _ = writeln!(
                output,
                "RULE-SET,{SURGE_SITE_RULE_BASE}{site}.conf,{policy}"
            );
        }
        for ip in rule.ips {
            let _ = writeln!(
                output,
                "RULE-SET,{SURGE_IP_RULE_BASE}{ip}.txt,{policy},no-resolve"
            );
        }
    }
    output.push_str("FINAL,PROXY\n");
    output
}

fn proxy_node_names(nodes: &[Node]) -> Vec<String> {
    if nodes.iter().any(|node| node.kind == "ssh") {
        return nodes
            .iter()
            .filter(|node| node.kind == "ssh")
            .chain(nodes.iter().filter(|node| node.kind == "vless"))
            .chain(
                nodes
                    .iter()
                    .filter(|node| !matches!(node.kind.as_str(), "ssh" | "vless")),
            )
            .map(|node| node.name.clone())
            .collect();
    }
    let shared_tcp_fallback = nodes.len() >= 2
        && nodes.iter().any(|node| node.kind == "hysteria2")
        && nodes.iter().any(|node| node.kind == "vless")
        && nodes
            .iter()
            .all(|node| node.server == nodes[0].server && node.port == nodes[0].port);
    if !shared_tcp_fallback {
        return nodes.iter().map(|node| node.name.clone()).collect();
    }
    nodes
        .iter()
        .filter(|node| node.kind == "vless")
        .chain(nodes.iter().filter(|node| node.kind == "hysteria2"))
        .map(|node| node.name.clone())
        .collect()
}

fn rule_policy(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy => "PROXY",
        RuleAction::Direct => "DIRECT",
        RuleAction::Reject => "REJECT",
    }
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
    if user_agent.contains("clash")
        || user_agent.contains("mihomo")
        || user_agent.contains("verge")
        || user_agent.contains("stash")
        || user_agent.contains("flclash")
        || user_agent.contains("nyanpasu")
        || user_agent.contains("clashmi")
        || user_agent.contains("sparkle")
        || user_agent.contains("surfboard")
    {
        "clash"
    } else if user_agent.contains("surge") {
        "surge"
    } else if user_agent.contains("sing-box")
        || user_agent.contains("singbox")
        || user_agent.starts_with("sfa/")
        || user_agent.starts_with("sfi/")
        || user_agent.starts_with("sfm/")
    {
        "singbox"
    } else if accept.contains("yaml") || accept.contains("yml") {
        "clash"
    } else if accept.contains("json") {
        "singbox"
    } else {
        "xray"
    }
}

fn normalize_format(format: &str) -> Result<&'static str> {
    match format.trim().to_ascii_lowercase().as_str() {
        "singbox" | "sing-box" | "json" => Ok("singbox"),
        "clash" | "mihomo" | "yaml" | "yml" => Ok("clash"),
        "surge" => Ok("surge"),
        "xray" | "v2ray" | "base64" | "universal" => Ok("xray"),
        _ => bail!("unsupported output format"),
    }
}

fn supports_mrs_format(user_agent: &str) -> bool {
    let user_agent = user_agent.to_ascii_lowercase();
    if user_agent.contains("mihomo")
        || user_agent.contains("meta")
        || user_agent.contains("clash-verge")
        || user_agent.contains("verge")
        || user_agent.contains("stash")
        || user_agent.contains("flclash")
        || user_agent.contains("nyanpasu")
        || user_agent.contains("clashmi")
        || user_agent.contains("sparkle")
    {
        return true;
    }
    !user_agent.contains("merlin")
        && !user_agent.contains("clashforwindows")
        && !user_agent.contains("clashforandroid")
        && !user_agent.contains("clash/")
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

    fn ssh_node() -> String {
        let mut url = Url::parse("ssh://singbox-proxy@example.com:51400").unwrap();
        url.query_pairs_mut()
            .append_pair(
                "private-key",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nkey-data\n-----END OPENSSH PRIVATE KEY-----",
            )
            .append_pair("host-key", "ssh-ed25519 AAAAtest host");
        url.set_fragment(Some("smoke-SSH"));
        url.to_string()
    }

    #[test]
    fn clash_subscription_prefers_encrypted_ssh_and_other_formats_fall_back() {
        let service = SublinkService::default();
        let input = format!("{}\n{VLESS}", ssh_node());
        let clash = service.convert("clash", &input).unwrap().body;
        assert!(clash.contains("type: 'ssh'"));
        assert!(clash.contains("username: 'singbox-proxy'"));
        assert!(clash.contains("private-key: |-\n      -----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(clash.contains("- 'ssh-ed25519 AAAAtest host'"));
        assert!(clash.find("- 'smoke-SSH'").unwrap() < clash.find("- 'smoke'").unwrap());

        let singbox = service.convert("singbox", &input).unwrap().body;
        assert!(!singbox.contains("\"type\":\"ssh\""));
        assert!(singbox.contains("\"type\":\"vless\""));
        let universal = String::from_utf8(
            STANDARD
                .decode(service.convert("xray", &input).unwrap().body)
                .unwrap(),
        )
        .unwrap();
        assert!(!universal.contains("ssh://"));
        assert!(universal.contains("vless://"));

        let mut without_host_key = Url::parse(&ssh_node()).unwrap();
        let query = without_host_key
            .query_pairs()
            .filter(|(key, _)| key != "host-key")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        without_host_key
            .query_pairs_mut()
            .clear()
            .extend_pairs(query);
        let clash = service
            .convert("clash", without_host_key.as_str())
            .unwrap()
            .body;
        assert!(!clash.contains("host-key:"));
    }

    #[test]
    fn relay_subscription_rewrites_endpoint_and_keeps_only_tcp_nodes() {
        let hy2 = "hysteria2://password@exit.example:51400/?sni=exit.example#user";
        let rewritten = rewrite_subscription_input(
            &format!("{hy2}\n{VLESS}"),
            Some("relay.example"),
            Some(52000),
            true,
        )
        .unwrap();
        assert!(!rewritten.contains("hysteria2://"));
        assert!(rewritten.contains("@relay.example:52000"));
        assert!(rewritten.contains("security=tls"));
        assert!(rewritten.contains("#smoke"));
    }

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
    fn preserves_standard_vless_packet_encoding_for_imported_nodes() {
        let node = "vless://12345678-1234-1234-1234-123456789012@example.com:51400?encryption=none&security=tls&type=tcp&sni=example.com&packetEncoding=none#vless-native";
        let service = SublinkService::default();
        let singbox = service.convert("singbox", node).unwrap().body;
        let parsed: Value = serde_json::from_str(&singbox).unwrap();
        assert_eq!(parsed["outbounds"][0]["tag"], "vless-native");
        assert_eq!(parsed["outbounds"][0]["type"], "vless");
        assert_eq!(parsed["outbounds"][0]["packet_encoding"], "");

        let clash = service.convert("clash", node).unwrap().body;
        assert!(clash.contains("name: 'vless-native'"));
        assert!(clash.contains("udp: true"));
        assert!(clash.contains("packet-encoding: ''"));
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
            "ss://{shadowsocks}@ss.example.com:8388#ss\nvmess://{vmess}\n{VLESS}\nhysteria2://secret@hy2.example.com:443#hy2\ntuic://12345678-1234-1234-1234-123456789012:secret@tuic.example.com:443#tuic"
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
            .take(5)
            .map(|outbound| outbound["type"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            ["shadowsocks", "vmess", "vless", "hysteria2", "tuic"]
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
    async fn permanent_identity_keeps_code_for_vless_only_subscription() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hy2-vless-links.toml");
        let hy2 = "hysteria2://password@example.com:443/?sni=example.com#user";
        let vless = "vless://2bb80d53-7b1d-43e3-8bd3-0361aa855686@example.com:443?encryption=none&security=tls&sni=example.com&type=tcp#user-VLESS";
        let service = SublinkService::with_persistence(path).unwrap();
        let hy2_url = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(hy2.as_bytes()).collect::<String>()
        );
        let code = service.shorten_hy2(&hy2_url).await.unwrap();
        let vless_url = format!(
            "https://example.com/xray?config={}&identity={}",
            url::form_urlencoded::byte_serialize(vless.as_bytes()).collect::<String>(),
            url::form_urlencoded::byte_serialize(hy2.as_bytes()).collect::<String>()
        );
        assert_eq!(service.shorten_hy2(&vless_url).await.unwrap(), code);

        let output = service.auto(&code, "sing-box/1.14", "").await.unwrap();
        assert_eq!(output.profile_name, "user");
        assert!(!output.body.contains("\"type\":\"hysteria2\""));
        assert!(output.body.contains("\"type\":\"vless\""));
        let document: Value = serde_json::from_str(&output.body).unwrap();
        let selector = document["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "PROXY")
            .unwrap();
        assert_eq!(selector["outbounds"], json!(["user-VLESS"]));

        let clash = service
            .auto(&code, "clash-verge/v2.4", "")
            .await
            .unwrap()
            .body;
        assert!(clash.contains("type: 'vless'"));
        assert!(!clash.contains("type: 'hysteria2'"));
        assert!(clash.contains("    udp: false"));
        assert!(clash.contains("servername: 'example.com'"));
    }

    #[tokio::test]
    async fn permanent_hy2_links_retain_and_update_rule_selection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hy2-rule-links.toml");
        let config = "hysteria2://password@example.com:443/?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret#user";
        let encoded = url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>();
        let minimal =
            format!("https://example.com/xray?config={encoded}&selectedRules=minimal&adblock=true");
        let first = SublinkService::with_persistence(path.clone()).unwrap();
        let code = first.shorten_hy2(&minimal).await.unwrap();
        let clash = first
            .auto(&code, "clash-verge/v2.4", "")
            .await
            .unwrap()
            .body;
        assert!(clash.contains("category-ads-all.mrs"));
        assert!(clash.contains("geolocation-!cn.mrs"));
        assert!(!clash.contains("youtube.mrs"));

        let comprehensive =
            format!("https://example.com/xray?config={encoded}&selectedRules=comprehensive");
        assert_eq!(first.shorten_hy2(&comprehensive).await.unwrap(), code);
        drop(first);

        let second = SublinkService::with_persistence(path).unwrap();
        let singbox = second.auto(&code, "sing-box/1.14", "").await.unwrap().body;
        assert!(singbox.contains("category-ads-all.srs"));
        assert!(singbox.contains("youtube.srs"));
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
        for user_agent in [
            "Clash Meta",
            "Clash Verge Rev",
            "ClashMetaForAndroid/2.11.28",
            "mihomo/1.19.12",
            "Surfboard/2.24",
        ] {
            let output = service.auto(&code, user_agent, "").await.unwrap();
            assert_eq!(output.profile_name, "user");
            assert_eq!(output.file_extension, "yaml");
            let body = output.body;
            assert!(body.contains("proxies:"));
            assert!(body.contains("log-level: warning"));
            assert!(body.contains("type: 'hysteria2'"));
            assert!(body.contains("sni: 'example.com'"));
            assert!(body.contains("alpn:\n      - h3"));
            assert!(body.contains("obfs: 'salamander'"));
            assert!(!body.contains("tls: true"));
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
    async fn adaptive_links_allow_explicit_format_aliases() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com#poetry";
        let raw = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>()
        );
        let code = service.shorten_hy2(&raw).await.unwrap();

        let clash = service
            .auto_with_format(&code, "unknown", "*/*", Some("mihomo"))
            .await
            .unwrap();
        assert_eq!(clash.profile_name, "poetry");
        assert_eq!(clash.file_extension, "yaml");
        assert!(clash.body.contains("proxies:"));

        let singbox = service
            .auto_with_format(&code, "unknown", "*/*", Some("sing-box"))
            .await
            .unwrap();
        assert_eq!(singbox.file_extension, "json");
        assert!(singbox.body.contains("\"outbounds\""));

        let universal = service
            .auto_with_format(&code, "unknown", "*/*", Some("universal"))
            .await
            .unwrap();
        assert_eq!(STANDARD.decode(universal.body).unwrap(), config.as_bytes());
        assert!(
            service
                .auto_with_format(&code, "unknown", "*/*", Some("unsupported"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn adaptive_links_cover_common_client_families() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret#user";
        let raw = format!(
            "https://example.com/xray?config={}&selectedRules=comprehensive",
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>()
        );
        let code = service.shorten_hy2(&raw).await.unwrap();

        for user_agent in [
            "mihomo/1.19",
            "clash-verge/v2.5",
            "ClashMetaForAndroid/2.11",
            "FlClash/0.8",
            "Clash.Nyanpasu/2.0",
            "Mihomo Party/1.8",
            "ClashMi/1.0",
            "Stash/2.6",
        ] {
            let body = service.auto(&code, user_agent, "").await.unwrap().body;
            assert!(body.contains("type: 'hysteria2'"), "{user_agent}");
            assert!(body.contains("format: mrs"), "{user_agent}");
        }

        for user_agent in [
            "Clash/1.0",
            "ClashForAndroid/2.5.12",
            "ClashForWindows/0.20.0",
            "Merlin Clash",
        ] {
            let body = service.auto(&code, user_agent, "").await.unwrap().body;
            assert!(body.contains("format: yaml"), "{user_agent}");
            assert!(!body.contains("format: mrs"), "{user_agent}");
        }

        for user_agent in [
            "sing-box/1.14",
            "SFA/1.14.0 (sing-box 1.14.0)",
            "SFI/1.14.0",
            "SFM/1.14.0",
        ] {
            let body = service.auto(&code, user_agent, "").await.unwrap().body;
            assert!(body.contains("\"outbounds\""), "{user_agent}");
            assert!(body.contains("category-ads-all.srs"), "{user_agent}");
        }

        let surge = service.auto(&code, "Surge/5.8", "").await.unwrap().body;
        assert!(surge.starts_with("[General]"));
        for user_agent in [
            "v2rayN/7.0",
            "v2rayNG/1.9",
            "Shadowrocket/2.2",
            "Quantumult%20X/1.5",
            "Loon/3.2",
            "NekoBox/1.3",
            "Hiddify/2.5",
            "Karing/1.2",
            "Streisand/1.6",
        ] {
            let universal = service.auto(&code, user_agent, "").await.unwrap();
            assert_eq!(universal.file_extension, "txt", "{user_agent}");
            assert_eq!(
                STANDARD.decode(universal.body).unwrap(),
                config.as_bytes(),
                "{user_agent}"
            );
        }
    }

    #[tokio::test]
    async fn clash_converter_and_adaptive_link_share_hy2_output() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfs-secret#user";
        let raw = format!(
            "https://example.com/xray?config={}",
            url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>()
        );
        let code = service.shorten_auto(&raw).await.unwrap();
        let direct = service.convert("clash", config).unwrap();
        let adaptive = service
            .auto(&code, "ClashMetaForAndroid/2.11.28", "")
            .await
            .unwrap();

        assert_eq!(adaptive.content_type, direct.content_type);
        assert_eq!(adaptive.body, direct.body);
    }

    #[test]
    fn original_rule_presets_generate_client_rule_sets() {
        let service = SublinkService::default();
        let minimal = service
            .convert_with_rules("clash", VLESS, Some("minimal"), true)
            .unwrap()
            .body;
        assert!(minimal.contains("category-ads-all.mrs"));
        assert!(minimal.contains("RULE-SET,category-ads-all,REJECT"));
        assert!(minimal.contains("RULE-SET,cn-ip,DIRECT,no-resolve"));
        assert!(!minimal.contains("youtube.mrs"));

        let balanced = service
            .convert_with_rules("singbox", VLESS, Some("balanced"), false)
            .unwrap()
            .body;
        assert!(balanced.contains("youtube.srs"));
        assert!(balanced.contains("geolocation-!cn.srs"));
        assert!(!balanced.contains("category-ads-all.srs"));

        let comprehensive = service
            .convert_with_rules("surge", VLESS, Some("comprehensive"), false)
            .unwrap()
            .body;
        assert!(comprehensive.contains("category-ads-all.conf,REJECT"));
        assert!(comprehensive.contains("netflix.conf,PROXY"));
    }

    #[test]
    fn china_preset_orders_mainland_routes_and_split_dns() {
        let service = SublinkService::default();
        let clash = service
            .convert_with_rules("clash", VLESS, Some("china"), true)
            .unwrap()
            .body;
        assert!(clash.contains("enhanced-mode: fake-ip"));
        assert!(clash.contains("https://1.1.1.1/dns-query#PROXY"));
        assert!(clash.contains("    proxy: DIRECT"));
        assert!(clash.contains("RULE-SET,category-ads-all,REJECT"));
        assert!(clash.contains("RULE-SET,private,DIRECT"));
        assert!(clash.contains("RULE-SET,apple-cn,DIRECT"));
        assert!(clash.contains("RULE-SET,microsoft@cn,DIRECT"));
        assert!(clash.contains("RULE-SET,steam@cn,DIRECT"));
        assert!(clash.contains("RULE-SET,category-games@cn,DIRECT"));
        assert!(clash.contains("RULE-SET,bilibili,DIRECT"));
        assert!(!clash.contains("RULE-SET,apple,PROXY"));
        assert!(!clash.contains("RULE-SET,microsoft,PROXY"));
        assert!(
            clash.find("RULE-SET,bilibili,DIRECT").unwrap()
                < clash.find("RULE-SET,google,PROXY").unwrap()
        );
        assert!(
            clash.find("RULE-SET,google,PROXY").unwrap()
                < clash.find("RULE-SET,cn,DIRECT").unwrap()
        );
        assert!(
            clash.find("RULE-SET,cn,DIRECT").unwrap()
                < clash.find("RULE-SET,geolocation-!cn,PROXY").unwrap()
        );

        let legacy = service
            .convert_with_rule_format("clash", VLESS, Some("china"), true, None, None, false)
            .unwrap()
            .body;
        assert!(legacy.contains("format: yaml"));
        assert!(!legacy.contains("enhanced-mode: fake-ip"));

        let singbox = service
            .convert_with_rules("singbox", VLESS, Some("china"), true)
            .unwrap()
            .body;
        let singbox: Value = serde_json::from_str(&singbox).unwrap();
        assert_eq!(singbox["dns"]["final"], "dns-global");
        assert!(singbox["dns"]["servers"][1].get("detour").is_none());
        assert!(singbox["dns"]["servers"][2].get("detour").is_none());
        assert_eq!(singbox["dns"]["servers"][3]["detour"], "PROXY");
        assert!(singbox.to_string().contains("dns-cn-ali"));
        assert!(singbox.to_string().contains("dns-cn-tencent"));

        let surge = service
            .convert_with_rules("surge", VLESS, Some("china"), true)
            .unwrap()
            .body;
        assert!(surge.contains("dns-server = 223.5.5.5, 119.29.29.29"));
        assert!(surge.contains("apple-cn.conf,DIRECT"));
    }

    #[tokio::test]
    async fn permanent_hy2_code_stays_stable_when_switching_to_china_rules() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com#user";
        let encoded = url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>();
        let balanced = format!(
            "https://example.com/xray?config={encoded}&selectedRules=balanced&adblock=true"
        );
        let china =
            format!("https://example.com/xray?config={encoded}&selectedRules=china&adblock=true");
        let code = service.shorten_hy2(&balanced).await.unwrap();
        assert_eq!(service.shorten_hy2(&china).await.unwrap(), code);
        let output = service.auto(&code, "clash-verge/v2.5", "").await.unwrap();
        assert!(output.body.contains("RULE-SET,apple-cn,DIRECT"));
        assert!(output.body.contains("enhanced-mode: fake-ip"));
    }

    #[test]
    fn custom_domain_lists_render_with_blacklist_priority() {
        let service = SublinkService::default();
        let whitelist = "direct.example\n*.shared.example";
        let blacklist = "blocked.example\n.shared.example";
        let clash = service
            .convert_with_custom_rules(
                "clash",
                VLESS,
                Some("china"),
                false,
                Some(whitelist),
                Some(blacklist),
            )
            .unwrap()
            .body;
        assert!(clash.contains("DOMAIN,direct.example,DIRECT"));
        assert!(clash.contains("DOMAIN,blocked.example,REJECT"));
        assert!(clash.contains("DOMAIN-SUFFIX,shared.example,REJECT"));
        assert!(clash.contains("DOMAIN-SUFFIX,shared.example,DIRECT"));
        assert!(
            clash.find("DOMAIN-SUFFIX,shared.example,REJECT").unwrap()
                < clash.find("DOMAIN-SUFFIX,shared.example,DIRECT").unwrap()
        );
        assert!(clash.contains("DOMAIN,direct.example,real-ip"));

        let singbox = service
            .convert_with_custom_rules(
                "singbox",
                VLESS,
                Some("china"),
                false,
                Some(whitelist),
                Some(blacklist),
            )
            .unwrap()
            .body;
        let singbox: Value = serde_json::from_str(&singbox).unwrap();
        assert_eq!(singbox["route"]["rules"][0]["action"], "reject");
        assert_eq!(singbox["route"]["rules"][1]["outbound"], "DIRECT");
        assert_eq!(singbox["dns"]["rules"][0]["action"], "reject");
        assert_eq!(singbox["dns"]["rules"][1]["server"], "dns-cn-ali");

        let surge = service
            .convert_with_custom_rules(
                "surge",
                VLESS,
                Some("china"),
                false,
                Some(whitelist),
                Some(blacklist),
            )
            .unwrap()
            .body;
        assert!(surge.contains("DOMAIN,blocked.example,REJECT"));
        assert!(surge.contains("DOMAIN,direct.example,DIRECT"));
    }

    #[test]
    fn custom_domain_lists_validate_and_deduplicate() {
        let rules =
            parse_domain_rules("Example.COM\nexample.com\n*.Example.NET", "whitelist").unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], DomainRule::Exact("example.com".to_owned()));
        assert_eq!(rules[1], DomainRule::Suffix("example.net".to_owned()));
        assert!(parse_domain_rules("https://example.com", "blacklist").is_err());
        assert!(parse_domain_rules("192.0.2.1", "blacklist").is_err());
    }

    #[tokio::test]
    async fn permanent_short_links_keep_custom_lists_without_changing_code() {
        let service = SublinkService::default();
        let config = "hysteria2://password@example.com:443/?sni=example.com#user";
        let encoded = url::form_urlencoded::byte_serialize(config.as_bytes()).collect::<String>();
        let plain = format!("https://example.com/xray?config={encoded}&selectedRules=china");
        let custom = format!("{plain}&whitelist=direct.example&blacklist=blocked.example");
        let code = service.shorten_hy2(&plain).await.unwrap();
        assert_eq!(service.shorten_hy2(&custom).await.unwrap(), code);
        let output = service.auto(&code, "clash-verge/v2.5", "").await.unwrap();
        assert!(output.body.contains("DOMAIN,direct.example,DIRECT"));
        assert!(output.body.contains("DOMAIN,blocked.example,REJECT"));
    }

    #[tokio::test]
    async fn adaptive_links_preserve_rule_preset_and_ad_block() {
        let service = SublinkService::default();
        let raw = format!(
            "https://example.com/xray?config={}&selectedRules=minimal&adblock=true",
            url::form_urlencoded::byte_serialize(VLESS.as_bytes()).collect::<String>()
        );
        let code = service.shorten_auto(&raw).await.unwrap();
        let body = service.auto(&code, "mihomo/1.19", "").await.unwrap().body;
        assert!(body.contains("category-ads-all.mrs"));
        assert!(body.contains("geolocation-!cn.mrs"));
        assert!(!body.contains("youtube.mrs"));
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

    #[tokio::test]
    async fn automatic_converter_links_survive_service_reload_until_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("converter-links.toml");
        let raw = format!(
            "https://example.com/xray?config={}&selectedRules=balanced&adblock=true",
            url::form_urlencoded::byte_serialize(VLESS.as_bytes()).collect::<String>()
        );
        let first = SublinkService::with_persistence(path.clone()).unwrap();
        let code = first.shorten_auto(&raw).await.unwrap();
        drop(first);

        let second = SublinkService::with_persistence(path.clone()).unwrap();
        let output = second.auto(&code, "clash-verge/v2.5", "").await.unwrap();
        assert!(output.body.contains("category-ads-all.mrs"));
        assert!(output.body.contains("youtube.mrs"));
        assert!(
            fs::read_to_string(path)
                .unwrap()
                .contains("expires_at_unix")
        );
    }
}
