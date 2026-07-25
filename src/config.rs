use std::{collections::HashMap, fs, net::SocketAddr, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    pub users: Vec<User>,
    #[serde(default)]
    pub bandwidth: Bandwidth,
    #[serde(default)]
    pub udp: UdpConfig,
    pub obfs: Option<ObfsConfig>,
    pub masquerade: Option<MasqueradeConfig>,
    pub share: Option<ShareConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate: String,
    pub private_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bandwidth {
    #[serde(default)]
    pub up_mbps: u64,
    #[serde(default)]
    pub down_mbps: u64,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default = "default_udp_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv6_server: String,
    pub port: u16,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default = "default_share_rule_preset")]
    pub rule_preset: String,
    #[serde(default)]
    pub ad_block: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub whitelist: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blacklist: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MasqueradeConfig {
    File {
        directory: String,
    },
    Proxy {
        url: String,
        #[serde(default)]
        rewrite_host: bool,
    },
    String {
        #[serde(default = "default_masquerade_status")]
        status_code: u16,
        #[serde(default)]
        headers: HashMap<String, Vec<String>>,
        #[serde(default)]
        content: String,
    },
}

const fn enabled() -> bool {
    true
}

const fn default_udp_timeout_secs() -> u64 {
    300
}

const fn default_masquerade_status() -> u16 {
    200
}

fn default_share_rule_preset() -> String {
    "balanced".to_owned()
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: default_udp_timeout_secs(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        Self::from_toml(&contents)
    }

    pub fn from_toml(contents: &str) -> Result<Self> {
        let config: Self = toml::from_str(contents).context("parse TOML configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        toml::to_string_pretty(self).context("serialize TOML configuration")
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let contents = self.to_toml()?;
        let temporary = path.with_extension("toml.tmp");
        fs::write(&temporary, contents)
            .with_context(|| format!("write temporary configuration {}", temporary.display()))?;
        if let Ok(metadata) = fs::metadata(path) {
            fs::set_permissions(&temporary, metadata.permissions()).with_context(|| {
                format!("preserve configuration permissions for {}", path.display())
            })?;
        }
        fs::rename(&temporary, path)
            .with_context(|| format!("replace configuration {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.users.is_empty(), "at least one HY2 user is required");
        ensure!(
            self.users.iter().all(|user| !user.password.is_empty()),
            "HY2 user passwords must not be empty"
        );
        ensure!(
            self.users.iter().all(|user| !user.name.trim().is_empty()),
            "HY2 user names must not be empty"
        );
        ensure!(
            !self.tls.certificate.trim().is_empty(),
            "TLS certificate path is required"
        );
        ensure!(
            !self.tls.private_key.trim().is_empty(),
            "TLS private key path is required"
        );
        ensure!(
            self.udp.timeout_secs > 0,
            "UDP timeout must be greater than zero"
        );
        if let Some(obfs) = &self.obfs {
            ensure!(obfs.kind == "salamander", "unsupported obfuscation type");
            ensure!(
                !obfs.password.is_empty(),
                "Salamander password must not be empty"
            );
        }
        if let Some(masquerade) = &self.masquerade {
            match masquerade {
                MasqueradeConfig::File { directory } => {
                    ensure!(
                        !directory.trim().is_empty(),
                        "masquerade directory is required"
                    );
                }
                MasqueradeConfig::Proxy { url, .. } => {
                    let url = reqwest::Url::parse(url).context("parse masquerade proxy URL")?;
                    ensure!(
                        matches!(url.scheme(), "http" | "https"),
                        "masquerade proxy URL must use http or https"
                    );
                }
                MasqueradeConfig::String {
                    status_code,
                    headers,
                    ..
                } => {
                    http::StatusCode::from_u16(*status_code)
                        .context("invalid masquerade status code")?;
                    for (name, values) in headers {
                        http::HeaderName::from_bytes(name.as_bytes())
                            .with_context(|| format!("invalid masquerade header name {name}"))?;
                        for value in values {
                            http::HeaderValue::from_str(value).with_context(|| {
                                format!("invalid value for masquerade header {name}")
                            })?;
                        }
                    }
                }
            }
        }
        if let Some(share) = &self.share {
            ensure!(
                !share.server.trim().is_empty() || !share.ipv6_server.trim().is_empty(),
                "at least one share server address is required"
            );
            ensure!(
                share.port > 0,
                "share server port must be greater than zero"
            );
            ensure!(
                matches!(
                    share.rule_preset.as_str(),
                    "minimal" | "balanced" | "comprehensive" | "china"
                ),
                "share rule preset must be minimal, balanced, comprehensive, or china"
            );
            crate::sublink::validate_custom_rule_values(&share.whitelist, "whitelist")?;
            crate::sublink::validate_custom_rule_values(&share.blacklist, "blacklist")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config::from_toml(include_str!("../integration/server.toml")).unwrap()
    }

    #[test]
    fn share_config_accepts_legacy_ipv4_only_files() {
        assert_eq!(
            base_config().share.unwrap().rule_preset,
            "balanced",
            "legacy share configs should receive the upstream default preset"
        );
        let mut config = base_config();
        config.share = Some(ShareConfig {
            server: "198.51.100.10".to_owned(),
            ipv6_server: String::new(),
            port: 443,
            sni: "example.com".to_owned(),
            insecure: false,
            rule_preset: "balanced".to_owned(),
            ad_block: false,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        });
        let encoded = config.to_toml().unwrap();
        assert!(encoded.contains("server = \"198.51.100.10\""));
        assert!(!encoded.contains("ipv6_server"));
        assert_eq!(
            Config::from_toml(&encoded)
                .unwrap()
                .share
                .unwrap()
                .ipv6_server,
            ""
        );
    }

    #[test]
    fn share_config_allows_an_ipv6_only_endpoint() {
        let mut config = base_config();
        config.share = Some(ShareConfig {
            server: String::new(),
            ipv6_server: "2001:db8::10".to_owned(),
            port: 443,
            sni: "example.com".to_owned(),
            insecure: false,
            rule_preset: "balanced".to_owned(),
            ad_block: false,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        });
        assert!(config.validate().is_ok());
        assert!(config.to_toml().unwrap().contains("2001:db8::10"));
    }

    #[test]
    fn share_config_accepts_china_rule_preset() {
        let mut config = base_config();
        let share = config.share.as_mut().unwrap();
        share.rule_preset = "china".to_owned();
        share.ad_block = true;
        assert!(config.validate().is_ok());
        let encoded = config.to_toml().unwrap();
        assert!(encoded.contains("rule_preset = \"china\""));
    }

    #[test]
    fn share_config_validates_custom_domain_lists() {
        let mut config = base_config();
        config.share.as_mut().unwrap().whitelist =
            vec!["example.cn".to_owned(), "*.internal.example.cn".to_owned()];
        config.share.as_mut().unwrap().blacklist = vec!["ads.example.com".to_owned()];
        assert!(config.validate().is_ok());

        config.share.as_mut().unwrap().blacklist = vec!["https://example.com/path".to_owned()];
        assert!(config.validate().is_err());
    }
}
