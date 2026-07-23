use std::collections::BTreeMap;

pub const STATUS_AUTH_OK: u16 = 233;
pub const REQUEST_HEADER_AUTH: &str = "Hysteria-Auth";
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
pub const HEADER_CC_RX: &str = "Hysteria-CC-RX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub password: String,
    pub receive_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    pub receive_bps: Option<u64>,
}

impl AuthRequest {
    pub fn from_headers(headers: &BTreeMap<String, String>) -> Self {
        Self {
            password: headers
                .get(REQUEST_HEADER_AUTH)
                .cloned()
                .unwrap_or_default(),
            receive_bps: headers
                .get(HEADER_CC_RX)
                .and_then(|value| value.parse().ok())
                .unwrap_or_default(),
        }
    }
}

impl AuthResponse {
    pub fn headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert(
            RESPONSE_HEADER_UDP_ENABLED.into(),
            self.udp_enabled.to_string(),
        );
        headers.insert(
            HEADER_CC_RX.into(),
            self.receive_bps
                .map_or_else(|| "auto".into(), |value| value.to_string()),
        );
        headers
    }
}
