//! CAPPORT (RFC 8908/8910) captive portal API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapportApi {
    pub venue_info_url: Option<String>,
    pub user_portal_url: Option<String>,
    pub can_extend_session: bool,
    pub seconds_remaining: Option<u32>,
    pub bytes_remaining: Option<u64>,
}

impl CapportApi {
    pub fn new() -> Self {
        Self {
            venue_info_url: None,
            user_portal_url: None,
            can_extend_session: true,
            seconds_remaining: None,
            bytes_remaining: None,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

impl Default for CapportApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capport_api_serializes() {
        let api = CapportApi::new();
        let json = api.to_json();
        assert!(json.get("can_extend_session").is_some());
    }
}
