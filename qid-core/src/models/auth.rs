use serde::{Deserialize, Serialize};

/// A password credential record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCredential {
    pub user_id: String,
    pub hash: String,
    pub algorithm: String,
    pub pepper_ref: Option<String>,
}

/// An OAuth/OIDC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub realm_id: String,
    pub client_id: String,
    pub client_type: ClientType,
    #[serde(default = "default_token_endpoint_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub client_secret_hash: Option<String>,
    #[serde(default)]
    pub mtls_certificate_thumbprints: Vec<String>,
    #[serde(default = "default_client_jwks")]
    pub jwks: serde_json::Value,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub contacts: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub default_max_age: Option<u64>,
    #[serde(default)]
    pub require_auth_time: bool,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    /// OpenID Connect CIBA backchannel client notification endpoint.
    /// Required for CIBA Ping mode. The AS sends an HTTP POST
    /// to this URI when the end-user has authenticated.
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Confidential,
    Public,
}

pub fn default_token_endpoint_auth_method() -> String {
    "client_secret_basic".to_string()
}

pub fn default_client_jwks() -> serde_json::Value {
    serde_json::json!({ "keys": [] })
}
