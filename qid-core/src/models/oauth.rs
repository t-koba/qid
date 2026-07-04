use serde::{Deserialize, Serialize};

/// A browser/session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub realm_id: String,
    pub user_id: String,
    pub auth_time: u64,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub idle_expires_at: u64,
    pub absolute_expires_at: u64,
    pub revoked: bool,
    pub created_at: u64,
    #[serde(default)]
    pub cnf: Option<serde_json::Value>,
}

/// An authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub realm_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
    pub expires_at: u64,
    pub used: bool,
    pub created_at: u64,
}

/// A refresh token family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenFamily {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub realm_id: String,
    pub current_refresh_hash: String,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
    #[serde(default)]
    pub sender_constraint: Option<serde_json::Value>,
    pub issued_at: u64,
    pub revoked: bool,
}

/// An access token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub jti: String,
    pub family_id: Option<String>,
    pub user_id: String,
    pub client_id: String,
    pub realm_id: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub resource: Vec<String>,
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
    #[serde(default)]
    pub cnf: Option<serde_json::Value>,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub sender_constraint: Option<serde_json::Value>,
    #[serde(default)]
    pub token_format: TokenFormat,
    pub expires_at: u64,
    pub revoked: bool,
    pub issued_at: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenFormat {
    #[default]
    Jwt,
    Opaque,
}

/// A WebAuthn credential record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u64,
    pub aaguid: Vec<u8>,
    pub device_name: Option<String>,
    pub created_at: u64,
}

/// Persistent verifiable credential status record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcCredentialStatusRecord {
    pub credential_id: String,
    pub realm_id: String,
    pub subject: String,
    pub issuer: String,
    pub status_list_uri: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    #[serde(default)]
    pub revocation_reason: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

/// A service account for client_credentials grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: String,
    pub client_id: String,
    pub realm_id: String,
    pub description: Option<String>,
    pub created_at: u64,
}

/// A TOTP credential for MFA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCredential {
    pub id: String,
    pub user_id: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub enabled: bool,
    pub last_used_step: Option<u64>,
    pub created_at: u64,
}

/// A known device posture signal.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostureSignal {
    DiskEncrypted,
    ScreenLock,
    OsUpdated,
    AntivirusEnabled,
    FirewallEnabled,
    MfaEnabled,
    DebuggerDisabled,
    DeveloperModeDisabled,
    JailbreakDetected,
    #[serde(other)]
    Unknown,
}

#[allow(dead_code)]
impl PostureSignal {
    pub fn from_strings(values: &[String]) -> Vec<Self> {
        values.iter().map(|v| Self::from_str(v)).collect()
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "disk_encrypted" => Self::DiskEncrypted,
            "screen_lock" => Self::ScreenLock,
            "os_updated" => Self::OsUpdated,
            "antivirus_enabled" => Self::AntivirusEnabled,
            "firewall_enabled" => Self::FirewallEnabled,
            "mfa_enabled" => Self::MfaEnabled,
            "debugger_disabled" => Self::DebuggerDisabled,
            "developer_mode_disabled" => Self::DeveloperModeDisabled,
            "jailbreak_detected" => Self::JailbreakDetected,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DiskEncrypted => "disk_encrypted",
            Self::ScreenLock => "screen_lock",
            Self::OsUpdated => "os_updated",
            Self::AntivirusEnabled => "antivirus_enabled",
            Self::FirewallEnabled => "firewall_enabled",
            Self::MfaEnabled => "mfa_enabled",
            Self::DebuggerDisabled => "debugger_disabled",
            Self::DeveloperModeDisabled => "developer_mode_disabled",
            Self::JailbreakDetected => "jailbreak_detected",
            Self::Unknown => "unknown",
        }
    }

    pub fn to_strings(values: &[Self]) -> Vec<String> {
        values.iter().map(|s| s.as_str().to_string()).collect()
    }
}

/// A registered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub user_id: String,
    pub realm_id: String,
    pub device_name: Option<String>,
    pub device_type: String,
    pub posture: Vec<String>,
    pub registered_at: u64,
    pub last_seen_at: u64,
}

/// A Pushed Authorization Request (RFC 9126).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParRequest {
    pub request_uri: String,
    pub client_id: String,
    pub realm_id: String,
    pub params_json: serde_json::Value,
    pub expires_at: u64,
    pub used: bool,
    pub created_at: u64,
}

/// An OAuth 2.0 Device Authorization Grant record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationGrant {
    pub device_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub realm_id: String,
    pub scopes: Vec<String>,
    pub user_id: Option<String>,
    pub expires_at: u64,
    pub approved_at: Option<u64>,
    pub consumed: bool,
    #[serde(default)]
    pub last_poll_at: Option<u64>,
    #[serde(default = "default_device_poll_interval_seconds")]
    pub poll_interval_seconds: u64,
    pub created_at: u64,
}

pub fn default_device_poll_interval_seconds() -> u64 {
    5
}

/// An OpenID Connect CIBA backchannel authentication grant record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackchannelAuthenticationGrant {
    pub auth_req_id_hash: String,
    pub client_id: String,
    pub realm_id: String,
    pub login_hint: String,
    pub binding_message: Option<String>,
    pub scopes: Vec<String>,
    pub user_id: Option<String>,
    pub expires_at: u64,
    pub approved_at: Option<u64>,
    pub consumed: bool,
    #[serde(default)]
    pub last_poll_at: Option<u64>,
    #[serde(default = "default_device_poll_interval_seconds")]
    pub poll_interval_seconds: u64,
    pub created_at: u64,
}
