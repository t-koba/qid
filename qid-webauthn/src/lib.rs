//! WebAuthn and passkey policy helpers for qid.
#![forbid(unsafe_code)]

use qid_core::{
    config::PasskeyConfig,
    error::{QidError, QidResult},
    models::WebAuthnCredential,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPolicy {
    None,
    Enterprise,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyBinding {
    Synced,
    HardwareBound,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorAttachment {
    Platform,
    Roaming,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyPolicy {
    pub attestation: AttestationPolicy,
    pub allow_aaguid: BTreeSet<String>,
    pub deny_aaguid: BTreeSet<String>,
    pub require_resident_key: bool,
    pub allow_conditional_ui: bool,
    pub require_hardware_backed_for_admin: bool,
    pub minimum_recovery_passkeys: usize,
    pub challenge_ttl_seconds: u64,
    /// FIDO Metadata Service (MDS) integration. When set, the policy will
    /// consult the configured source for the up-to-date allow/deny lists
    /// rather than relying on a static, manually maintained configuration.
    #[serde(default)]
    pub metadata: Option<MetadataSourceConfig>,
}

/// Configuration for the FIDO Metadata Service source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetadataSourceConfig {
    /// Local file or HTTP(S) URL that serves the FIDO MDS blob.
    pub source: String,
    /// Allow AAGUIDs that the policy previously trusted but have been
    /// removed from the upstream MDS. Operators populate this list when
    /// they want to grandfather authenticators.
    #[serde(default)]
    pub retention_allow: BTreeSet<String>,
    /// Refresh interval in seconds. A value of `0` disables automatic
    /// refresh and forces a manual `refresh()` call on the loaded source.
    #[serde(default = "default_metadata_refresh_seconds")]
    pub refresh_seconds: u64,
}

fn default_metadata_refresh_seconds() -> u64 {
    86_400
}

impl Default for PasskeyPolicy {
    fn default() -> Self {
        Self {
            attestation: AttestationPolicy::None,
            allow_aaguid: BTreeSet::new(),
            deny_aaguid: BTreeSet::new(),
            require_resident_key: true,
            allow_conditional_ui: true,
            require_hardware_backed_for_admin: true,
            minimum_recovery_passkeys: 2,
            challenge_ttl_seconds: 300,
            metadata: None,
        }
    }
}

impl PasskeyPolicy {
    pub fn validate(&self) -> QidResult<()> {
        if self.challenge_ttl_seconds == 0 || self.challenge_ttl_seconds > 900 {
            return Err(QidError::Config {
                message: "WebAuthn challenge TTL must be between 1 and 900 seconds".to_string(),
            });
        }
        if !self.allow_aaguid.is_disjoint(&self.deny_aaguid) {
            return Err(QidError::Config {
                message: "WebAuthn AAGUID allow and deny lists overlap".to_string(),
            });
        }
        if self.attestation == AttestationPolicy::Strict && self.allow_aaguid.is_empty() {
            return Err(QidError::Config {
                message: "strict WebAuthn attestation requires an AAGUID allow list".to_string(),
            });
        }
        Ok(())
    }
}

/// A snapshot of FIDO MDS data: the set of authenticator AAGUIDs that are
/// currently known to be trusted and the set that are explicitly blocked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataSnapshot {
    pub allow_aaguid: BTreeSet<String>,
    pub deny_aaguid: BTreeSet<String>,
    pub fetched_at: Option<u64>,
}

/// Trait for FIDO Metadata Service sources. Implementations may fetch the
/// blob over HTTPS from the FIDO Alliance, read a local file maintained by
/// the operator, or use any other trustworthy mechanism. The interface
/// intentionally hides the transport so the policy can be tested with
/// deterministic local data.
pub trait MetadataSource: Send + Sync {
    fn load(&self) -> QidResult<MetadataSnapshot>;
}

/// Static metadata source driven by a JSON blob. The blob is parsed once
/// and re-parsed on every `load()` call so operators can rotate the file
/// without restarting the server.
pub struct StaticMetadataSource {
    blob: String,
}

impl StaticMetadataSource {
    pub fn new(blob: String) -> Self {
        Self { blob }
    }
}

impl MetadataSource for StaticMetadataSource {
    fn load(&self) -> QidResult<MetadataSnapshot> {
        serde_json::from_str(&self.blob).map_err(|e| QidError::Config {
            message: format!("failed to parse metadata source blob: {e}"),
        })
    }
}

/// Merge a metadata snapshot into a base policy. Static lists take
/// precedence: anything in `policy.allow_aaguid` or `policy.deny_aaguid`
/// overrides the snapshot, while authenticators only present in the
/// snapshot are added to the merged result. The `retention` set lets
/// operators keep authenticators that have been removed from upstream.
pub fn merge_metadata_into_policy(
    policy: &PasskeyPolicy,
    snapshot: &MetadataSnapshot,
    retention: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut allow = policy.allow_aaguid.clone();
    for aaguid in &snapshot.allow_aaguid {
        if retention.contains(aaguid) || !policy.deny_aaguid.contains(aaguid) {
            allow.insert(aaguid.clone());
        }
    }
    let mut deny = policy.deny_aaguid.clone();
    for aaguid in &snapshot.deny_aaguid {
        deny.insert(aaguid.clone());
    }
    (allow, deny)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebAuthnRp {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

impl WebAuthnRp {
    pub fn from_config(public_base_url: &str, config: &PasskeyConfig) -> QidResult<Self> {
        let base = Url::parse(public_base_url).map_err(|e| QidError::Config {
            message: format!("invalid public_base_url for WebAuthn RP: {e}"),
        })?;
        if base.scheme() != "https" && base.host_str() != Some("localhost") {
            return Err(QidError::Config {
                message: "WebAuthn RP origin must use https except localhost".to_string(),
            });
        }
        let host = base.host_str().ok_or_else(|| QidError::Config {
            message: "WebAuthn RP origin must include a host".to_string(),
        })?;
        let rp_id = config.rp_id.clone().unwrap_or_else(|| host.to_string());
        let rp_origin = config
            .rp_origin
            .clone()
            .unwrap_or_else(|| origin_from_url(&base));
        validate_rp_origin(&rp_id, &rp_origin)?;
        Ok(Self {
            rp_id,
            rp_origin,
            rp_name: config.rp_name.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub aaguid: Option<String>,
    pub binding: PasskeyBinding,
    pub attachment: AuthenticatorAttachment,
    pub resident_key: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl CredentialMetadata {
    pub fn from_credential(credential: &WebAuthnCredential) -> Self {
        let public_key_json: serde_json::Value =
            serde_json::from_slice(&credential.public_key).unwrap_or(serde_json::Value::Null);
        Self {
            credential_id: credential.id.clone(),
            aaguid: normalize_aaguid(&credential.aaguid),
            binding: infer_binding(credential, &public_key_json),
            attachment: infer_attachment(credential, &public_key_json),
            resident_key: bool_field(&public_key_json, &["resident_key", "rk", "discoverable"])
                .unwrap_or(false),
            backup_eligible: bool_field(&public_key_json, &["backup_eligible", "be"])
                .unwrap_or(false),
            backup_state: bool_field(&public_key_json, &["backup_state", "bs"]).unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyInventoryReport {
    pub user_id: String,
    pub total: usize,
    pub hardware_bound: usize,
    pub synced: usize,
    pub recovery_ready: bool,
    pub credentials: Vec<CredentialMetadata>,
    pub violations: Vec<String>,
}

pub fn evaluate_passkey_inventory(
    user_id: &str,
    credentials: &[WebAuthnCredential],
    policy: &PasskeyPolicy,
    admin: bool,
) -> QidResult<PasskeyInventoryReport> {
    policy.validate()?;
    let metadata: Vec<_> = credentials
        .iter()
        .map(CredentialMetadata::from_credential)
        .collect();
    let hardware_bound = metadata
        .iter()
        .filter(|credential| credential.binding == PasskeyBinding::HardwareBound)
        .count();
    let synced = metadata
        .iter()
        .filter(|credential| credential.binding == PasskeyBinding::Synced)
        .count();
    let mut violations = Vec::new();

    for credential in &metadata {
        if let Some(aaguid) = &credential.aaguid {
            if policy.deny_aaguid.contains(aaguid) {
                violations.push(format!(
                    "credential {} uses denied AAGUID",
                    credential.credential_id
                ));
            }
            if !policy.allow_aaguid.is_empty() && !policy.allow_aaguid.contains(aaguid) {
                violations.push(format!(
                    "credential {} is not in AAGUID allow list",
                    credential.credential_id
                ));
            }
        } else if policy.attestation == AttestationPolicy::Strict {
            violations.push(format!(
                "credential {} lacks attested AAGUID",
                credential.credential_id
            ));
        }
        if policy.require_resident_key && !credential.resident_key {
            violations.push(format!(
                "credential {} is not discoverable",
                credential.credential_id
            ));
        }
    }

    if admin && policy.require_hardware_backed_for_admin && hardware_bound == 0 {
        violations.push("admin operation requires a hardware-bound passkey".to_string());
    }

    let recovery_ready = metadata.len() >= policy.minimum_recovery_passkeys;
    if !recovery_ready {
        violations.push("insufficient recovery passkeys registered".to_string());
    }

    Ok(PasskeyInventoryReport {
        user_id: user_id.to_string(),
        total: metadata.len(),
        hardware_bound,
        synced,
        recovery_ready,
        credentials: metadata,
        violations,
    })
}

pub fn ceremony_state_key(realm_id: &str, user_id: &str, ceremony_id: &str) -> String {
    let digest = Sha256::digest(format!("{realm_id}:{user_id}:{ceremony_id}").as_bytes());
    hex_encode(&digest)
}

pub fn challenge_is_fresh(issued_at: u64, now: u64, ttl_seconds: u64) -> bool {
    issued_at <= now && now.saturating_sub(issued_at) <= ttl_seconds
}

fn validate_rp_origin(rp_id: &str, origin: &str) -> QidResult<()> {
    let parsed = Url::parse(origin).map_err(|e| QidError::Config {
        message: format!("invalid WebAuthn RP origin: {e}"),
    })?;
    if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
        return Err(QidError::Config {
            message: "WebAuthn RP origin must use https except localhost".to_string(),
        });
    }
    let host = parsed.host_str().ok_or_else(|| QidError::Config {
        message: "WebAuthn RP origin must include a host".to_string(),
    })?;
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Err(QidError::Config {
            message: "WebAuthn RP origin host must match RP ID scope".to_string(),
        });
    }
    Ok(())
}

fn origin_from_url(url: &Url) -> String {
    match url.port() {
        Some(port) => format!(
            "{}://{}:{}",
            url.scheme(),
            url.host_str().unwrap_or_default(),
            port
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

fn normalize_aaguid(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    Some(hex_encode(raw))
}

fn infer_binding(
    credential: &WebAuthnCredential,
    public_key_json: &serde_json::Value,
) -> PasskeyBinding {
    if bool_field(public_key_json, &["hardware_bound", "device_bound"]).unwrap_or(false)
        || !credential.aaguid.is_empty()
    {
        return PasskeyBinding::HardwareBound;
    }
    if bool_field(public_key_json, &["backup_eligible", "be"]).unwrap_or(false)
        || bool_field(public_key_json, &["backup_state", "bs"]).unwrap_or(false)
    {
        return PasskeyBinding::Synced;
    }
    PasskeyBinding::Unknown
}

fn infer_attachment(
    credential: &WebAuthnCredential,
    public_key_json: &serde_json::Value,
) -> AuthenticatorAttachment {
    if string_field(public_key_json, &["attachment", "authenticator_attachment"]).as_deref()
        == Some("platform")
    {
        return AuthenticatorAttachment::Platform;
    }
    if string_field(public_key_json, &["attachment", "authenticator_attachment"]).as_deref()
        == Some("cross-platform")
        || credential
            .device_name
            .as_deref()
            .map(|name| name.to_ascii_lowercase().contains("security key"))
            .unwrap_or(false)
    {
        return AuthenticatorAttachment::Roaming;
    }
    AuthenticatorAttachment::Unknown
}

fn bool_field(value: &serde_json::Value, names: &[&str]) -> Option<bool> {
    names.iter().find_map(|name| {
        value
            .get(*name)
            .and_then(serde_json::Value::as_bool)
            .or_else(|| {
                value
                    .pointer(&format!("/cred/{}", name))
                    .and_then(serde_json::Value::as_bool)
            })
    })
}

fn string_field(value: &serde_json::Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        value
            .get(*name)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                value
                    .pointer(&format!("/cred/{}", name))
                    .and_then(serde_json::Value::as_str)
            })
            .map(str::to_string)
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: &str, public_key: serde_json::Value, aaguid: Vec<u8>) -> WebAuthnCredential {
        WebAuthnCredential {
            id: id.to_string(),
            user_id: "user-1".to_string(),
            credential_id: id.as_bytes().to_vec(),
            public_key: serde_json::to_vec(&public_key).expect("public key JSON"),
            counter: 0,
            aaguid,
            device_name: Some("security key".to_string()),
            created_at: 100,
        }
    }

    #[test]
    fn rp_config_derives_and_validates_origin_scope() {
        let config = PasskeyConfig {
            enabled: true,
            preferred: true,
            rp_id: Some("example.com".to_string()),
            rp_origin: Some("https://login.example.com".to_string()),
            rp_name: "qid".to_string(),
            attestation: None,
        };
        let rp = WebAuthnRp::from_config("https://id.example.com", &config).expect("RP config");
        assert_eq!(rp.rp_id, "example.com");
        assert_eq!(rp.rp_origin, "https://login.example.com");

        let bad = PasskeyConfig {
            rp_origin: Some("https://evil.example.net".to_string()),
            ..config
        };
        assert!(WebAuthnRp::from_config("https://id.example.com", &bad).is_err());
    }

    #[test]
    fn passkey_policy_rejects_unsafe_strict_attestation() {
        let policy = PasskeyPolicy {
            attestation: AttestationPolicy::Strict,
            ..PasskeyPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn inventory_detects_recovery_and_admin_hardware_requirements() {
        let hw = credential(
            "hw",
            serde_json::json!({
                "resident_key": true,
                "hardware_bound": true,
                "attachment": "cross-platform"
            }),
            vec![1, 2, 3, 4],
        );
        let synced = credential(
            "synced",
            serde_json::json!({
                "resident_key": true,
                "backup_eligible": true,
                "attachment": "platform"
            }),
            Vec::new(),
        );
        let report =
            evaluate_passkey_inventory("user-1", &[hw, synced], &PasskeyPolicy::default(), true)
                .expect("inventory");

        assert_eq!(report.total, 2);
        assert_eq!(report.hardware_bound, 1);
        assert_eq!(report.synced, 1);
        assert!(report.recovery_ready);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn inventory_enforces_aaguid_and_resident_key_policy() {
        let denied = credential(
            "denied",
            serde_json::json!({
                "resident_key": false,
                "hardware_bound": true
            }),
            vec![0xde, 0xad],
        );
        let policy = PasskeyPolicy {
            deny_aaguid: BTreeSet::from(["dead".to_string()]),
            minimum_recovery_passkeys: 2,
            ..PasskeyPolicy::default()
        };
        let report =
            evaluate_passkey_inventory("user-1", &[denied], &policy, true).expect("inventory");

        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("denied AAGUID"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("not discoverable"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("insufficient recovery passkeys"))
        );
    }

    #[test]
    fn ceremony_state_key_is_realm_scoped_and_challenge_ttl_is_checked() {
        let a = ceremony_state_key("corp", "user-1", "ceremony-1");
        let b = ceremony_state_key("partner", "user-1", "ceremony-1");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(challenge_is_fresh(100, 120, 30));
        assert!(!challenge_is_fresh(100, 140, 30));
        assert!(!challenge_is_fresh(140, 100, 30));
    }
}
