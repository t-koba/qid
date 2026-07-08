//! Key ring management.

use crate::jwk::{JwkSet, eddsa_jwk_from_pem, es256_jwk_from_pem, generate_eddsa, generate_es256};
use crate::jwt::LocalSigner;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A key ring holds signing keys for a realm, with rotation state.
#[derive(Debug)]
pub struct Keyring {
    pub name: String,
    active_kid: String,
    next_kid: Option<String>,
    previous_kids: Vec<String>,
    overlap_days: u64,
    max_age_days: u64,
    signers: HashMap<String, LocalSigner>,
    jwks: JwkSet,
    key_created_at: HashMap<String, u64>,
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Keyring {
    /// Create a new keyring with default rotation config (14-day overlap, 90-day max age).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            active_kid: String::new(),
            next_kid: None,
            previous_kids: Vec::new(),
            overlap_days: 14,
            max_age_days: 90,
            signers: HashMap::new(),
            jwks: JwkSet::new(Vec::new()),
            key_created_at: HashMap::new(),
        }
    }

    /// Create a new keyring with explicit rotation config.
    pub fn with_rotation(name: impl Into<String>, overlap_days: u64, max_age_days: u64) -> Self {
        Self {
            name: name.into(),
            active_kid: String::new(),
            next_kid: None,
            previous_kids: Vec::new(),
            overlap_days,
            max_age_days,
            signers: HashMap::new(),
            jwks: JwkSet::new(Vec::new()),
            key_created_at: HashMap::new(),
        }
    }

    pub fn validate(&self) -> QidResult<()> {
        if self.name.trim().is_empty() {
            return Err(QidError::Config {
                message: "keyring name must not be empty".to_string(),
            });
        }
        if self.active_kid.is_empty() {
            return Err(QidError::Config {
                message: format!("keyring {} has no active key", self.name),
            });
        }
        Ok(())
    }

    /// Generate and add a new ES256 key as the active key.
    pub fn generate_es256(&mut self, kid: impl Into<String>) -> QidResult<String> {
        let kid = kid.into();
        let generated = generate_es256(&kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate ES256 key: {e}"),
        })?;
        self.insert_es256_key(&kid, &generated.private_pem)?;
        self.active_kid = kid.clone();
        Ok(kid)
    }

    /// Generate and add a new ES256 successor key without changing the active key.
    ///
    /// The successor is published in JWKS immediately through [`Keyring::jwks`],
    /// but [`Keyring::active_signer`] continues to use the current active key
    /// until [`Keyring::rotate`] promotes the successor.
    pub fn generate_next_es256(&mut self, kid: impl Into<String>) -> QidResult<String> {
        let kid = kid.into();
        let generated = generate_es256(&kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate ES256 successor key: {e}"),
        })?;
        self.insert_es256_key(&kid, &generated.private_pem)?;
        self.next_kid = Some(kid.clone());
        Ok(kid)
    }

    /// Generate and add a new EdDSA key as the active key.
    pub fn generate_eddsa(&mut self, kid: impl Into<String>) -> QidResult<String> {
        let kid = kid.into();
        let generated = generate_eddsa(&kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate EdDSA key: {e}"),
        })?;
        self.insert_eddsa_key(&kid, &generated.private_pem)?;
        self.active_kid = kid.clone();
        Ok(kid)
    }

    /// Generate and add a new EdDSA successor key without changing the active key.
    ///
    /// The successor is published in JWKS immediately through [`Keyring::jwks`],
    /// but signing remains on the current active key until promotion.
    pub fn generate_next_eddsa(&mut self, kid: impl Into<String>) -> QidResult<String> {
        let kid = kid.into();
        let generated = generate_eddsa(&kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate EdDSA successor key: {e}"),
        })?;
        self.insert_eddsa_key(&kid, &generated.private_pem)?;
        self.next_kid = Some(kid.clone());
        Ok(kid)
    }

    /// Load an ES256 key from PEM as the active key.
    pub fn load_es256(&mut self, kid: impl Into<String>, pem: &str) -> QidResult<String> {
        let kid = kid.into();
        self.insert_es256_key(&kid, pem)?;
        self.active_kid = kid.clone();
        Ok(kid)
    }

    /// Load an ES256 key from PEM as the successor key.
    pub fn load_next_es256(&mut self, kid: impl Into<String>, pem: &str) -> QidResult<String> {
        let kid = kid.into();
        self.insert_es256_key(&kid, pem)?;
        self.next_kid = Some(kid.clone());
        Ok(kid)
    }

    fn insert_es256_key(&mut self, kid: &str, pem: &str) -> QidResult<()> {
        let signer =
            LocalSigner::from_ec_pem(kid, pem.as_bytes()).map_err(|e| QidError::Crypto {
                message: format!("failed to load ES256 key: {e}"),
            })?;
        let jwk = es256_jwk_from_pem(kid, pem).map_err(|e| QidError::Crypto {
            message: format!("failed to derive JWK: {e}"),
        })?;
        let now = now_epoch();
        self.key_created_at.insert(kid.to_string(), now);
        self.signers.insert(kid.to_string(), signer);
        self.jwks.keys.push(jwk);
        Ok(())
    }

    /// Load an EdDSA key from PEM as the active key.
    pub fn load_eddsa(&mut self, kid: impl Into<String>, pem: &str) -> QidResult<String> {
        let kid = kid.into();
        self.insert_eddsa_key(&kid, pem)?;
        self.active_kid = kid.clone();
        Ok(kid)
    }

    /// Load an EdDSA key from PEM as the successor key.
    pub fn load_next_eddsa(&mut self, kid: impl Into<String>, pem: &str) -> QidResult<String> {
        let kid = kid.into();
        self.insert_eddsa_key(&kid, pem)?;
        self.next_kid = Some(kid.clone());
        Ok(kid)
    }

    fn insert_eddsa_key(&mut self, kid: &str, pem: &str) -> QidResult<()> {
        let signer =
            LocalSigner::from_eddsa_pem(kid, pem.as_bytes()).map_err(|e| QidError::Crypto {
                message: format!("failed to load EdDSA key: {e}"),
            })?;
        let jwk = eddsa_jwk_from_pem(kid, pem).map_err(|e| QidError::Crypto {
            message: format!("failed to derive JWK: {e}"),
        })?;
        let now = now_epoch();
        self.key_created_at.insert(kid.to_string(), now);
        self.signers.insert(kid.to_string(), signer);
        self.jwks.keys.push(jwk);
        Ok(())
    }

    pub fn active_signer(&self) -> Option<&LocalSigner> {
        self.signers.get(&self.active_kid)
    }

    /// Return the JWKS containing active, next (if any), and previous keys.
    /// External verifiers receive these to validate tokens signed by any
    /// key currently in the rotation window.
    pub fn jwks(&self) -> JwkSet {
        let mut keys = Vec::new();
        for jwk in &self.jwks.keys {
            if jwk.kid == self.active_kid
                || self.next_kid.as_deref() == Some(jwk.kid.as_str())
                || self.previous_kids.contains(&jwk.kid)
            {
                keys.push(jwk.clone());
            }
        }
        // Preserve insertion order by keeping the original order
        // and deduplicating entries that match the criteria.
        let mut seen = std::collections::HashSet::new();
        keys.retain(|k| seen.insert(k.kid.clone()));
        JwkSet::new(keys)
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn next_kid(&self) -> Option<&str> {
        self.next_kid.as_deref()
    }

    pub fn previous_kids(&self) -> &[String] {
        &self.previous_kids
    }

    pub fn overlap_days(&self) -> u64 {
        self.overlap_days
    }

    pub fn max_age_days(&self) -> u64 {
        self.max_age_days
    }

    /// Look up a signer by kid, checking active, next, and previous keys.
    /// Used to decode/verify tokens signed with recently rotated keys.
    pub fn decoding_signer(&self, kid: &str) -> Option<&LocalSigner> {
        if kid == self.active_kid {
            return self.signers.get(kid);
        }
        if self.next_kid.as_deref() == Some(kid) {
            return self.signers.get(kid);
        }
        if self.previous_kids.iter().any(|k| k == kid) {
            return self.signers.get(kid);
        }
        None
    }

    /// Set the successor (next) key for rotation.
    pub fn set_next_kid(&mut self, kid: impl Into<String>) {
        self.next_kid = Some(kid.into());
    }

    /// Perform a rotation step:
    /// - Current active key moves to `previous_kids`.
    /// - Next key (if set) becomes the new active key.
    /// - Prunes expired previous keys.
    pub fn rotate(&mut self) {
        if !self.active_kid.is_empty() {
            self.previous_kids.insert(0, self.active_kid.clone());
        }
        if let Some(next) = self.next_kid.take() {
            self.active_kid = next;
        }
        self.prune();
    }

    /// Remove previous keys whose creation time exceeds `max_age_days`.
    /// Also cleans up orphaned signers and JWKs for pruned kids that are
    /// no longer active, next, or referenced by `previous_kids`.
    pub fn prune(&mut self) {
        let cutoff = now_epoch().saturating_sub(self.max_age_days * 86400);
        self.previous_kids
            .retain(|kid| self.key_created_at.get(kid).is_none_or(|&ts| ts > cutoff));
        let retained: std::collections::HashSet<String> = self
            .previous_kids
            .iter()
            .chain(std::iter::once(&self.active_kid))
            .chain(self.next_kid.iter())
            .cloned()
            .collect();
        self.signers.retain(|kid, _| retained.contains(kid));
        self.jwks.keys.retain(|jwk| retained.contains(&jwk.kid));
        self.key_created_at.retain(|kid, _| retained.contains(kid));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSignerConfig {
    pub provider: RemoteSignerProvider,
    pub key_id: String,
    pub algorithm: String,
    pub endpoint: String,
    #[serde(default)]
    pub health_check_required: bool,
    #[serde(default)]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteSignerProvider {
    Kms,
    Hsm,
    Pkcs11,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSigningRequest {
    pub provider: RemoteSignerProvider,
    pub key_id: String,
    pub algorithm: String,
    pub signing_input: Vec<u8>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSigningResponse {
    pub key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSignerHealth {
    pub reachable: bool,
    pub key_available: bool,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSignerReadiness {
    pub ready: bool,
    pub reasons: Vec<String>,
}

pub trait RemoteSignerTransport {
    fn sign(&self, request: RemoteSigningRequest) -> Result<RemoteSigningResponse, String>;
    fn health(&self, config: &RemoteSignerConfig) -> Result<RemoteSignerHealth, String>;
}

pub fn validate_remote_signer_config(config: &RemoteSignerConfig) -> QidResult<()> {
    if config.key_id.trim().is_empty() {
        return Err(config_error("remote signer key id must not be empty"));
    }
    if !matches!(config.algorithm.as_str(), "ES256" | "RS256" | "EdDSA") {
        return Err(config_error(
            "remote signer algorithm must be ES256, RS256, or EdDSA",
        ));
    }
    if config.endpoint.trim().is_empty() {
        return Err(config_error("remote signer endpoint must not be empty"));
    }
    if config.timeout_ms == 0 {
        return Err(config_error(
            "remote signer timeout must be greater than zero",
        ));
    }
    Ok(())
}

pub fn remote_sign<T: RemoteSignerTransport>(
    transport: &T,
    config: &RemoteSignerConfig,
    signing_input: Vec<u8>,
) -> QidResult<RemoteSigningResponse> {
    validate_remote_signer_config(config)?;
    if signing_input.is_empty() {
        return Err(QidError::Crypto {
            message: "remote signer input must not be empty".to_string(),
        });
    }
    let response = transport
        .sign(RemoteSigningRequest {
            provider: config.provider.clone(),
            key_id: config.key_id.clone(),
            algorithm: config.algorithm.clone(),
            signing_input,
            endpoint: Some(config.endpoint.clone()),
        })
        .map_err(|message| QidError::Crypto {
            message: format!("remote signer failed: {message}"),
        })?;
    if response.key_id != config.key_id {
        return Err(QidError::Crypto {
            message: "remote signer returned a different key id".to_string(),
        });
    }
    if response.algorithm != config.algorithm {
        return Err(QidError::Crypto {
            message: "remote signer returned a different algorithm".to_string(),
        });
    }
    if response.signature.is_empty() {
        return Err(QidError::Crypto {
            message: "remote signer returned an empty signature".to_string(),
        });
    }
    Ok(response)
}

pub fn check_remote_signer_readiness<T: RemoteSignerTransport>(
    transport: &T,
    config: &RemoteSignerConfig,
) -> RemoteSignerReadiness {
    let mut reasons = Vec::new();
    if let Err(err) = validate_remote_signer_config(config) {
        reasons.push(err.message());
    }
    if config.health_check_required {
        match transport.health(config) {
            Ok(health) => {
                if !health.reachable {
                    reasons.push("remote signer is not reachable".to_string());
                }
                if !health.key_available {
                    reasons.push("remote signer key is not available".to_string());
                }
                if health.latency_ms > config.timeout_ms {
                    reasons.push("remote signer latency exceeds timeout".to_string());
                }
            }
            Err(err) => reasons.push(format!("remote signer health check failed: {err}")),
        }
    }
    RemoteSignerReadiness {
        ready: reasons.is_empty(),
        reasons,
    }
}

/// An HTTP-based remote signer transport that sends signing requests to
/// a configurable endpoint (e.g., AWS KMS, HashiCorp Vault, PKCS#11 proxy).
///
/// The transport sends a POST request with JSON body:
/// ```json
/// { "provider": "kms", "key_id": "...", "algorithm": "ES256", "signing_input": "base64..." }
/// ```
/// and expects a JSON response:
/// ```json
/// { "key_id": "...", "algorithm": "ES256", "signature": "base64..." }
/// ```
pub struct HttpRemoteSignerTransport {
    client: reqwest::blocking::Client,
}

impl HttpRemoteSignerTransport {
    pub fn new() -> QidResult<Self> {
        Self::with_timeout(30)
    }

    pub fn with_timeout(timeout_seconds: u64) -> QidResult<Self> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_seconds))
                .build()
                .map_err(|e| QidError::Internal {
                    message: format!("failed to build remote signer HTTP client: {e}"),
                })?,
        })
    }
}

impl Default for HttpRemoteSignerTransport {
    fn default() -> Self {
        Self::new().expect("remote signer HTTP client default timeout must be valid")
    }
}

impl RemoteSignerTransport for HttpRemoteSignerTransport {
    fn sign(&self, request: RemoteSigningRequest) -> Result<RemoteSigningResponse, String> {
        use base64::Engine;
        let body = serde_json::json!({
            "provider": request.provider,
            "key_id": request.key_id,
            "algorithm": request.algorithm,
            "signing_input": base64::engine::general_purpose::STANDARD.encode(&request.signing_input),
        });
        let endpoint = request.endpoint.as_deref().unwrap_or("");
        let response = self
            .client
            .post(endpoint)
            .json(&body)
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?;
        let status = response.status();
        let json: serde_json::Value = response
            .json()
            .map_err(|e| format!("response parse failed: {e}"))?;
        if !status.is_success() {
            let msg = json
                .get("error")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("remote signer returned {status}: {msg}"));
        }
        let key_id = json
            .get("key_id")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or("response missing key_id")?
            .to_string();
        let algorithm = json
            .get("algorithm")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or("response missing algorithm")?
            .to_string();
        let sig_b64 = json
            .get("signature")
            .and_then(|v: &serde_json::Value| v.as_str())
            .ok_or("response missing signature")?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| format!("signature base64 decode failed: {e}"))?;
        Ok(RemoteSigningResponse {
            key_id,
            algorithm,
            signature,
        })
    }

    fn health(&self, config: &RemoteSignerConfig) -> Result<RemoteSignerHealth, String> {
        let before = std::time::Instant::now();
        let health_endpoint = if config.endpoint.ends_with("/sign") {
            config.endpoint.trim_end_matches("/sign").to_string() + "/health"
        } else {
            config.endpoint.clone()
        };
        let response = self
            .client
            .get(&health_endpoint)
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .send()
            .map_err(|e| format!("health check request failed: {e}"))?;
        let latency_ms = before.elapsed().as_millis() as u64;
        Ok(RemoteSignerHealth {
            reachable: response.status().is_success(),
            key_available: true,
            latency_ms,
        })
    }
}

fn config_error(message: impl Into<String>) -> QidError {
    QidError::Config {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::jwt::{JwtClaims, Signer};
    use std::collections::HashMap;

    struct RecordingRemoteSigner {
        response: RemoteSigningResponse,
        health: RemoteSignerHealth,
    }

    impl RemoteSignerTransport for RecordingRemoteSigner {
        fn sign(&self, request: RemoteSigningRequest) -> Result<RemoteSigningResponse, String> {
            assert_eq!(request.key_id, "kms-key-1");
            assert_eq!(request.algorithm, "ES256");
            assert_eq!(request.signing_input, b"payload".to_vec());
            Ok(self.response.clone())
        }

        fn health(&self, _config: &RemoteSignerConfig) -> Result<RemoteSignerHealth, String> {
            Ok(self.health.clone())
        }
    }

    fn config() -> RemoteSignerConfig {
        RemoteSignerConfig {
            provider: RemoteSignerProvider::Kms,
            key_id: "kms-key-1".to_string(),
            algorithm: "ES256".to_string(),
            endpoint: "https://kms.example/sign".to_string(),
            health_check_required: true,
            timeout_ms: 500,
        }
    }

    #[test]
    fn remote_signer_rejects_invalid_config() {
        let mut cfg = config();
        cfg.algorithm = "HS256".to_string();

        assert!(validate_remote_signer_config(&cfg).is_err());
    }

    #[test]
    fn remote_signer_validates_response_binding() {
        let transport = RecordingRemoteSigner {
            response: RemoteSigningResponse {
                key_id: "kms-key-1".to_string(),
                algorithm: "ES256".to_string(),
                signature: b"sig".to_vec(),
            },
            health: RemoteSignerHealth {
                reachable: true,
                key_available: true,
                latency_ms: 10,
            },
        };

        let response = remote_sign(&transport, &config(), b"payload".to_vec()).unwrap();

        assert_eq!(response.signature, b"sig".to_vec());
    }

    #[test]
    fn remote_signer_readiness_fails_closed_on_latency() {
        let transport = RecordingRemoteSigner {
            response: RemoteSigningResponse {
                key_id: "kms-key-1".to_string(),
                algorithm: "ES256".to_string(),
                signature: b"sig".to_vec(),
            },
            health: RemoteSignerHealth {
                reachable: true,
                key_available: true,
                latency_ms: 700,
            },
        };

        let readiness = check_remote_signer_readiness(&transport, &config());

        assert!(!readiness.ready);
        assert!(
            readiness
                .reasons
                .contains(&"remote signer latency exceeds timeout".to_string())
        );
    }

    #[test]
    fn keyring_generates_and_loads_eddsa_keys() {
        let mut keyring = Keyring::new("realm-signing");
        keyring
            .generate_eddsa("eddsa-1")
            .expect("EdDSA generation failed");

        keyring.validate().expect("keyring should be valid");
        assert_eq!(keyring.active_kid(), "eddsa-1");
        assert_eq!(keyring.jwks().keys[0].kty, "OKP");
        assert_eq!(keyring.jwks().keys[0].crv.as_deref(), Some("Ed25519"));
        assert_eq!(keyring.jwks().keys[0].alg.as_deref(), Some("EdDSA"));

        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: None,
            iat: None,
            jti: None,
            extra: HashMap::new(),
        };
        let token = keyring
            .active_signer()
            .expect("active signer")
            .sign(&claims)
            .expect("JWT signing failed");
        let decoded = keyring
            .active_signer()
            .expect("active signer")
            .decode_signature_only(&token)
            .expect("JWT decoding failed");
        assert_eq!(decoded.claims.sub.as_deref(), Some("subject"));

        let generated = generate_eddsa("eddsa-2").expect("EdDSA generation failed");
        let mut loaded = Keyring::new("loaded");
        loaded
            .load_eddsa("eddsa-2", &generated.private_pem)
            .expect("EdDSA load failed");
        assert_eq!(loaded.jwks().keys[0].kid, "eddsa-2");
    }

    #[test]
    fn keyring_publishes_successor_before_promoting_it() {
        let mut keyring = Keyring::new("realm-signing");
        keyring
            .generate_es256("old")
            .expect("ES256 generation failed");
        keyring
            .generate_next_es256("new")
            .expect("ES256 successor generation failed");

        assert_eq!(keyring.active_kid(), "old");
        assert_eq!(keyring.next_kid(), Some("new"));
        assert_eq!(
            keyring
                .jwks()
                .keys
                .iter()
                .map(|jwk| jwk.kid.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "new"]
        );

        let claims = JwtClaims {
            iss: Some("issuer".to_string()),
            sub: Some("subject".to_string()),
            aud: Some("audience".to_string()),
            exp: Some(2_000_000_000),
            nbf: None,
            iat: None,
            jti: None,
            extra: HashMap::new(),
        };
        let old_token = keyring
            .active_signer()
            .expect("active signer")
            .sign(&claims)
            .expect("old JWT signing failed");

        keyring.rotate();

        assert_eq!(keyring.active_kid(), "new");
        assert_eq!(keyring.previous_kids(), &["old".to_string()]);
        assert_eq!(
            keyring
                .jwks()
                .keys
                .iter()
                .map(|jwk| jwk.kid.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "new"]
        );
        let decoded = keyring
            .decoding_signer("old")
            .expect("previous signer must remain available")
            .decode_signature_only(&old_token)
            .expect("old JWT must verify during overlap");
        assert_eq!(decoded.claims.sub.as_deref(), Some("subject"));
    }
}
