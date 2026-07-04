//! JWK and key generation helpers.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A JSON Web Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub alg: Option<String>,
}

/// A JWK Set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

/// A generated key pair with PEM private key, public key, and public JWK.
pub struct GeneratedKeyPair {
    pub kid: String,
    pub private_pem: String,
    pub public_pem: String,
    pub public_jwk: Jwk,
}

/// Generate a new ES256 key pair.
pub fn generate_es256(kid: impl Into<String>) -> anyhow::Result<GeneratedKeyPair> {
    let kid = kid.into();
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let private_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();

    let verifying_key = signing_key.verifying_key();
    let public_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = encoded_point
        .x()
        .map(|b| qid_core::util::base64_url_encode(b));
    let y = encoded_point
        .y()
        .map(|b| qid_core::util::base64_url_encode(b));

    let public_jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x,
        y,
        n: None,
        e: None,
        kid: kid.clone(),
        use_: Some("sig".to_string()),
        alg: Some("ES256".to_string()),
    };

    Ok(GeneratedKeyPair {
        kid,
        private_pem,
        public_pem,
        public_jwk,
    })
}

/// Generate a new EdDSA (Ed25519) key pair.
pub fn generate_eddsa(kid: impl Into<String>) -> anyhow::Result<GeneratedKeyPair> {
    use ed25519_dalek::{
        SigningKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey},
    };
    use rand::rngs::OsRng;
    let kid = kid.into();
    let mut secret = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let private_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();
    let verifying_key = signing_key.verifying_key();
    let public_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();

    let public_jwk = Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(qid_core::util::base64_url_encode(verifying_key.as_bytes())),
        y: None,
        n: None,
        e: None,
        kid: kid.clone(),
        use_: Some("sig".to_string()),
        alg: Some("EdDSA".to_string()),
    };

    Ok(GeneratedKeyPair {
        kid,
        private_pem,
        public_pem,
        public_jwk,
    })
}

/// Reconstruct a JWK from an existing ES256 private key PEM.
///
/// Expects PKCS#8 (`-----BEGIN PRIVATE KEY-----`) format.
pub fn es256_jwk_from_pem(kid: impl Into<String>, pem: &str) -> anyhow::Result<Jwk> {
    let kid = kid.into();
    let signing_key = SigningKey::from_pkcs8_pem(pem)?;
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = encoded_point
        .x()
        .map(|b| qid_core::util::base64_url_encode(b));
    let y = encoded_point
        .y()
        .map(|b| qid_core::util::base64_url_encode(b));

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x,
        y,
        n: None,
        e: None,
        kid,
        use_: Some("sig".to_string()),
        alg: Some("ES256".to_string()),
    })
}

/// Reconstruct a JWK from an existing Ed25519 private key PEM.
///
/// Expects PKCS#8 (`-----BEGIN PRIVATE KEY-----`) format.
pub fn eddsa_jwk_from_pem(kid: impl Into<String>, pem: &str) -> anyhow::Result<Jwk> {
    use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};
    let kid = kid.into();
    let signing_key = SigningKey::from_pkcs8_pem(pem)?;
    let verifying_key = signing_key.verifying_key();

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(qid_core::util::base64_url_encode(verifying_key.as_bytes())),
        y: None,
        n: None,
        e: None,
        kid,
        use_: Some("sig".to_string()),
        alg: Some("EdDSA".to_string()),
    })
}

/// Compute the JWK Thumbprint per RFC 7638 using SHA-256.
pub fn jwk_thumbprint(jwk: &Jwk) -> QidResult<String> {
    let mut canonical = serde_json::Map::new();
    if let Some(ref crv) = jwk.crv {
        canonical.insert("crv".to_string(), serde_json::Value::String(crv.clone()));
    }
    canonical.insert(
        "kty".to_string(),
        serde_json::Value::String(jwk.kty.clone()),
    );
    if let Some(ref x) = jwk.x {
        canonical.insert("x".to_string(), serde_json::Value::String(x.clone()));
    }
    if let Some(ref y) = jwk.y {
        canonical.insert("y".to_string(), serde_json::Value::String(y.clone()));
    }
    if let Some(ref e) = jwk.e {
        canonical.insert("e".to_string(), serde_json::Value::String(e.clone()));
    }
    if let Some(ref n) = jwk.n {
        canonical.insert("n".to_string(), serde_json::Value::String(n.clone()));
    }
    let json = serde_json::to_string(&canonical).map_err(|e| QidError::Internal {
        message: format!("JWK thumbprint serialization failed: {e}"),
    })?;
    let hash = Sha256::digest(json.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
}

/// Compute the JWK Thumbprint URI per RFC 9278.
pub fn jwk_thumbprint_uri(jwk: &Jwk) -> QidResult<String> {
    let thumbprint = jwk_thumbprint(jwk)?;
    Ok(format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{thumbprint}"
    ))
}

/// Compute a key ID from a JWK thumbprint.
pub fn compute_kid(jwk: &Jwk) -> String {
    let mut thumbprint = HashMap::new();
    thumbprint.insert("crv", jwk.crv.clone().unwrap_or_default());
    thumbprint.insert("kty", jwk.kty.clone());
    thumbprint.insert("x", jwk.x.clone().unwrap_or_default());
    thumbprint.insert("y", jwk.y.clone().unwrap_or_default());
    let json = serde_json::to_string(&thumbprint).unwrap_or_default();
    let hash = Sha256::digest(json.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}
