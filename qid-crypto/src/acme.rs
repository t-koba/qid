//! Automatic Certificate Management Environment (RFC 8555) client.
//! Provides the core protocol types and a minimal directory discovery.
//! Certificate issuance requires an external ACME server.

use base64::Engine;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: Option<String>,
    pub meta: Option<AcmeDirectoryMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    #[serde(default)]
    pub caa_identities: Vec<String>,
    pub external_account_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeAccount {
    pub status: String,
    pub contact: Vec<String>,
    pub orders: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeOrder {
    pub status: String,
    pub expires: Option<String>,
    pub identifiers: Vec<AcmeIdentifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeIdentifier {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeAuthorization {
    pub identifier: AcmeIdentifier,
    pub status: String,
    pub expires: Option<String>,
    pub challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeChallenge {
    pub r#type: String,
    pub url: String,
    pub status: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeCertificate {
    pub certificate: String,
    pub chain: Option<String>,
}

pub async fn discover_acme_directory(url: &str) -> QidResult<AcmeDirectory> {
    let resp = reqwest::get(url).await.map_err(|e| QidError::BadRequest {
        message: format!("ACME directory discovery failed: {e}"),
    })?;
    let dir: AcmeDirectory = resp.json().await.map_err(|e| QidError::BadRequest {
        message: format!("ACME directory parse failed: {e}"),
    })?;
    Ok(dir)
}

pub fn acme_alpn_challenge_value(token: &str, key_authorization: &str) -> String {
    let hash = sha2::Sha256::digest(key_authorization.as_bytes());
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    format!("{token}.{b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_alpn_challenge() {
        let result = acme_alpn_challenge_value("test-token", "test-key-auth");
        assert!(result.contains("test-token"));
        assert!(result.len() > 20);
    }

    #[test]
    fn acme_directory_deserialize() {
        let json = r#"{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "meta": {
                "termsOfService": "https://example.com/terms",
                "caaIdentities": ["example.com"]
            }
        }"#;
        let dir: AcmeDirectory = serde_json::from_str(json).unwrap();
        assert_eq!(dir.new_nonce, "https://example.com/acme/new-nonce");
        assert!(dir.meta.is_some());
    }

    #[test]
    fn acme_order_round_trip() {
        let order = AcmeOrder {
            status: "pending".to_string(),
            expires: Some("2026-07-01T00:00:00Z".to_string()),
            identifiers: vec![AcmeIdentifier {
                r#type: "dns".to_string(),
                value: "example.com".to_string(),
            }],
            authorizations: vec!["https://example.com/acme/authz/1".to_string()],
            finalize: "https://example.com/acme/finalize/1".to_string(),
            certificate: None,
        };
        let json = serde_json::to_string(&order).unwrap();
        let parsed: AcmeOrder = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, "pending");
    }

    #[test]
    fn acme_authorization_deserialize() {
        let json = r#"{
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "challenges": [
                {"type": "http-01", "url": "https://example.com/acme/challenge/1", "status": "pending"}
            ]
        }"#;
        let authz: AcmeAuthorization = serde_json::from_str(json).unwrap();
        assert_eq!(authz.identifier.value, "example.com");
        assert_eq!(authz.challenges.len(), 1);
    }
}
