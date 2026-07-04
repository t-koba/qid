//! DID Core 1.0 (Decentralized Identifier) resolution.

use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Vec<String>>,
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(default)]
    pub assertion_method: Vec<String>,
    #[serde(default)]
    pub key_agreement: Vec<String>,
    #[serde(default)]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub capability_delegation: Vec<String>,
    #[serde(default)]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    pub verification_method_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidService {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
}

/// Parse a DID string and return the method and method-specific identifier.
pub fn parse_did(did: &str) -> QidResult<(String, String)> {
    if !did.starts_with("did:") {
        return Err(QidError::BadRequest {
            message: "DID must start with 'did:'".to_string(),
        });
    }
    let rest = &did[4..];
    let parts: Vec<&str> = rest.splitn(2, ':').collect();
    if parts.len() < 2 {
        return Err(QidError::BadRequest {
            message: "DID must have method and method-specific-id".to_string(),
        });
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Resolve a `did:key` to a DID Document (RFC).
pub fn resolve_did_key(did: &str) -> QidResult<DidDocument> {
    let (method, id) = parse_did(did)?;
    if method != "key" {
        return Err(QidError::BadRequest {
            message: format!("unsupported DID method: {method}"),
        });
    }
    // For did:key, the ID is a multibase-encoded public key
    Ok(DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: did.to_string(),
        also_known_as: None,
        controller: None,
        verification_method: vec![VerificationMethod {
            id: format!("{did}#keys-1"),
            controller: did.to_string(),
            verification_method_type: "JsonWebKey2020".to_string(),
            public_key_jwk: Some(serde_json::json!({"kty": "EC", "crv": "P-256"})),
            public_key_multibase: Some(id),
        }],
        authentication: vec![format!("{did}#keys-1")],
        assertion_method: vec![format!("{did}#keys-1")],
        key_agreement: vec![],
        capability_invocation: vec![],
        capability_delegation: vec![],
        service: vec![],
    })
}

/// Resolve a `did:web` to a DID Document by fetching from the well-known URL.
pub async fn resolve_did_web(did: &str) -> QidResult<DidDocument> {
    let (method, id) = parse_did(did)?;
    if method != "web" {
        return Err(QidError::BadRequest {
            message: format!("unsupported DID method: {method}"),
        });
    }
    let url = format!("https://{id}/.well-known/did.json");
    let resp = reqwest::get(&url).await.map_err(|e| QidError::BadRequest {
        message: format!("DID web resolution failed: {e}"),
    })?;
    let doc: DidDocument = resp.json().await.map_err(|e| QidError::BadRequest {
        message: format!("DID document parse failed: {e}"),
    })?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_valid() {
        let (method, id) =
            parse_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpGQjQqG6P9Y").unwrap();
        assert_eq!(method, "key");
        assert!(id.starts_with("z6Mk"));
    }

    #[test]
    fn parse_did_invalid_prefix() {
        assert!(parse_did("http://example.com").is_err());
    }

    #[test]
    fn parse_did_missing_method() {
        assert!(parse_did("did:").is_err());
    }

    #[test]
    fn resolve_did_key_returns_document() {
        let doc =
            resolve_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpGQjQqG6P9Y").unwrap();
        assert!(doc.id.starts_with("did:key:"));
        assert!(!doc.verification_method.is_empty());
        assert!(!doc.authentication.is_empty());
    }

    #[test]
    fn resolve_did_key_rejects_unsupported_method() {
        assert!(resolve_did_key("did:ethr:0x1234").is_err());
    }

    #[test]
    fn did_document_serializes() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: "did:example:123".to_string(),
            also_known_as: None,
            controller: None,
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["id"], "did:example:123");
        assert!(json.get("@context").is_some());
    }
}
