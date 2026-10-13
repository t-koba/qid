//! OpenID for Verifiable Presentations (OID4VP) request helpers.
//!
//! Unsigned local JSON transport/build helpers for OID4VP request
//! objects and the `presentation_definition` object that an OID4VP
//! wallet receives. Nothing here signs requests (this is not JAR
//! transport) and nothing stores state: request authentication,
//! expected audience/nonce provenance, and single-use transaction
//! handling belong to the consuming verifier integration.

use base64::Engine;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// OpenID4VP request mode (response_type / presentation_definition
/// delivery).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpRequest {
    pub client_id: String,
    pub response_uri: String,
    pub nonce: String,
    pub state: String,
    #[serde(default)]
    pub presentation_definition: Option<Oid4VpPresentationDefinition>,
    #[serde(default)]
    pub request_uri: Option<String>,
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpPresentationDefinition {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub input_descriptors: Vec<Oid4VpInputDescriptor>,
    #[serde(default)]
    pub format: HashMap<String, Oid4VpFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpInputDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[serde(default)]
    pub constraints: Oid4VpConstraints,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Oid4VpConstraints {
    #[serde(default)]
    pub fields: Vec<Oid4VpField>,
    #[serde(default)]
    pub limit_disclosure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpField {
    pub path: Vec<String>,
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpFormat {
    #[serde(default)]
    pub alg: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpPresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<Oid4VpDescriptorMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4VpDescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
    #[serde(default)]
    pub path_nested: Option<serde_json::Value>,
}

/// Encode an OID4VP request as unsigned JSON carried in a `request`
/// query parameter (the form `openid4vp://?request=...`). Callers that
/// need authenticated requests must sign the object themselves (JAR)
/// or serve it over an authenticated `request_uri`.
pub fn encode_oid4vp_request_uri(request: &Oid4VpRequest) -> QidResult<String> {
    let json = serde_json::to_vec(request).map_err(|e| QidError::Internal {
        message: format!("failed to serialize OID4VP request: {e}"),
    })?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    Ok(format!("openid4vp://?request={b64}"))
}

/// Decode an OID4VP request URL into the typed request.
pub fn decode_oid4vp_request_uri(uri: &str) -> QidResult<Oid4VpRequest> {
    let url = Url::parse(uri).map_err(|e| QidError::BadRequest {
        message: format!("invalid OID4VP request URI: {e}"),
    })?;
    let mut encoded: Option<String> = None;
    for (key, value) in url.query_pairs() {
        if key == "request" {
            encoded = Some(value.into_owned());
            break;
        }
    }
    let encoded = encoded.ok_or_else(|| QidError::BadRequest {
        message: "OID4VP request URI is missing the request parameter".to_string(),
    })?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| QidError::BadRequest {
            message: format!("OID4VP request base64 decode failed: {e}"),
        })?;
    serde_json::from_slice(&json).map_err(|e| QidError::BadRequest {
        message: format!("OID4VP request JSON parse failed: {e}"),
    })
}

/// Build the in-memory `presentation_submission` object that a wallet
/// returns with its verifiable presentation. The value is only
/// constructed, never stored or matched against a request here.
pub fn build_oid4vp_presentation_submission(
    request: &Oid4VpRequest,
) -> Option<Oid4VpPresentationSubmission> {
    let definition = request.presentation_definition.as_ref()?;
    let entry = Oid4VpDescriptorMapEntry {
        id: definition
            .input_descriptors
            .first()
            .map(|d| d.id.clone())
            .unwrap_or_else(|| "credential".to_string()),
        format: "ldp_vc".to_string(),
        path: "$.verifiableCredential".to_string(),
        path_nested: None,
    };
    Some(Oid4VpPresentationSubmission {
        id: ulid::Ulid::new().to_string(),
        definition_id: definition.id.clone(),
        descriptor_map: vec![entry],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_uri() {
        let request = Oid4VpRequest {
            client_id: "https://verifier.example.com".to_string(),
            response_uri: "https://verifier.example.com/cb".to_string(),
            nonce: "abc123".to_string(),
            state: "xyz".to_string(),
            presentation_definition: None,
            request_uri: None,
            response_type: Some("vp_token".to_string()),
            response_mode: Some("direct_post".to_string()),
        };
        let uri = encode_oid4vp_request_uri(&request).unwrap();
        let parsed = decode_oid4vp_request_uri(&uri).unwrap();
        assert_eq!(parsed.client_id, request.client_id);
        assert_eq!(parsed.nonce, request.nonce);
    }
}
