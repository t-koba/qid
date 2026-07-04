//! DPoP proof validation and private_key_jwt client authentication.
//!
//! Validates DPoP proof structure, claims, JWK thumbprint binding, and proof signature.

use base64::Engine;
use qid_core::error::{QidError, QidResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

mod private_key_jwt;
mod validate;

pub use private_key_jwt::extract_private_key_jwt;
pub use validate::{validate_dpop_proof, validate_dpop_proof_with_cache};

/// Parse a JWT into its header and payload JSON values without cryptographic verification.
pub(crate) fn parse_jwt_unverified(
    token: &str,
) -> QidResult<(serde_json::Value, serde_json::Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(QidError::BadRequest {
            message: "invalid JWT format: expected 3 dot-separated segments".to_string(),
        });
    }

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| QidError::BadRequest {
            message: "invalid base64url encoding in JWT header".to_string(),
        })?;

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| QidError::BadRequest {
            message: "invalid base64url encoding in JWT payload".to_string(),
        })?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| QidError::BadRequest {
            message: format!("invalid JSON in JWT header: {e}"),
        })?;

    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| QidError::BadRequest {
            message: format!("invalid JSON in JWT payload: {e}"),
        })?;

    Ok((header, payload))
}

/// Extract the raw DPoP proof JWT from a `DPoP` HTTP header value.
///
/// RFC 9449 defines the field value as the proof JWT itself.
pub fn extract_dpop_jkt(dpop_header: &str) -> QidResult<String> {
    let token = dpop_header.trim();
    if token.is_empty() {
        return Err(QidError::BadRequest {
            message: "DPoP header token is empty".to_string(),
        });
    }
    if token.chars().any(char::is_whitespace) {
        return Err(QidError::BadRequest {
            message: "DPoP header must contain only the compact proof JWT".to_string(),
        });
    }
    if token.split('.').count() != 3 {
        return Err(QidError::BadRequest {
            message: "DPoP header must contain a compact proof JWT".to_string(),
        });
    }

    Ok(token.to_string())
}

/// Verify the `ath` claim binds a DPoP proof to an access token.
pub fn validate_dpop_ath(dpop_proof: &str, access_token: &str) -> QidResult<()> {
    let (_header, payload) = parse_jwt_unverified(dpop_proof)?;
    let ath = payload
        .get("ath")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::Unauthorized {
            message: "DPoP proof missing ath claim".to_string(),
        })?;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(access_token.as_bytes()));
    if !qid_core::util::constant_time_eq(ath.as_bytes(), expected.as_bytes()) {
        return Err(QidError::Unauthorized {
            message: "DPoP proof ath does not match access token".to_string(),
        });
    }
    Ok(())
}

/// Compute a DPoP public key thumbprint from the proof JWT header JWK.
///
/// The thumbprint is computed per RFC 7638 §3.1: serialize the required
/// members of the public key (in lexicographic order, without whitespace)
/// as a JSON object, SHA-256 the UTF-8 bytes of that serialization, and
/// base64url-encode the digest without padding.
pub fn dpop_jkt_from_proof(dpop_proof: &str) -> QidResult<String> {
    let (header, _payload) = parse_jwt_unverified(dpop_proof)?;
    let jwk = header.get("jwk").ok_or_else(|| QidError::BadRequest {
        message: "DPoP proof missing jwk header".to_string(),
    })?;
    let object = jwk.as_object().ok_or_else(|| QidError::BadRequest {
        message: "DPoP proof jwk header must be an object".to_string(),
    })?;
    let kty = object
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof jwk missing kty".to_string(),
        })?;
    let required_members: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        other => {
            return Err(QidError::BadRequest {
                message: format!("unsupported DPoP jwk kty: {other}"),
            });
        }
    };
    let mut canonical = BTreeMap::new();
    for member in required_members {
        let value = object
            .get(*member)
            .and_then(|v| v.as_str())
            .ok_or_else(|| QidError::BadRequest {
                message: format!("DPoP proof jwk missing required member {member}"),
            })?;
        canonical.insert(*member, value);
    }
    let canonical_json = serde_json::to_string(&canonical).map_err(|e| QidError::BadRequest {
        message: format!("failed to canonicalize DPoP jwk: {e}"),
    })?;
    let digest = Sha256::digest(canonical_json.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// Extract the optional `nonce` claim from a DPoP proof.
pub fn dpop_nonce_from_proof(dpop_proof: &str) -> QidResult<Option<String>> {
    let (_header, payload) = parse_jwt_unverified(dpop_proof)?;
    Ok(payload
        .get("nonce")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned))
}

/// Extract the `iss` (client_id) claim from a client_assertion JWT without signature verification.
///
/// Phase 0: parses the assertion JWT and returns the `iss` claim value.
pub fn extract_client_id_from_assertion(client_assertion: &str) -> QidResult<String> {
    let (_header, payload) = parse_jwt_unverified(client_assertion)?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "client_assertion missing iss claim".to_string(),
        })
}

#[cfg(test)]
mod tests;
