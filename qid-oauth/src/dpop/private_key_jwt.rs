//! private_key_jwt client authentication validation.

use qid_core::dpop::DpopState;
use qid_core::error::{QidError, QidResult};
use qid_core::util::now_seconds;
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};

use super::parse_jwt_unverified;

/// Validate a `private_key_jwt` client authentication JWT.
///
/// `client_assertion` - the JWT sent as `client_assertion` parameter.
/// `client_id` - the expected client identifier.
/// `token_url` - the token endpoint URL (expected `aud` claim).
/// `client_jwks` - the client's registered public JWK set.
pub fn extract_private_key_jwt(
    client_assertion: &str,
    client_id: &str,
    token_url: &str,
    client_jwks: &serde_json::Value,
    replay_cache: &DpopState,
) -> QidResult<()> {
    let (header, payload) = parse_jwt_unverified(client_assertion)?;
    verify_client_assertion_signature(client_assertion, &header, client_jwks)?;

    // Validate iss == client_id
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "client_assertion missing iss claim".to_string(),
        })?;
    if iss != client_id {
        return Err(QidError::BadRequest {
            message: format!("client_assertion iss mismatch: expected '{client_id}', got '{iss}'"),
        });
    }

    // Validate sub == client_id
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "client_assertion missing sub claim".to_string(),
        })?;
    if sub != client_id {
        return Err(QidError::BadRequest {
            message: format!("client_assertion sub mismatch: expected '{client_id}', got '{sub}'"),
        });
    }

    // Validate aud == token_url
    if !audience_matches(payload.get("aud"), token_url) {
        return Err(QidError::BadRequest {
            message: format!("client_assertion aud mismatch: expected '{token_url}'"),
        });
    }

    // Validate exp
    let exp = payload
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| QidError::BadRequest {
            message: "client_assertion missing or invalid exp claim".to_string(),
        })?;

    let now = now_seconds();
    if exp < now {
        return Err(QidError::BadRequest {
            message: "client_assertion has expired".to_string(),
        });
    }

    // Validate jti (required for replay detection)
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "client_assertion missing jti claim".to_string(),
        })?;

    replay_cache.record_jti(jti, now, now)?;

    Ok(())
}

fn audience_matches(aud: Option<&serde_json::Value>, token_url: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == token_url,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(token_url))
        }
        _ => false,
    }
}

fn verify_client_assertion_signature(
    client_assertion: &str,
    header: &serde_json::Value,
    client_jwks: &serde_json::Value,
) -> QidResult<()> {
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::Unauthorized {
            message: "client_assertion missing alg header".to_string(),
        })?;
    if !matches!(alg, "ES256" | "EdDSA" | "RS256") {
        return Err(QidError::Unauthorized {
            message: format!("client_assertion alg is not supported: {alg}"),
        });
    }
    let kid = header.get("kid").and_then(|value| value.as_str());
    let keys = client_jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .ok_or_else(|| QidError::Unauthorized {
            message: "client_assertion client jwks is missing keys".to_string(),
        })?;
    if keys.is_empty() {
        return Err(QidError::Unauthorized {
            message: "client_assertion client jwks has no keys".to_string(),
        });
    }

    let candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|key| {
            kid.is_none_or(|expected_kid| {
                key.get("kid").and_then(|value| value.as_str()) == Some(expected_kid)
            })
        })
        .collect();
    if candidates.is_empty() {
        return Err(QidError::Unauthorized {
            message: "client_assertion kid is not registered for client".to_string(),
        });
    }
    let mut last_error = None;
    for candidate in candidates {
        let mut jwk_value = candidate.clone();
        if let Some(object) = jwk_value.as_object_mut() {
            object
                .entry("kid".to_string())
                .or_insert_with(|| serde_json::Value::String(String::new()));
        }
        let jwk: Jwk = match serde_json::from_value(jwk_value) {
            Ok(jwk) => jwk,
            Err(err) => {
                last_error = Some(format!("registered client JWK is invalid: {err}"));
                continue;
            }
        };
        if jwk.alg.as_deref() != Some(alg) {
            last_error = Some("registered client JWK alg does not match JWT alg".to_string());
            continue;
        }
        match verify_jwt_signature_with_jwk(client_assertion, &jwk, alg) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err.message().to_string()),
        }
    }
    Err(QidError::Unauthorized {
        message: format!(
            "client_assertion signature verification failed: {}",
            last_error.unwrap_or_else(|| "no usable client key".to_string())
        ),
    })
}
