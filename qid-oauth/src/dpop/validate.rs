//! DPoP proof validation.

use qid_core::dpop::DpopState;
use qid_core::error::{QidError, QidResult};
use qid_core::jwt::Signer;
use qid_core::util::now_seconds;
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};
use qid_ops::{CacheKey, CachePut, RedisLikeCache, RedisLikeTransport};

use super::parse_jwt_unverified;

/// Maximum acceptable clock skew in seconds for DPoP proof iat.
const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Maximum age in seconds for a DPoP proof.
const MAX_PROOF_AGE_SECS: u64 = 120;

const REPLAY_MESSAGE: &str = "DPoP proof jti already used (replay detected)";

/// Validate a DPoP proof JWT.
///
/// `dpop_proof` - the raw DPoP proof JWT string.
/// `expected_htm` - the expected HTTP method (e.g. "POST").
/// `expected_htu` - the expected HTTP URI (e.g. "`https://id.example.com/token`").
/// Returns the `jti` (unique proof identifier) on success.
pub fn validate_dpop_proof(
    dpop_state: &DpopState,
    dpop_proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    required_nonce: Option<&str>,
    _signer: &dyn Signer,
) -> QidResult<String> {
    let claims = validate_dpop_proof_claims(dpop_proof, expected_htm, expected_htu)?;
    if let Some(required_nonce) = required_nonce {
        if claims.nonce.as_deref() != Some(required_nonce) {
            return Err(QidError::DpopNonce {
                message: "DPoP proof nonce mismatch".to_string(),
            });
        }
        dpop_state.consume_nonce(required_nonce, claims.now)?;
    }
    dpop_state.record_replay_key(
        &claims.jti,
        claims.replay_expires_at(),
        claims.now,
        REPLAY_MESSAGE,
    )?;
    Ok(claims.jti)
}

/// Validate a DPoP proof and record replay state in a Redis/Valkey-compatible cache.
pub fn validate_dpop_proof_with_cache<T: RedisLikeTransport>(
    cache: &mut RedisLikeCache<T>,
    dpop_proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    required_nonce: Option<&str>,
    _signer: &dyn Signer,
) -> QidResult<String> {
    let claims = validate_dpop_proof_claims(dpop_proof, expected_htm, expected_htu)?;
    if let Some(required_nonce) = required_nonce
        && claims.nonce.as_deref() != Some(required_nonce)
    {
        return Err(QidError::DpopNonce {
            message: "DPoP proof nonce mismatch".to_string(),
        });
    }
    let cache_key = CacheKey::new(
        "dpop_jti",
        format!("{}:{}:{}", expected_htm, expected_htu, claims.jti),
    )?;
    let recorded = cache.put_if_absent_with_exact_ttl(CachePut {
        key: cache_key,
        value: claims.iat.to_string().into_bytes(),
        ttl_seconds: claims.replay_expires_at().saturating_sub(claims.now).max(1),
    })?;
    if !recorded {
        return Err(QidError::BadRequest {
            message: REPLAY_MESSAGE.to_string(),
        });
    }
    Ok(claims.jti)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DpopProofClaims {
    jti: String,
    iat: u64,
    now: u64,
    nonce: Option<String>,
}

impl DpopProofClaims {
    fn replay_expires_at(&self) -> u64 {
        // The age check accepts the entire second at iat + MAX_PROOF_AGE_SECS.
        self.iat.saturating_add(MAX_PROOF_AGE_SECS + 1)
    }
}

fn validate_dpop_proof_claims(
    dpop_proof: &str,
    expected_htm: &str,
    expected_htu: &str,
) -> QidResult<DpopProofClaims> {
    let (header, payload) = parse_jwt_unverified(dpop_proof)?;

    // Validate typ header (required by RFC 9449 Section 4.1)
    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing typ header".to_string(),
        })?;
    if typ != "dpop+jwt" {
        return Err(QidError::BadRequest {
            message: format!("DPoP proof typ must be 'dpop+jwt', got '{typ}'"),
        });
    }

    let jwk = header.get("jwk").ok_or_else(|| QidError::BadRequest {
        message: "DPoP proof missing jwk header".to_string(),
    })?;
    if !jwk.is_object() {
        return Err(QidError::BadRequest {
            message: "DPoP proof jwk header must be an object".to_string(),
        });
    }
    verify_dpop_proof_signature(dpop_proof, &header)?;

    // Validate htm (HTTP method)
    let htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing htm claim".to_string(),
        })?;
    if htm != expected_htm {
        return Err(QidError::BadRequest {
            message: format!("DPoP proof htm mismatch: expected '{expected_htm}', got '{htm}'"),
        });
    }

    // Validate htu (HTTP URI)
    let htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing htu claim".to_string(),
        })?;
    if htu != expected_htu {
        return Err(QidError::BadRequest {
            message: format!("DPoP proof htu mismatch: expected '{expected_htu}', got '{htu}'"),
        });
    }

    // Validate iat (issued-at timestamp)
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing or invalid iat claim".to_string(),
        })?;

    let now = now_seconds();
    if iat > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(QidError::BadRequest {
            message: "DPoP proof iat is in the future (beyond clock skew)".to_string(),
        });
    }
    if iat < now.saturating_sub(MAX_PROOF_AGE_SECS) {
        return Err(QidError::BadRequest {
            message: "DPoP proof has expired (iat too old)".to_string(),
        });
    }

    // Extract jti (unique proof identifier)
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing jti claim".to_string(),
        })?;

    // Replay detection
    Ok(DpopProofClaims {
        jti: jti.to_string(),
        iat,
        now,
        nonce: payload
            .get("nonce")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
    })
}

fn verify_dpop_proof_signature(dpop_proof: &str, header: &serde_json::Value) -> QidResult<()> {
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing alg header".to_string(),
        })?;
    if !matches!(alg, "ES256" | "EdDSA" | "RS256") {
        return Err(QidError::BadRequest {
            message: format!("DPoP proof alg is not supported: {alg}"),
        });
    }
    let mut jwk_value = header
        .get("jwk")
        .cloned()
        .ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof missing jwk header".to_string(),
        })?;
    if let Some(object) = jwk_value.as_object_mut() {
        object
            .entry("kid".to_string())
            .or_insert_with(|| serde_json::Value::String(String::new()));
    }
    let jwk: Jwk = serde_json::from_value(jwk_value).map_err(|e| QidError::BadRequest {
        message: format!("DPoP proof jwk header is invalid: {e}"),
    })?;
    if jwk.alg.as_deref().is_some_and(|jwk_alg| jwk_alg != alg) {
        return Err(QidError::BadRequest {
            message: "DPoP proof jwk alg does not match JWT alg".to_string(),
        });
    }
    // The thumbprint bound to the access token is derived from the JWK members
    // selected by `kty`, while signature verification selects members by `alg`.
    // Reject a mismatch so a proof cannot present a victim's thumbprint while
    // being signed by a key the attacker controls.
    let key_type_matches_alg = match alg {
        "ES256" => jwk.kty == "EC" && jwk.crv.as_deref() == Some("P-256"),
        "RS256" => jwk.kty == "RSA",
        "EdDSA" => jwk.kty == "OKP" && jwk.crv.as_deref() == Some("Ed25519"),
        _ => false,
    };
    if !key_type_matches_alg {
        return Err(QidError::BadRequest {
            message: format!("DPoP proof jwk key type does not match alg {alg}"),
        });
    }
    verify_jwt_signature_with_jwk(dpop_proof, &jwk, alg).map_err(|e| QidError::BadRequest {
        message: format!("DPoP proof jwk cannot verify signature: {}", e.message()),
    })?;
    Ok(())
}
