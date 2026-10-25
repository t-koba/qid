//! Strict ES256 push proofs, not delivery receipts or authentication decisions.
//!
//! Wire format: untagged COSE_Sign1 with protected `{1: -7}`, empty
//! unprotected headers, attached canonical CBOR-array claims and a raw 64-byte
//! signature. No extensions, detached payloads or external AAD are supported.
//! Unlike the legacy generic COSE helper, this uses the RFC 9052 four-element
//! Sig_structure. Never use provider acceptance as a substitute for this proof.
//! Storage must still atomically enforce expiry, attempts, revocation and one use.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use qid_core::{
    error::{QidError, QidResult},
    models::{
        PushAuthenticator, PushDecision, PushLoginChallenge, PushPublicJwk,
        PushRegistrationChallenge,
    },
    util::{constant_time_eq, sha256_hex},
};

/// Hard parser bound; realm policy can impose a smaller request limit.
pub const MAX_PROOF_BYTES: usize = 8192;

fn invalid() -> QidError {
    // Do not include nonce, provider destination, JWK or signed data in errors.
    QidError::BadRequest {
        message: "invalid push proof".into(),
    }
}

/// Reject non-P-256, private/unknown JWK parameters (also rejected by the model),
/// non-canonical coordinates, wrong coordinate lengths and off-curve points.
pub fn validate_public_key(jwk: &PushPublicJwk) -> QidResult<VerifyingKey> {
    let PushPublicJwk::EC { crv, x, y } = jwk else {
        return Err(invalid());
    };
    if crv != "P-256" {
        return Err(invalid());
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    for (value, output) in [x, y].into_iter().zip(sec1[1..].chunks_mut(32)) {
        if value.len() != 43 {
            return Err(invalid());
        }
        let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != *value {
            return Err(invalid());
        }
        output.copy_from_slice(&decoded);
    }
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| invalid())
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn encode(value: &Value) -> QidResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|_| invalid())?;
    Ok(out)
}
fn decode(bytes: &[u8]) -> QidResult<Value> {
    let mut input = bytes;
    let value = ciborium::from_reader(&mut input).map_err(|_| invalid())?;
    if !input.is_empty() {
        return Err(invalid());
    }
    Ok(value)
}
fn nonce_matches(nonce: &str, verifier: &str) -> QidResult<()> {
    if nonce.len() != 43 {
        return Err(invalid());
    }
    let raw = URL_SAFE_NO_PAD.decode(nonce).map_err(|_| invalid())?;
    if raw.len() != 32
        || URL_SAFE_NO_PAD.encode(&raw) != nonce
        || !constant_time_eq(sha256_hex(nonce.as_bytes()).as_bytes(), verifier.as_bytes())
    {
        return Err(invalid());
    }
    Ok(())
}
fn bounded_ids(ids: &[&str]) -> QidResult<()> {
    if ids.iter().any(|s| s.is_empty() || s.len() > 256) {
        return Err(invalid());
    }
    Ok(())
}

/// Canonical registration payload. The registration ID is the authenticator ID.
/// The destination digest binds the new key to the destination receiving the nonce.
pub fn registration_payload(c: &PushRegistrationChallenge, nonce: &str) -> QidResult<Vec<u8>> {
    let a = &c.authenticator;
    bounded_ids(&[&a.realm_id, &a.user_id, &a.id])?;
    if a.destination.is_empty() || a.destination.len() > 4096 {
        return Err(invalid());
    }
    nonce_matches(nonce, &c.nonce_verifier)?;
    encode(&Value::Array(vec![
        text("qid.push.registration.v1"),
        text(&a.realm_id),
        text(&a.user_id),
        text("registration"),
        text(&a.id),
        text(&a.id),
        text(nonce),
        text(&sha256_hex(a.destination.as_bytes())),
    ]))
}

/// Canonical login payload. Challenge ID IS the password-login transaction ID.
/// A deny signature cannot be replayed as approval; browser binding is NOT sent
/// to the device and is checked separately during atomic redemption.
pub fn login_payload(
    c: &PushLoginChallenge,
    nonce: &str,
    decision: PushDecision,
) -> QidResult<Vec<u8>> {
    bounded_ids(&[&c.realm_id, &c.user_id, &c.authenticator_id, &c.id])?;
    nonce_matches(nonce, &c.nonce_verifier)?;
    let purpose = match c.purpose {
        qid_core::models::PushPurpose::PasswordLogin => "password_login",
    };
    encode(&Value::Array(vec![
        text("qid.push.login.v1"),
        text(&c.realm_id),
        text(&c.user_id),
        text(purpose),
        text(&c.authenticator_id),
        text(&c.id),
        text(nonce),
        text(match decision {
            PushDecision::Approve => "approve",
            PushDecision::Deny => "deny",
        }),
    ]))
}

pub fn verify_registration(
    c: &PushRegistrationChallenge,
    nonce: &str,
    proof: &[u8],
) -> QidResult<()> {
    verify(
        &c.authenticator.public_jwk,
        &registration_payload(c, nonce)?,
        proof,
    )
}
pub fn verify_login(
    c: &PushLoginChallenge,
    a: &PushAuthenticator,
    nonce: &str,
    decision: PushDecision,
    proof: &[u8],
) -> QidResult<()> {
    if a.realm_id != c.realm_id
        || a.user_id != c.user_id
        || a.id != c.authenticator_id
        || a.revoked_at.is_some()
    {
        return Err(invalid());
    }
    verify(&a.public_jwk, &login_payload(c, nonce, decision)?, proof)
}

fn verify(jwk: &PushPublicJwk, expected: &[u8], proof: &[u8]) -> QidResult<()> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(invalid());
    }
    let Value::Array(parts) = decode(proof)? else {
        return Err(invalid());
    };
    let [
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(payload),
        Value::Bytes(signature),
    ] = parts.as_slice()
    else {
        return Err(invalid());
    };
    // Preserve map entries until validation: converting to a map first would
    // silently discard duplicate alg headers. Reject every unsupported header.
    let Value::Map(headers) = decode(protected)? else {
        return Err(invalid());
    };
    if headers.len() != 1
        || !unprotected.is_empty()
        || headers[0] != (Value::Integer(1.into()), Value::Integer((-7).into()))
        || !constant_time_eq(payload, expected)
    {
        return Err(invalid());
    }
    let signed = encode(&Value::Array(vec![
        text("Signature1"),
        Value::Bytes(protected.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.clone()),
    ]))?;
    let signature = Signature::from_slice(signature).map_err(|_| invalid())?;
    validate_public_key(jwk)?
        .verify(&signed, &signature)
        .map_err(|_| invalid())
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
