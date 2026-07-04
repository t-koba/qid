//! DPoP and private_key_jwt tests.

use base64::Engine;
use qid_core::dpop::DpopState;
use qid_crypto::{Jwk, LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};
use qid_ops::{
    CacheBackendConfig, CacheBackendKind, RedisLikeCache, RedisLikeCommand, RedisLikeTransport,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::{
    extract_dpop_jkt, extract_private_key_jwt, validate_dpop_proof, validate_dpop_proof_with_cache,
};

fn test_signer() -> LocalSigner {
    LocalSigner::from_secret("test", b"test-secret-for-unit-tests")
}

fn dpop_private_pem_and_jwk() -> (String, Jwk) {
    static KEY: OnceLock<(String, Jwk)> = OnceLock::new();
    KEY.get_or_init(|| {
        let generated = generate_es256("dpop-test-key").expect("DPoP key generation failed");
        (generated.private_pem, generated.public_jwk)
    })
    .clone()
}

/// Helper: base64url-encode a JSON value to produce a JWT segment.
fn b64_encode_json(val: &serde_json::Value) -> String {
    let json = serde_json::to_string(val).expect("serialization failed");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Build an unvalidated three-part JWT from header and payload JSON values.
fn build_jwt(header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let (private_pem, _) = dpop_private_pem_and_jwk();
    let Some(jwk_value) = header.get("jwk").cloned() else {
        return format!(
            "{}.{}.dummy_signature",
            b64_encode_json(header),
            b64_encode_json(payload)
        );
    };
    let Ok(jwk) = serde_json::from_value::<Jwk>(jwk_value) else {
        return format!(
            "{}.{}.dummy_signature",
            b64_encode_json(header),
            b64_encode_json(payload)
        );
    };
    let typ = header
        .get("typ")
        .and_then(|value| value.as_str())
        .unwrap_or("JWT");
    sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, typ, payload)
        .expect("DPoP proof signing failed")
}

fn dpop_header() -> serde_json::Value {
    let (_, jwk) = dpop_private_pem_and_jwk();
    serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(jwk).expect("JWK serialization failed"),
    })
}

fn private_key_jwt_header() -> serde_json::Value {
    let (_, jwk) = dpop_private_pem_and_jwk();
    serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": serde_json::to_value(jwk).expect("JWK serialization failed"),
    })
}

fn private_key_jwt_jwks() -> serde_json::Value {
    let (_, jwk) = dpop_private_pem_and_jwk();
    serde_json::json!({
        "keys": [serde_json::to_value(jwk).expect("JWK serialization failed")]
    })
}

#[derive(Default)]
struct MemoryRedisLikeTransport {
    values: BTreeMap<String, Vec<u8>>,
}

impl RedisLikeTransport for MemoryRedisLikeTransport {
    fn execute(
        &mut self,
        command: RedisLikeCommand,
    ) -> Result<Option<Vec<u8>>, qid_core::QidError> {
        match command {
            RedisLikeCommand::Get { key } => Ok(self.values.get(&key).cloned()),
            RedisLikeCommand::SetEx { key, value, .. } => {
                self.values.insert(key, value);
                Ok(None)
            }
            RedisLikeCommand::SetNxEx { key, value, .. } => {
                if let std::collections::btree_map::Entry::Vacant(entry) = self.values.entry(key) {
                    entry.insert(value);
                    Ok(Some(b"OK".to_vec()))
                } else {
                    Ok(None)
                }
            }
            RedisLikeCommand::Del { key } => {
                self.values.remove(&key);
                Ok(None)
            }
            RedisLikeCommand::Ping => Ok(Some(b"PONG".to_vec())),
        }
    }
}

fn dpop_cache() -> RedisLikeCache<MemoryRedisLikeTransport> {
    RedisLikeCache::new(
        CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: vec!["redis://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 120,
        },
        MemoryRedisLikeTransport::default(),
    )
    .unwrap()
}

// ── DPoP validation tests ──────────────────────────────────────────

#[test]
fn valid_dpop_proof_succeeds() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "unique-proof-id",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(
        result.is_ok(),
        "valid DPoP proof should succeed: {:?}",
        result
    );
    assert_eq!(result.unwrap(), "unique-proof-id");
}

#[test]
fn dpop_tampered_payload_signature_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "tampered-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let proof = build_jwt(&dpop_header(), &payload);
    let (header_and_payload, _signature) = proof
        .rsplit_once('.')
        .expect("proof should contain signature");
    let (header, _payload) = header_and_payload
        .split_once('.')
        .expect("proof should contain payload");
    let tampered_payload = serde_json::json!({
        "jti": "tampered-proof",
        "htm": "POST",
        "htu": "https://evil.example.com/token",
        "iat": now,
    });
    let tampered = format!(
        "{}.{}.{}",
        header,
        b64_encode_json(&tampered_payload),
        proof.rsplit_once('.').unwrap().1
    );
    let result = validate_dpop_proof(
        &DpopState::new(),
        &tampered,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "tampered DPoP proof should fail");
}

#[test]
fn dpop_wrong_htm_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "proof-2",
        "htm": "GET",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "wrong htm should fail");
}

#[test]
fn dpop_wrong_htu_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "proof-3",
        "htm": "POST",
        "htu": "https://evil.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "wrong htu should fail");
}

#[test]
fn dpop_missing_typ_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "proof-4",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = serde_json::json!({
        "alg": "ES256",
        "jwk": {"kty": "EC"},
    });
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "missing typ should fail");
}

#[test]
fn dpop_wrong_typ_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "proof-5",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": {"kty": "EC"},
    });
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "wrong typ should fail");
}

#[test]
fn dpop_missing_jwk_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "proof-6",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
    });
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "missing jwk should fail");
}

#[test]
fn dpop_missing_jti_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "missing jti should fail");
}

#[test]
fn dpop_iat_too_old_fails() {
    let signer = test_signer();
    let old_iat = qid_core::util::now_seconds() - 300; // 5 minutes ago
    let payload = serde_json::json!({
        "jti": "proof-old",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": old_iat,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "stale iat should fail");
}

#[test]
fn dpop_iat_in_future_fails() {
    let signer = test_signer();
    let future_iat = qid_core::util::now_seconds() + 120; // 2 minutes in the future
    let payload = serde_json::json!({
        "jti": "proof-future",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": future_iat,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let result = validate_dpop_proof(
        &DpopState::new(),
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "future iat should fail");
}

#[test]
fn dpop_replay_detected() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "replay-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);

    // First use should succeed
    let state = DpopState::new();
    let r1 = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(r1.is_ok(), "first use should succeed");

    // Second use with same jti should fail
    let r2 = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(r2.is_err(), "replay should be rejected");
}

#[test]
fn dpop_required_nonce_is_consumed_once() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let state = DpopState::new();
    let nonce = state.issue_nonce(now).unwrap();
    let payload = serde_json::json!({
        "jti": "nonce-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
        "nonce": nonce,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);

    let first = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        Some(&nonce),
        &signer,
    );
    assert!(first.is_ok(), "fresh nonce should succeed");

    let second = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        Some(&nonce),
        &signer,
    );
    assert!(second.is_err(), "nonce replay should be rejected");
}

#[test]
fn dpop_required_nonce_mismatch_fails() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let state = DpopState::new();
    let nonce = state.issue_nonce(now).unwrap();
    let payload = serde_json::json!({
        "jti": "nonce-mismatch-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
        "nonce": "other-nonce",
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);

    let result = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        Some(&nonce),
        &signer,
    );
    assert!(result.is_err(), "nonce mismatch should fail");
}

#[test]
fn dpop_replay_detected_with_external_cache() {
    let signer = test_signer();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "jti": "redis-replay-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);
    let mut cache = dpop_cache();

    let first = validate_dpop_proof_with_cache(
        &mut cache,
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(first.is_ok(), "first use should succeed");

    let second = validate_dpop_proof_with_cache(
        &mut cache,
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(second.is_err(), "external cache replay should be rejected");
}

#[test]
fn dpop_invalid_jwt_format_fails() {
    let signer = test_signer();
    let result = validate_dpop_proof(
        &DpopState::new(),
        "not-a-jwt",
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "invalid JWT should fail");
}

#[test]
fn dpop_invalid_base64_fails() {
    let signer = test_signer();
    let result = validate_dpop_proof(
        &DpopState::new(),
        "!!!.payload.sig",
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(result.is_err(), "invalid base64 should fail");
}

// ── extract_dpop_jkt tests ─────────────────────────────────────────

#[test]
fn extract_valid_dpop_header() {
    let token = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJhIn0.AAAA";
    let result = extract_dpop_jkt(token);
    assert!(result.is_ok(), "valid DPoP header should succeed");
    assert_eq!(result.unwrap(), token);
}

#[test]
fn extract_prefixed_dpop_header_rejected() {
    let token = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJhIn0.AAAA";
    let result = extract_dpop_jkt(&format!("DPoP {token}"));
    assert!(result.is_err(), "DPoP prefix is not RFC 9449 wire format");
}

#[test]
fn extract_dpop_header_empty_token() {
    let result = extract_dpop_jkt("DPoP ");
    assert!(result.is_err(), "empty token should fail");
}

#[test]
fn extract_dpop_header_no_space() {
    let result = extract_dpop_jkt("DPoPtoken");
    assert!(result.is_err(), "non-JWT proof should fail");
}

// ── private_key_jwt tests ──────────────────────────────────────────

#[test]
fn valid_private_key_jwt_succeeds() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
        "iat": now,
        "jti": "client-jti-1",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(
        result.is_ok(),
        "valid private_key_jwt should succeed: {:?}",
        result
    );
}

#[test]
fn private_key_jwt_wrong_iss_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "wrong-client",
        "sub": "wrong-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(result.is_err(), "wrong iss should fail");
}

#[test]
fn private_key_jwt_wrong_sub_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "other-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(result.is_err(), "wrong sub should fail");
}

#[test]
fn private_key_jwt_wrong_aud_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://evil.com/token",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(result.is_err(), "wrong aud should fail");
}

#[test]
fn private_key_jwt_expired_fails() {
    let old_exp = qid_core::util::now_seconds() - 10;
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": old_exp,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(result.is_err(), "expired assertion should fail");
}

#[test]
fn private_key_jwt_missing_iss_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(result.is_err(), "missing iss should fail");
}

#[test]
fn private_key_jwt_tampered_payload_signature_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let (header_and_payload, signature) = jwt
        .rsplit_once('.')
        .expect("client assertion should contain signature");
    let (header, _payload) = header_and_payload
        .split_once('.')
        .expect("client assertion should contain payload");
    let tampered_payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
        "scope": "admin",
    });
    let tampered = format!(
        "{header}.{}.{signature}",
        b64_encode_json(&tampered_payload)
    );
    let result = extract_private_key_jwt(
        &tampered,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &DpopState::new(),
    );
    assert!(
        result.is_err(),
        "tampered client assertion should fail signature validation"
    );
}

#[test]
fn private_key_jwt_jti_replay_detected() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com/token",
        "exp": now + 3600,
        "iat": now,
        "jti": "unique-client-jti",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);

    let state = DpopState::new();
    let r1 = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &state,
    );
    assert!(r1.is_ok(), "first use with fresh jti should succeed");

    let r2 = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com/token",
        &private_key_jwt_jwks(),
        &state,
    );
    assert!(
        r2.is_err(),
        "second use with same jti should fail (replay detected)"
    );
}

#[test]
fn dpop_nonce_concurrent_consumption_detected() {
    let now = qid_core::util::now_seconds();
    let state = DpopState::new();
    let nonce = state.issue_nonce(now).unwrap();
    let payload = serde_json::json!({
        "jti": "nonce-concurrent",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": now,
        "nonce": nonce,
    });
    let header = dpop_header();
    let proof = build_jwt(&header, &payload);

    let r1 = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        Some(&nonce),
        &test_signer(),
    );
    let r2 = validate_dpop_proof(
        &state,
        &proof,
        "POST",
        "https://id.example.com/token",
        Some(&nonce),
        &test_signer(),
    );

    assert!(r1.is_ok(), "first nonce consumption should succeed");
    assert!(r2.is_err(), "concurrent nonce replay must be rejected");
}
