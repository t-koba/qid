//! DPoP and private_key_jwt tests.

use axum::http::{HeaderMap, HeaderValue};
use base64::Engine;
use qid_core::cache::SharedCache;
use qid_core::dpop::DpopState;
use qid_core::error::QidError;
use qid_core::util::now_seconds;
use qid_crypto::{Jwk, LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};
use qid_ops::{
    CacheBackendConfig, CacheBackendKind, RedisLikeCache, RedisLikeCommand, RedisLikeTransport,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::{
    dpop_jkt_from_proof, extract_dpop_header, extract_dpop_jkt,
    extract_private_key_jwt_at as extract_private_key_jwt, validate_dpop_proof,
    validate_dpop_proof_with_cache,
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

/// Sign a JWT over the caller's exact header JSON text.
///
/// Unlike `build_jwt`, this preserves header members that `Jwk` does not model,
/// such as private key members in a proof's embedded JWK.
fn build_jwt_with_raw_header(header_json: &str, payload: &serde_json::Value) -> String {
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer},
        pkcs8::DecodePrivateKey,
    };
    let (private_pem, _) = dpop_private_pem_and_jwk();
    let signing_input = format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
        b64_encode_json(payload)
    );
    let signature: Signature = SigningKey::from_pkcs8_pem(&private_pem)
        .expect("test DPoP key should parse")
        .sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
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
struct RecordingReplayExpiry(Mutex<Option<u64>>);

impl RecordingReplayExpiry {
    fn record(&self, ttl_seconds: u64) {
        *self.0.lock().unwrap() = Some(now_seconds() + ttl_seconds);
    }

    fn assert_covers(&self, iat: u64) {
        let expires_at = self
            .0
            .lock()
            .unwrap()
            .expect("replay expiry was not recorded");
        assert!(
            expires_at > iat + 120,
            "replay expiry {expires_at} must cover the last accepted second {}",
            iat + 120
        );
    }
}

impl SharedCache for RecordingReplayExpiry {
    fn get(&self, _: &str) -> Option<Vec<u8>> {
        unreachable!()
    }

    fn set(&self, _: &str, _: Vec<u8>, _: u64) {
        unreachable!()
    }

    fn set_if_absent(&self, _: &str, _: Vec<u8>, ttl_seconds: u64) -> qid_core::QidResult<bool> {
        self.record(ttl_seconds);
        Ok(true)
    }

    fn delete(&self, _: &str) {
        unreachable!()
    }
}

struct MemoryRedisLikeTransport {
    values: BTreeMap<String, Vec<u8>>,
    replay_expiry: Arc<RecordingReplayExpiry>,
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
            RedisLikeCommand::SetNxEx {
                key,
                value,
                ttl_seconds,
            } => {
                if let std::collections::btree_map::Entry::Vacant(entry) = self.values.entry(key) {
                    entry.insert(value);
                    self.replay_expiry.record(ttl_seconds);
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

fn dpop_cache(
    replay_expiry: Arc<RecordingReplayExpiry>,
) -> RedisLikeCache<MemoryRedisLikeTransport> {
    RedisLikeCache::new(
        CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: vec!["redis://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 120,
        },
        MemoryRedisLikeTransport {
            values: BTreeMap::new(),
            replay_expiry,
        },
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
fn dpop_proof_with_private_jwk_members_is_rejected() {
    let signer = test_signer();
    let htu = "https://id.example.com/token";
    let payload = serde_json::json!({
        "jti": "private-jwk-proof",
        "htm": "POST",
        "htu": htu,
        "iat": now_seconds(),
    });
    let public_header = dpop_header();
    let public_header_json =
        serde_json::to_string(&public_header).expect("header serialization failed");

    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut header = public_header.clone();
        header["jwk"][member] = serde_json::json!("private-material");
        let proof = build_jwt_with_raw_header(
            &serde_json::to_string(&header).expect("header serialization failed"),
            &payload,
        );
        assert!(
            matches!(
                validate_dpop_proof(&DpopState::new(), &proof, "POST", htu, None, &signer),
                Err(QidError::BadRequest { .. })
            ),
            "jwk member {member} must be rejected"
        );
        assert!(
            matches!(
                dpop_jkt_from_proof(&proof),
                Err(QidError::BadRequest { .. })
            ),
            "jkt extraction must reject jwk member {member}"
        );
    }

    // An escaped JSON member name still decodes to a forbidden member.
    let escaped_header =
        public_header_json.replace("\"kid\":", "\"\\u0064\":\"private-material\",\"kid\":");
    assert_ne!(
        escaped_header, public_header_json,
        "escaped member was not inserted"
    );
    let escaped_proof = build_jwt_with_raw_header(&escaped_header, &payload);
    assert!(matches!(
        validate_dpop_proof(
            &DpopState::new(),
            &escaped_proof,
            "POST",
            htu,
            None,
            &signer
        ),
        Err(QidError::BadRequest { .. })
    ));
    assert!(matches!(
        dpop_jkt_from_proof(&escaped_proof),
        Err(QidError::BadRequest { .. })
    ));

    // A public-only JWK remains usable on both paths.
    let public_proof = build_jwt(&public_header, &payload);
    assert_eq!(
        validate_dpop_proof(&DpopState::new(), &public_proof, "POST", htu, None, &signer).unwrap(),
        "private-jwk-proof"
    );
    assert!(dpop_jkt_from_proof(&public_proof).is_ok());
}

#[test]
fn dpop_proof_with_jwk_key_type_mismatching_alg_is_rejected() {
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer},
        pkcs8::DecodePrivateKey,
    };
    let signer = test_signer();
    let htu = "https://id.example.com/token";
    let payload = serde_json::json!({
        "jti": "mixed-kty-proof",
        "htm": "POST",
        "htu": htu,
        "iat": now_seconds(),
    });

    // The attacker signs with their own P-256 key but presents an RSA-looking
    // JWK carrying the victim's n/e and the attacker's x/y. The token jkt comes
    // from kty members (n/e), while signature verification uses alg members
    // (x/y), so the two can disagree without an explicit kty/alg check.
    let attacker = generate_es256("attacker-dpop-key").expect("DPoP key generation failed");
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "RSA",
            "n": "victim-rsa-modulus",
            "e": "AQAB",
            "x": attacker.public_jwk.x,
            "y": attacker.public_jwk.y,
            "alg": "ES256",
        },
    });
    let input = format!("{}.{}", b64_encode_json(&header), b64_encode_json(&payload));
    let signature: Signature = SigningKey::from_pkcs8_pem(&attacker.private_pem)
        .unwrap()
        .sign(input.as_bytes());
    let mixed_proof = format!(
        "{input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );

    // The thumbprint follows the RSA kty members, not the signing key.
    let presented_jkt = dpop_jkt_from_proof(&mixed_proof).unwrap();
    let genuine_jkt = dpop_jkt_from_proof(&build_jwt(&dpop_header(), &payload)).unwrap();
    assert_ne!(
        presented_jkt, genuine_jkt,
        "mixed JWK must present a thumbprint derived from the RSA kty members"
    );

    let result = validate_dpop_proof(&DpopState::new(), &mixed_proof, "POST", htu, None, &signer);
    assert!(
        result.is_err(),
        "JWK with kty mismatch must be rejected even when its signature verifies: {:?}",
        result
    );
}

#[test]
fn dpop_replay_expiry_covers_fresh_and_future_dated_proofs() {
    let signer = test_signer();
    let header = dpop_header();
    let htu = "https://id.example.com/token";
    for skew in [0, 60] {
        let cache = Arc::new(RecordingReplayExpiry::default());
        let state = DpopState::with_cache(cache.clone());
        let iat = now_seconds() + skew;
        let proof = build_jwt(
            &header,
            &serde_json::json!({"jti": "replay-window", "htm": "POST", "htu": htu, "iat": iat}),
        );

        validate_dpop_proof(&state, &proof, "POST", htu, None, &signer).unwrap();
        cache.assert_covers(iat);
    }
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

/// Validate a signed proof against the expected HTTP URI provided by the caller.
fn htu_is_accepted_against(htu: &str, expected: &str) -> bool {
    let signer = test_signer();
    let payload = serde_json::json!({
        "jti": "htu-normalization-proof",
        "htm": "POST",
        "htu": htu,
        "iat": now_seconds(),
    });
    let proof = build_jwt(&dpop_header(), &payload);
    validate_dpop_proof(&DpopState::new(), &proof, "POST", expected, None, &signer).is_ok()
}

/// Validate a signed proof whose only varying claim is `htu`.
fn htu_is_accepted(htu: &str) -> bool {
    htu_is_accepted_against(htu, "https://id.example.com/token")
}

#[test]
fn dpop_htu_normalization_is_accepted() {
    for htu in [
        "https://ID.EXAMPLE.COM/token",
        "https://id.example.com:443/token",
        "https://id.example.com/token?client=one",
        "https://id.example.com/token#section",
    ] {
        assert!(htu_is_accepted(htu), "normalized htu should match: {htu}");
    }
}

#[test]
fn dpop_htu_mismatches_are_rejected() {
    for htu in [
        "https://other.example.com/token",
        "https://id.example.com/token/extra",
        "https://id.example.com/token/",
        "https://id.example.com:8443/token",
        "http://id.example.com/token",
        "ftp://id.example.com/token",
        "not a url",
    ] {
        assert!(!htu_is_accepted(htu), "mismatched htu must fail: {htu}");
    }
}

#[test]
fn dpop_htu_percent_encoding_normalization_is_accepted() {
    for (htu, expected) in [
        (
            "https://id.example.com/to%6ben",
            "https://id.example.com/token",
        ),
        (
            "https://id.example.com/%7Efoo",
            "https://id.example.com/~foo",
        ),
        (
            "https://id.example.com/a/%2E%2E/token",
            "https://id.example.com/token",
        ),
        (
            "https://id.example.com/%2e/token",
            "https://id.example.com/token",
        ),
        (
            "https://id.example.com/x/%2f/y",
            "https://id.example.com/x/%2F/y",
        ),
        (
            "https://id.example.com/x/%3a/y",
            "https://id.example.com/x/%3A/y",
        ),
    ] {
        assert!(
            htu_is_accepted_against(htu, expected),
            "normalized htu should match: {htu} vs {expected}"
        );
    }
}

#[test]
fn dpop_htu_reserved_escapes_are_not_literal_separators() {
    for (htu, expected) in [
        ("https://id.example.com/a%2Fb", "https://id.example.com/a/b"),
        ("https://id.example.com/a%3Ab", "https://id.example.com/a:b"),
    ] {
        assert!(
            !htu_is_accepted_against(htu, expected),
            "reserved escape must not match literal separator: {htu} vs {expected}"
        );
    }
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
    let header = dpop_header();
    let iat = now_seconds() + 60;
    let payload = serde_json::json!({
        "jti": "redis-replay-proof",
        "htm": "POST",
        "htu": "https://id.example.com/token",
        "iat": iat,
    });
    let proof = build_jwt(&header, &payload);
    let replay_expiry = Arc::new(RecordingReplayExpiry::default());
    let mut cache = dpop_cache(replay_expiry.clone());

    let first = validate_dpop_proof_with_cache(
        &mut cache,
        &proof,
        "POST",
        "https://id.example.com/token",
        None,
        &signer,
    );
    assert!(first.is_ok(), "first use should succeed");
    replay_expiry.assert_covers(iat);

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
        "aud": "https://id.example.com",
        "exp": now + 3600,
        "iat": now,
        "jti": "client-jti-1",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
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
        "aud": "https://id.example.com",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
    );
    assert!(result.is_err(), "wrong iss should fail");
}

#[test]
fn private_key_jwt_wrong_sub_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "other-client",
        "aud": "https://id.example.com",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
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
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
    );
    assert!(result.is_err(), "wrong aud should fail");
}

#[test]
fn private_key_jwt_expired_fails() {
    let now = qid_core::util::now_seconds();
    let old_exp = now - 10;
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com",
        "exp": old_exp,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
    );
    assert!(result.is_err(), "expired assertion should fail");
}

#[test]
fn private_key_jwt_missing_iss_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "sub": "my-client",
        "aud": "https://id.example.com",
        "exp": now + 3600,
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
    );
    assert!(result.is_err(), "missing iss should fail");
}

#[test]
fn private_key_jwt_tampered_payload_signature_fails() {
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com",
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
        "aud": "https://id.example.com",
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
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        now,
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
        "aud": "https://id.example.com",
        "exp": now + 3600,
        "iat": now,
        "jti": "unique-client-jti",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);

    let state = DpopState::new();
    let r1 = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &state,
        now,
    );
    assert!(r1.is_ok(), "first use with fresh jti should succeed");

    let r2 = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &state,
        now,
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

#[test]
fn private_key_jwt_replay_lives_until_verified_exp() {
    use qid_core::cache::{MemoryCache, SharedCache};
    use std::sync::{Arc, Mutex};

    struct TtlRecordingCache {
        inner: MemoryCache,
        ttls: Mutex<Vec<(String, u64)>>,
    }

    impl TtlRecordingCache {
        fn new() -> Self {
            Self {
                inner: MemoryCache::new(),
                ttls: Mutex::new(Vec::new()),
            }
        }
    }

    impl SharedCache for TtlRecordingCache {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get(key)
        }

        fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
            self.inner.set(key, value, ttl_seconds);
        }

        fn set_if_absent(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl_seconds: u64,
        ) -> qid_core::error::QidResult<bool> {
            self.ttls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((key.to_string(), ttl_seconds));
            self.inner.set_if_absent(key, value, ttl_seconds)
        }

        fn delete(&self, key: &str) {
            self.inner.delete(key);
        }

        fn take(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.take(key)
        }
    }

    const T: u64 = 1_700_000_000;
    const EXP: u64 = T + 3600;
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com",
        "exp": EXP,
        "iat": T,
        "jti": "exp-scoped-jti-1",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let cache = Arc::new(TtlRecordingCache::new());
    let state = DpopState::assertion_replay(cache.clone());

    let first = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &state,
        T,
    );
    assert!(first.is_ok(), "first use at T should succeed: {first:?}");
    // Replay TTL must cover the verified exp, not the 60s DPoP window.
    let ttls = cache.ttls.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(ttls.len(), 1, "expected one replay entry, got {ttls:?}");
    assert_eq!(
        ttls[0].1, 3600,
        "replay TTL must equal exp-now, got {ttls:?}"
    );
    drop(ttls);

    let replay = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &state,
        T + 61,
    );
    assert!(replay.is_err(), "replay at T+61 must fail");
    assert!(
        replay.unwrap_err().message().contains("already used"),
        "replay error must be protocol-appropriate"
    );

    let other_payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com",
        "exp": EXP,
        "iat": T,
        "jti": "exp-scoped-jti-2",
    });
    let other_jwt = build_jwt(&private_key_jwt_header(), &other_payload);
    let other = extract_private_key_jwt(
        &other_jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &state,
        T + 61,
    );
    assert!(
        other.is_ok(),
        "distinct JTI at T+61 should succeed: {other:?}"
    );
}

#[test]
fn private_key_jwt_rejects_exp_at_now_boundary() {
    const T: u64 = 1_700_000_000;
    let payload = serde_json::json!({
        "iss": "my-client",
        "sub": "my-client",
        "aud": "https://id.example.com",
        "exp": T,
        "iat": T,
        "jti": "boundary-jti",
    });
    let jwt = build_jwt(&private_key_jwt_header(), &payload);
    let result = extract_private_key_jwt(
        &jwt,
        "my-client",
        "https://id.example.com",
        &private_key_jwt_jwks(),
        &DpopState::new(),
        T,
    );
    assert!(result.is_err(), "exp == now must be rejected");
}

#[test]
fn private_key_jwt_accepts_only_one_exact_issuer_audience() {
    let now = qid_core::util::now_seconds();
    for (aud, expected) in [
        (serde_json::json!("https://id.example.com"), true),
        (serde_json::json!(["https://id.example.com"]), true),
        (serde_json::json!([]), false),
        (serde_json::json!([1]), false),
        (
            serde_json::json!(["https://id.example.com", "https://other.example.com"]),
            false,
        ),
        (serde_json::json!("https://id.example.com/token"), false),
        (serde_json::Value::Null, false),
    ] {
        let payload = serde_json::json!({"iss":"my-client", "sub":"my-client", "aud":aud, "exp":now+60, "jti":"aud-test"});
        let jwt = build_jwt(&private_key_jwt_header(), &payload);
        let result = extract_private_key_jwt(
            &jwt,
            "my-client",
            "https://id.example.com",
            &private_key_jwt_jwks(),
            &DpopState::new(),
            now,
        );
        assert_eq!(result.is_ok(), expected, "aud={aud}");
    }
}

#[test]
fn non_utf8_dpop_header_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert("dpop", HeaderValue::from_bytes(&[0xff]).unwrap());
    assert!(matches!(
        extract_dpop_header(&headers),
        Err(QidError::BadRequest { .. })
    ));
}
