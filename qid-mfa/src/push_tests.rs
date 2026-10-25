use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use qid_core::{models::*, util::now_seconds};
use qid_storage::{FileRepository, SqlRepository, prelude::*};

fn fixture() -> (SigningKey, PushRegistrationChallenge, String) {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let nonce = URL_SAFE_NO_PAD.encode([11; 32]);
    let now = now_seconds();
    let c = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "device".into(),
            realm_id: "realm".into(),
            user_id: "owner".into(),
            destination: "provider-destination".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::EC {
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            },
            created_at: now,
            revoked_at: None,
        },
        nonce_verifier: sha256_hex(&nonce),
        expires_at: now + 300,
        max_attempts: 2,
        attempt_count: 0,
    };
    (key, c, nonce)
}
fn login(c: &PushRegistrationChallenge, nonce: &str) -> PushLoginChallenge {
    PushLoginChallenge {
        id: "login".into(),
        realm_id: c.authenticator.realm_id.clone(),
        user_id: c.authenticator.user_id.clone(),
        authenticator_id: c.authenticator.id.clone(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: sha256_hex(nonce),
        browser_binding_verifier: sha256_hex("browser-secret"),
        resend_admitted_at: Vec::new(),
        created_at: c.authenticator.created_at,
        expires_at: c.expires_at,
        max_attempts: 2,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    }
}
// Independent signer: standard four-element Sig_structure, raw protected bytes.
fn sign_headers(
    key: &SigningKey,
    payload: Vec<u8>,
    protected: Vec<u8>,
    unprotected: Value,
) -> Vec<u8> {
    let mut signed = Vec::new();
    ciborium::into_writer(
        &(
            "Signature1",
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.clone()),
        ),
        &mut signed,
    )
    .unwrap();
    let signature: Signature = key.sign(&signed);
    encode(&Value::Array(vec![
        Value::Bytes(protected),
        unprotected,
        Value::Bytes(payload),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap()
}
fn sign(key: &SigningKey, payload: Vec<u8>) -> Vec<u8> {
    sign_headers(key, payload, vec![0xa1, 1, 0x26], Value::Map(vec![]))
}

#[test]
fn strict_headers_reject_even_correctly_signed_downgrades() {
    let (key, c, nonce) = fixture();
    let payload = registration_payload(&c, &nonce).unwrap();
    assert!(verify_registration(&c, &nonce, &sign(&key, payload.clone())).is_ok());
    let alg = (Value::Integer(1.into()), Value::Integer((-7).into()));
    let bad_headers = [
        Value::Map(vec![]),                                          // missing
        Value::Map(vec![alg.clone(), alg.clone()]),                  // duplicate
        Value::Map(vec![(Value::Integer(1.into()), text("ES256"))]), // malformed
        Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-8).into()),
        )]),
        Value::Map(vec![(text("alg"), Value::Integer((-7).into()))]),
        Value::Map(vec![
            alg.clone(),
            (Value::Integer(2.into()), Value::Array(vec![])),
        ]), // unsupported critical
        Value::Null,
    ];
    for headers in bad_headers {
        let proof = sign_headers(
            &key,
            payload.clone(),
            encode(&headers).unwrap(),
            Value::Map(vec![]),
        );
        assert!(verify_registration(&c, &nonce, &proof).is_err());
    }
    for protected in [vec![], vec![0xa1, 1, 0x26, 0], vec![0xff]] {
        let proof = sign_headers(&key, payload.clone(), protected, Value::Map(vec![]));
        assert!(verify_registration(&c, &nonce, &proof).is_err());
    }
    for protected in [vec![0xa0], vec![0xa1, 1, 0x26]] {
        let proof = sign_headers(
            &key,
            payload.clone(),
            protected,
            Value::Map(vec![alg.clone()]),
        );
        assert!(verify_registration(&c, &nonce, &proof).is_err());
    }
    let valid = sign(&key, payload);
    let mut trailing = valid.clone();
    trailing.push(0);
    for proof in [
        vec![],
        vec![0; MAX_PROOF_BYTES + 1],
        trailing,
        valid[..valid.len() - 1].to_vec(),
        encode(&Value::Tag(18, Box::new(decode(&valid).unwrap()))).unwrap(),
    ] {
        assert!(verify_registration(&c, &nonce, &proof).is_err());
    }
}

#[test]
fn jwk_validation_rejects_wrong_curve_bad_coordinates_and_wrong_key() {
    let (key, c, nonce) = fixture();
    assert!(validate_public_key(&c.authenticator.public_jwk).is_ok());
    let PushPublicJwk::EC { x, y, .. } = &c.authenticator.public_jwk else {
        unreachable!()
    };
    let keys = [
        PushPublicJwk::OKP {
            crv: "Ed25519".into(),
            x: x.clone(),
        },
        PushPublicJwk::RSA {
            n: "n".into(),
            e: "AQAB".into(),
        },
        PushPublicJwk::EC {
            crv: "P-384".into(),
            x: x.clone(),
            y: y.clone(),
        },
        PushPublicJwk::EC {
            crv: "P-256".into(),
            x: format!("{x}="),
            y: y.clone(),
        },
        PushPublicJwk::EC {
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode([0; 32]),
            y: URL_SAFE_NO_PAD.encode([0; 32]),
        },
        PushPublicJwk::EC {
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode([1; 31]),
            y: y.clone(),
        },
    ];
    for jwk in keys {
        assert!(validate_public_key(&jwk).is_err());
    }
    let wrong_key = SigningKey::from_slice(&[8; 32]).unwrap();
    assert!(
        verify_registration(
            &c,
            &nonce,
            &sign(&wrong_key, registration_payload(&c, &nonce).unwrap())
        )
        .is_err()
    );
    let mut proof = sign(&key, registration_payload(&c, &nonce).unwrap());
    *proof.last_mut().unwrap() ^= 1;
    assert!(verify_registration(&c, &nonce, &proof).is_err());
}

#[test]
fn claims_bind_owner_destination_transaction_nonce_purpose_and_decision() {
    let (key, c, nonce) = fixture();
    let proof = sign(&key, registration_payload(&c, &nonce).unwrap());
    for field in 0..5 {
        let mut changed = c.clone();
        match field {
            0 => changed.authenticator.realm_id.push('x'),
            1 => changed.authenticator.user_id.push('x'),
            2 => changed.authenticator.id.push('x'),
            3 => changed.authenticator.destination.push('x'),
            _ => changed.nonce_verifier = "0".repeat(64),
        }
        assert!(verify_registration(&changed, &nonce, &proof).is_err());
    }
    assert!(verify_registration(&c, &URL_SAFE_NO_PAD.encode([12; 32]), &proof).is_err());
    let l = login(&c, &nonce);
    assert!(verify_login(&l, &c.authenticator, &nonce, PushDecision::Approve, &proof).is_err());
    let approve = sign(
        &key,
        login_payload(&l, &nonce, PushDecision::Approve).unwrap(),
    );
    assert!(
        verify_login(
            &l,
            &c.authenticator,
            &nonce,
            PushDecision::Approve,
            &approve
        )
        .is_ok()
    );
    assert!(verify_login(&l, &c.authenticator, &nonce, PushDecision::Deny, &approve).is_err());
    for field in 0..5 {
        let mut changed = l.clone();
        match field {
            0 => changed.realm_id.push('x'),
            1 => changed.user_id.push('x'),
            2 => changed.authenticator_id.push('x'),
            3 => changed.id.push('x'),
            _ => changed.nonce_verifier = "0".repeat(64),
        }
        assert!(
            verify_login(
                &changed,
                &c.authenticator,
                &nonce,
                PushDecision::Approve,
                &approve
            )
            .is_err()
        );
    }
    let mut revoked = c.authenticator.clone();
    revoked.revoked_at = Some(now_seconds());
    assert!(verify_login(&l, &revoked, &nonce, PushDecision::Approve, &approve).is_err());
}

/// Signed proof + atomic storage contract, NOT HTTP/session integration.
async fn proof_storage_flow(repo: &impl Repository) {
    repo.create_realm(
        &"tenant".into(),
        &"realm".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "owner".into(),
        realm_id: "realm".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let (key, c, nonce) = fixture();
    assert!(
        repo.try_issue_push_registration(&c, 10, 3600)
            .await
            .unwrap()
    );
    // Delivery acceptance is not proof; pending state is not an authenticator.
    assert!(
        repo.get_push_authenticator(&"realm".into(), "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    let registration = sign(&key, registration_payload(&c, &nonce).unwrap());
    let verified = verify_registration(&c, &nonce, &registration).is_ok();
    assert!(verified);
    assert!(
        repo.attempt_push_registration(&c, verified, now_seconds())
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_registration(&c, verified, now_seconds())
            .await
            .unwrap()
    );
    let a = repo
        .get_push_authenticator(&"realm".into(), "owner", "device")
        .await
        .unwrap()
        .unwrap();
    // Enrollment resets created_at. Bind the login record to the durable row,
    // not to the earlier pending registration timestamp (which may cross a
    // wall-clock second boundary during this test).
    let mut l = login(&c, &nonce);
    l.created_at = a.created_at;
    assert!(repo.try_issue_push_login(&l, 10, 3600).await.unwrap());
    // Even a delivered prompt plus the correct browser secret is not approval.
    assert!(
        !repo
            .redeem_push_login(&l, &sha256_hex("browser-secret"), now_seconds())
            .await
            .unwrap()
    );
    assert!(
        repo.get_push_login(&"other".into(), "owner", &l.id)
            .await
            .unwrap()
            .is_none()
    );
    let approve = sign(
        &key,
        login_payload(&l, &nonce, PushDecision::Approve).unwrap(),
    );
    assert!(verify_login(&l, &a, &nonce, PushDecision::Approve, &approve).is_ok());
    assert!(
        repo.attempt_push_login(&l, Some(PushDecision::Approve), now_seconds())
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&l, Some(PushDecision::Approve), now_seconds())
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&l, &sha256_hex("other-browser"), now_seconds())
            .await
            .unwrap()
    );
    let (one, two) = tokio::join!(
        repo.redeem_push_login(&l, &l.browser_binding_verifier, now_seconds()),
        repo.redeem_push_login(&l, &l.browser_binding_verifier, now_seconds())
    );
    assert_ne!(one.unwrap(), two.unwrap());
    for id in ["exhausted", "expired", "denied", "revoked"] {
        let mut pending = l.clone();
        pending.id = id.into();
        assert!(repo.try_issue_push_login(&pending, 10, 3600).await.unwrap());
        let deny = sign(
            &key,
            login_payload(&pending, &nonce, PushDecision::Deny).unwrap(),
        );
        assert!(verify_login(&pending, &a, &nonce, PushDecision::Deny, &deny).is_ok());
        if id == "exhausted" {
            for _ in 0..pending.max_attempts {
                // Malformed signatures still spend attempts, never approve.
                let verified =
                    verify_login(&pending, &a, &nonce, PushDecision::Approve, b"receipt").is_ok();
                assert!(!verified);
                assert!(
                    repo.attempt_push_login(
                        &pending,
                        verified.then_some(PushDecision::Approve),
                        now_seconds()
                    )
                    .await
                    .unwrap()
                );
            }
            assert!(
                !repo
                    .attempt_push_login(&pending, Some(PushDecision::Approve), now_seconds())
                    .await
                    .unwrap()
            );
        } else if id == "expired" {
            assert!(
                !repo
                    .attempt_push_login(&pending, Some(PushDecision::Approve), pending.expires_at)
                    .await
                    .unwrap()
            );
        } else if id == "denied" {
            assert!(
                repo.attempt_push_login(&pending, Some(PushDecision::Deny), now_seconds())
                    .await
                    .unwrap()
            );
        } else {
            assert!(
                repo.revoke_push_authenticator(&"realm".into(), "owner", &a.id, now_seconds())
                    .await
                    .unwrap()
            );
            assert!(
                !repo
                    .attempt_push_login(&pending, Some(PushDecision::Approve), now_seconds())
                    .await
                    .unwrap()
            );
        }
        if id != "expired" {
            assert!(
                !repo
                    .redeem_push_login(&pending, &pending.browser_binding_verifier, now_seconds())
                    .await
                    .unwrap()
            );
        }
        assert!(
            !repo
                .redeem_push_login(
                    &pending,
                    &pending.browser_binding_verifier,
                    pending.expires_at
                )
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn signed_proof_storage_flow_file() {
    let path = std::env::temp_dir().join(format!(
        "qid-push-proof-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&path).unwrap();
    let repo = FileRepository::new(path.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    proof_storage_flow(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(path).unwrap();
}
#[tokio::test]
async fn signed_proof_storage_flow_sqlite() {
    let path = std::env::temp_dir().join(format!(
        "qid-push-proof-sql-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&path).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", path.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    proof_storage_flow(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn smallest_registration_proof_fits_the_minimum_configured_limit() {
    let (key, mut c, nonce) = fixture();
    c.authenticator.id = "i".into();
    c.authenticator.realm_id = "r".into();
    c.authenticator.user_id = "u".into();
    c.authenticator.destination = "d".into();
    let proof = sign(&key, registration_payload(&c, &nonce).unwrap());
    assert!(proof.len() > 128);
    assert!(proof.len() <= 256, "proof bytes: {}", proof.len());
}

#[test]
fn bounded_inputs_and_secret_errors() {
    let (key, c, nonce) = fixture();
    let proof = sign(&key, registration_payload(&c, &nonce).unwrap());
    let error = verify_registration(&c, "bad-nonce", &proof)
        .unwrap_err()
        .to_string();
    assert!(!error.contains(&nonce));
    assert!(!error.contains(&c.authenticator.destination));
    for size in [0, 257] {
        let mut changed = c.clone();
        changed.authenticator.id = "x".repeat(size);
        assert!(registration_payload(&changed, &nonce).is_err());
    }
    let mut changed = c.clone();
    changed.authenticator.destination = "x".repeat(4097);
    assert!(registration_payload(&changed, &nonce).is_err());
    // The CBOR decoder has its own finite nesting limit as well as the byte cap.
    let nested = [vec![0x81; 512], vec![0xf6]].concat();
    assert!(verify_registration(&c, &nonce, &nested).is_err());
}

#[test]
fn rfc_9052_appendix_c_single_sign1_vector_verifies() {
    // RFC 9052 Appendix C.2.1 and C.7.1, kid "11". The profile here requires
    // untagged Sign1 and empty unprotected headers, so omit only the optional
    // tag and unsigned kid; protected bytes, payload, public key and signature
    // remain the RFC vector unchanged.
    let jwk = PushPublicJwk::EC {
        crv: "P-256".into(),
        x: "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8".into(),
        y: "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4".into(),
    };
    let proof = encode(&Value::Array(vec![
        Value::Bytes(vec![0xa1, 0x01, 0x26]),
        Value::Map(vec![]),
        Value::Bytes(b"This is the content.".to_vec()),
        Value::Bytes(
            URL_SAFE_NO_PAD
                .decode("jrM-TKMdHEZasFqsNMxrI9WP71wIMQbE0lqRrvCwEX4q-aKRqjLhSrg03FbtKiI0RFR-AfEdOwkW5aTDRcrLNg")
                .unwrap(),
        ),
    ]))
    .unwrap();
    verify(&jwk, b"This is the content.", &proof).unwrap();
}
