use super::*;
const START: &str = "/api/v1/corp/auth/password/push/registrations/start";
const FINISH: &str = "/api/v1/corp/auth/password/push/registrations/finish";
const REVOKE: &str = "/api/v1/corp/auth/password/push/registrations/revoke";
const DEST: &str = "private-account-device-destination";

fn start_body(key: &signature::EcdsaKeyPair) -> JsonValue {
    let p = key.public_key().as_ref();
    json!({"destination": DEST, "device_name": "Test Phone",
        "device_platform": "android", "public_jwk": {
        "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(&p[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&p[33..]),
    }})
}
async fn password_cookie(f: &Fixture) -> String {
    let response = login(f).await;
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}
async fn session(f: &Fixture, user: &str, realm: &str, amr: &[&str], age: u64) -> String {
    // Trusted persisted sessions, not request AMR. Password bootstrap and TOTP
    // positive paths below also exercise actual authentication endpoints.
    if realm != "corp"
        && f.state
            .repo
            .get_realm_issuer(&realm.into())
            .await
            .unwrap()
            .is_none()
    {
        f.state
            .repo
            .create_realm(
                &"tenant-1".into(),
                &realm.into(),
                "https://other.example.com",
                None,
            )
            .await
            .unwrap();
    }
    if f.state.repo.get_user_by_id(user).await.unwrap().is_none() {
        f.state
            .repo
            .create_user(&User {
                id: user.into(),
                realm_id: realm.into(),
                email: None,
                email_verified: false,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
    }
    let now = util::now_seconds();
    let sid = format!("sid_{}", ulid::Ulid::new());
    f.state
        .repo
        .create_session(&Session {
            id: sid.clone(),
            user_id: user.into(),
            realm_id: realm.into(),
            auth_time: now - age,
            acr: Some("untrusted-acr-is-not-enough".into()),
            amr: amr.iter().map(|s| s.to_string()).collect(),
            idle_expires_at: now + 1000,
            absolute_expires_at: now + 2000,
            revoked: false,
            created_at: now - age,
            cnf: None,
        })
        .await
        .unwrap();
    format!(
        "{}={sid}",
        f.state.plan.realms[0].browser_session.cookie_name
    )
}
async fn configure_email_magic_link(f: &mut Fixture, enabled: bool) {
    let mut config = f.state.config.clone();
    config.realms[0].authentication.email_magic_link.enabled = enabled;
    let state = SharedState::new(
        config,
        f.state.repo.clone(),
        f.state.signer.clone(),
        f.state.jwks.clone(),
    )
    .unwrap()
    .with_notification_transport(f.delivery.clone());
    f.state = Arc::new(state);
    f.app = qid_session::auth_routes(&f.state.paths).with_state(f.state.clone());
}

async fn begin(
    f: &Fixture,
    cookie: &str,
    key: &signature::EcdsaKeyPair,
) -> (PushRegistrationChallenge, String) {
    let response = post(f, START, Some(cookie), start_body(key)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let json = body(response).await;
    assert_eq!(json.as_object().unwrap().len(), 2);
    let id = json["registration_id"].as_str().unwrap();
    let c = f
        .state
        .repo
        .get_push_registration(&"corp".into(), "user-1", id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        f.state
            .repo
            .get_push_authenticator(&"corp".into(), "user-1", id)
            .await
            .unwrap()
            .is_none()
    );
    let delivery = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(delivery.channel, NotificationChannel::Push);
    assert_eq!(delivery.recipient, DEST);
    assert_eq!(delivery.data_json["registration_id"], id);
    assert_eq!(delivery.data_json["purpose"], "registration");
    let nonce = delivery.data_json["nonce"].as_str().unwrap().to_owned();
    assert!(!json.to_string().contains(DEST));
    assert!(!json.to_string().contains(&nonce));
    assert_eq!(c.nonce_verifier, util::sha256_hex(nonce.as_bytes()));
    (c, nonce)
}
fn finish_body(
    c: &PushRegistrationChallenge,
    nonce: &str,
    key: &signature::EcdsaKeyPair,
) -> JsonValue {
    json!({"registration_id": c.authenticator.id, "nonce": nonce,
        "proof": URL_SAFE_NO_PAD.encode(sign(key, qid_mfa::push::registration_payload(c, nonce).unwrap()))})
}
async fn rejected(response: Response, nonce: Option<&str>) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    for secret in [
        DEST,
        "sensitive provider diagnostic",
        nonce.unwrap_or("must-not-be-present"),
    ] {
        assert!(!text.contains(secret), "secret in response");
    }
}
async fn attempts(f: &Fixture, c: &PushRegistrationChallenge) -> u32 {
    f.state
        .repo
        .get_push_registration(&"corp".into(), "user-1", &c.authenticator.id)
        .await
        .unwrap()
        .unwrap()
        .attempt_count
}
async fn totp(f: &Fixture, enabled: bool) {
    f.state
        .repo
        .store_totp_credential(&TotpCredential {
            id: "totp".into(),
            user_id: "user-1".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            enabled,
            last_used_step: None,
            created_at: util::now_seconds() - 1000,
        })
        .await
        .unwrap();
}
async fn passkey(f: &Fixture) {
    f.state
        .repo
        .store_webauthn_credential(&WebAuthnCredential {
            id: "passkey".into(),
            user_id: "user-1".into(),
            credential_id: vec![1],
            public_key: vec![2],
            counter: 0,
            aaguid: vec![],
            device_name: None,
            created_at: util::now_seconds() - 1000,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn password_bootstrap_activates_only_after_device_proof_then_requires_push() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    let req = finish_body(&c, &nonce, &key);
    assert_eq!(
        post(&f, FINISH, Some(&cookie), req.clone()).await.status(),
        StatusCode::NO_CONTENT
    );
    let a = f
        .state
        .repo
        .get_push_authenticator(&"corp".into(), "user-1", &c.authenticator.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.destination, DEST);
    assert!(a.revoked_at.is_none());
    assert!(!format!("{a:?}").contains(DEST));
    assert!(!format!("{c:?}").contains(&nonce));
    // Replay cannot activate again. The newly enrolled factor also prevents the
    // old password-only session enrolling another device.
    rejected(post(&f, FINISH, Some(&cookie), req).await, Some(&nonce)).await;
    rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    assert_eq!(login(&f).await.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn start_requires_active_recent_same_realm_account_authentication() {
    let f = fixture(true, true, false).await;
    let key = device_key();
    rejected(post(&f, START, None, start_body(&key)).await, None).await;
    for (methods, age, realm, user) in [
        (vec!["pwd"], 301, "corp", "user-1"),
        (vec!["push"], 0, "corp", "user-1"),
        (vec!["email_magic_link"], 0, "corp", "user-1"),
        (vec!["pwd"], 0, "other", "user-1"),
    ] {
        let cookie = session(&f, user, realm, &methods, age).await;
        rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    }
    let cookie = password_cookie(&f).await;
    f.state
        .repo
        .revoke_session(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn finish_rechecks_owner_realm_exact_session_and_revocation_without_spending_attempts() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    let req = finish_body(&c, &nonce, &key);
    let another = session(&f, "user-1", "corp", &["pwd"], 0).await;
    let foreign = session(&f, "someone-else", "corp", &["pwd"], 0).await;
    for wrong in [None, Some(another.as_str()), Some(foreign.as_str())] {
        rejected(post(&f, FINISH, wrong, req.clone()).await, Some(&nonce)).await;
    }
    rejected(
        post(
            &f,
            &FINISH.replace("corp", "other"),
            Some(&cookie),
            req.clone(),
        )
        .await,
        Some(&nonce),
    )
    .await;
    let mut substituted = req.clone();
    substituted["registration_id"] = json!(format!("{}x", c.authenticator.id));
    rejected(
        post(&f, FINISH, Some(&cookie), substituted).await,
        Some(&nonce),
    )
    .await;
    assert_eq!(attempts(&f, &c).await, 0);
    f.state
        .repo
        .revoke_session(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    rejected(post(&f, FINISH, Some(&cookie), req).await, Some(&nonce)).await;
    assert_eq!(attempts(&f, &c).await, 0);
}

#[tokio::test]
async fn finish_rechecks_recent_authentication_not_session_idle_freshness() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    let pool = sqlx::SqlitePool::connect(&f.url).await.unwrap();
    sqlx::query("UPDATE sessions SET auth_time = ? WHERE id = ?")
        .bind((util::now_seconds() - 301) as i64)
        .bind(cookie.split_once('=').unwrap().1)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    rejected(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key)).await,
        Some(&nonce),
    )
    .await;
    assert_eq!(attempts(&f, &c).await, 0);
}

#[tokio::test]
async fn current_stronger_factors_require_recent_matching_trusted_amr_at_start_and_finish() {
    for factor in ["totp", "webauthn"] {
        let f = fixture(true, true, false).await;
        let cookie = password_cookie(&f).await;
        let key = device_key();
        let (c, nonce) = begin(&f, &cookie, &key).await;
        if factor == "totp" {
            totp(&f, true).await;
        } else {
            passkey(&f).await;
        }
        rejected(
            post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key)).await,
            Some(&nonce),
        )
        .await;
        rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
        let stale = session(&f, "user-1", "corp", &[factor], 301).await;
        rejected(post(&f, START, Some(&stale), start_body(&key)).await, None).await;
        let wrong_method = if factor == "totp" { "webauthn" } else { "totp" };
        let wrong = session(&f, "user-1", "corp", &[wrong_method], 0).await;
        rejected(post(&f, START, Some(&wrong), start_body(&key)).await, None).await;
        let recent = session(&f, "user-1", "corp", &[factor], 0).await;
        let (c, nonce) = begin(&f, &recent, &key).await;
        assert_eq!(
            post(&f, FINISH, Some(&recent), finish_body(&c, &nonce, &key))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
}

#[tokio::test]
async fn real_totp_authentication_session_can_enroll_without_admin_step_up_policy() {
    let mut f = fixture(true, true, false).await;
    totp(&f, true).await;
    f.app = f
        .app
        .merge(qid_session::totp_api::totp_routes(&f.state.paths).with_state(f.state.clone()));
    let code = qid_crypto::totp::TotpVerifier::default()
        .generate_code("JBSWY3DPEHPK3PXP", util::now_seconds())
        .unwrap();
    let response = post(
        &f,
        "/api/v1/corp/auth/totp/authenticate",
        None,
        json!({"user_id":"user-1", "code": code}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    assert_eq!(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(
            &f,
            REVOKE,
            Some(&cookie),
            json!({"authenticator_id":c.authenticator.id})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn disabled_totp_does_not_prevent_password_bootstrap() {
    let f = fixture(true, true, false).await;
    totp(&f, false).await;
    let cookie = password_cookie(&f).await;
    begin(&f, &cookie, &device_key()).await;
}

#[tokio::test]
async fn proof_binds_device_key_owner_realm_registration_and_destination() {
    for field in ["key", "user", "realm", "id", "destination", "purpose"] {
        let f = fixture(true, true, false).await;
        let cookie = password_cookie(&f).await;
        let key = device_key();
        let (c, nonce) = begin(&f, &cookie, &key).await;
        let mut wrong = c.clone();
        match field {
            "user" => wrong.authenticator.user_id = "wrong-user".into(),
            "realm" => wrong.authenticator.realm_id = "wrong-realm".into(),
            "id" => wrong.authenticator.id = "wrong-registration".into(),
            "destination" => wrong.authenticator.destination = "wrong-destination".into(),
            _ => {}
        }
        let signing_key = if field == "key" { device_key() } else { key };
        let mut req = finish_body(&wrong, &nonce, &signing_key);
        req["registration_id"] = json!(c.authenticator.id);
        if field == "purpose" {
            let login = PushLoginChallenge {
                id: c.authenticator.id.clone(),
                realm_id: "corp".into(),
                user_id: "user-1".into(),
                authenticator_id: c.authenticator.id.clone(),
                purpose: PushPurpose::PasswordLogin,
                nonce_verifier: c.nonce_verifier.clone(),
                browser_binding_verifier: util::sha256_hex(b"browser"),
                resend_admitted_at: Vec::new(),
                created_at: c.authenticator.created_at,
                expires_at: c.expires_at,
                max_attempts: 2,
                attempt_count: 0,
                decision: None,
                decided_at: None,
                consumed_at: None,
            };
            req["proof"] = json!(URL_SAFE_NO_PAD.encode(sign(
                &signing_key,
                qid_mfa::push::login_payload(&login, &nonce, PushDecision::Approve).unwrap()
            )));
        }
        rejected(post(&f, FINISH, Some(&cookie), req).await, Some(&nonce)).await;
        assert_eq!(attempts(&f, &c).await, 1);
        assert!(
            f.state
                .repo
                .list_push_authenticators(&"corp".into(), "user-1")
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn bad_and_oversized_proofs_spend_atomic_attempt_budget_then_valid_proof_fails() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    let mut bad = finish_body(&c, &nonce, &key);
    bad["proof"] = json!("!invalid!");
    let mut oversized = bad.clone();
    oversized["proof"] = json!("A".repeat(6000));
    let (one, two) = tokio::join!(
        post(&f, FINISH, Some(&cookie), bad),
        post(&f, FINISH, Some(&cookie), oversized)
    );
    rejected(one, Some(&nonce)).await;
    rejected(two, Some(&nonce)).await;
    assert_eq!(attempts(&f, &c).await, 2);
    rejected(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key)).await,
        Some(&nonce),
    )
    .await;
    assert_eq!(attempts(&f, &c).await, 2);
}

#[tokio::test]
async fn expiry_is_checked_atomically_without_sleeping() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (mut c, nonce) = begin(&f, &cookie, &key).await;
    let now = util::now_seconds();
    c.authenticator.created_at = now - 20;
    c.expires_at = now - 1;
    let pool = sqlx::SqlitePool::connect(&f.url).await.unwrap();
    sqlx::query("UPDATE push_authenticators SET issued_at = ?, pending_expires_at = ?, record_json = ? WHERE id = ?")
        .bind((now-20) as i64).bind(c.expires_at as i64)
        .bind(serde_json::to_string(&PushAuthenticatorRecord::Pending(c.clone())).unwrap())
        .bind(&c.authenticator.id).execute(&pool).await.unwrap();
    pool.close().await;
    rejected(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key)).await,
        Some(&nonce),
    )
    .await;
    assert_eq!(attempts(&f, &c).await, 0);
}

#[tokio::test]
async fn delivery_failures_timeout_disabled_and_unconfigured_never_activate_or_leak() {
    for (enabled, provider, fail, hang) in [
        (false, true, false, false),
        (true, false, false, false),
        (true, true, true, false),
        (true, true, false, true),
    ] {
        let f = fixture_with_options(enabled, provider, fail, hang).await;
        let cookie = password_cookie(&f).await;
        let response = post(&f, START, Some(&cookie), start_body(&device_key())).await;
        let nonce = f
            .delivery
            .requests
            .lock()
            .unwrap()
            .last()
            .map(|r| r.data_json["nonce"].as_str().unwrap().to_owned());
        rejected(response, nonce.as_deref()).await;
        assert!(
            f.state
                .repo
                .list_push_authenticators(&"corp".into(), "user-1")
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn concurrency_admission_and_owner_wide_issuance_budget_precede_delivery() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let permit = f
        .state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
        .unwrap();
    rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    assert!(f.delivery.requests.lock().unwrap().is_empty());
    drop(permit);
    for _ in 0..5 {
        begin(&f, &cookie, &key).await;
    }
    rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn invalid_inputs_and_caller_assurance_are_rejected_without_secrets_or_delivery() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    for dest in [
        "".into(),
        "  ".into(),
        "x\ny".into(),
        "x".repeat(1025),
        "x".repeat(17000),
    ] {
        let mut req = start_body(&key);
        req["destination"] = json!(dest);
        rejected(post(&f, START, Some(&cookie), req).await, None).await;
    }
    for (field, value) in [("d", DEST), ("crv", "P-384"), ("x", DEST)] {
        let mut req = start_body(&key);
        req["public_jwk"][field] = json!(value);
        rejected(post(&f, START, Some(&cookie), req).await, None).await;
    }
    for (field, value) in [
        ("amr", json!(["totp"])),
        ("user_id", json!("other")),
        ("realm_id", json!("other")),
    ] {
        let mut req = start_body(&key);
        req[field] = value;
        rejected(post(&f, START, Some(&cookie), req).await, None).await;
    }
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn activation_is_one_use_under_concurrent_finishes() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    let req = finish_body(&c, &nonce, &key);
    let (a, b) = tokio::join!(
        post(&f, FINISH, Some(&cookie), req.clone()),
        post(&f, FINISH, Some(&cookie), req)
    );
    assert_eq!(
        [a.status(), b.status()]
            .iter()
            .filter(|s| **s == StatusCode::NO_CONTENT)
            .count(),
        1
    );
    assert_eq!(
        f.state
            .repo
            .list_push_authenticators(&"corp".into(), "user-1")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn revocation_is_owner_only_and_invalidates_password_push_login() {
    let f = fixture(true, true, false).await;
    let cookie = password_cookie(&f).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    assert_eq!(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let foreign = session(&f, "someone-else", "corp", &["pwd"], 0).await;
    let req = json!({"authenticator_id":c.authenticator.id});
    rejected(post(&f, REVOKE, Some(&foreign), req.clone()).await, None).await;
    rejected(
        post(
            &f,
            &REVOKE.replace("corp", "other"),
            Some(&cookie),
            req.clone(),
        )
        .await,
        None,
    )
    .await;
    rejected(post(&f, REVOKE, None, req.clone()).await, None).await;
    // A stale password-only session must not turn revocation into a factor bypass.
    rejected(post(&f, REVOKE, Some(&cookie), req.clone()).await, None).await;
    let stale = session(&f, "user-1", "corp", &["pwd", "push"], 301).await;
    rejected(post(&f, REVOKE, Some(&stale), req.clone()).await, None).await;
    let response = login(&f).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let binding = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let d = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        decide(&f, &key, &d, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    let response = super::finish(&f, Some(&binding), &d).await;
    assert_eq!(response.status(), StatusCode::OK);
    let sid = body(response).await["session"].as_str().unwrap().to_owned();
    let recent = format!(
        "{}={sid}",
        f.state.plan.realms[0].browser_session.cookie_name
    );
    assert_eq!(
        post(&f, REVOKE, Some(&recent), req).await.status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        f.state
            .repo
            .get_push_authenticator(&"corp".into(), "user-1", &c.authenticator.id)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(login(&f).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn owner_revocation_remains_available_when_delivery_is_disabled_or_unconfigured() {
    let f = fixture(false, false, false).await;
    enroll(&f).await;
    let cookie = session(&f, "user-1", "corp", &["pwd", "push"], 0).await;
    assert_eq!(
        post(
            &f,
            REVOKE,
            Some(&cookie),
            json!({"authenticator_id":"device"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn unknown_or_future_authentication_and_expired_sessions_fail_closed() {
    let f = fixture(true, true, false).await;
    let key = device_key();
    let cookie = session(&f, "user-1", "corp", &[], 0).await;
    rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    for column in ["auth_time", "idle_expires_at", "absolute_expires_at"] {
        let cookie = session(&f, "user-1", "corp", &["pwd"], 0).await;
        let pool = sqlx::SqlitePool::connect(&f.url).await.unwrap();
        let statement = match column {
            "auth_time" => "UPDATE sessions SET auth_time = ? WHERE id = ?",
            "idle_expires_at" => "UPDATE sessions SET idle_expires_at = ? WHERE id = ?",
            _ => "UPDATE sessions SET absolute_expires_at = ? WHERE id = ?",
        };
        let now = util::now_seconds();
        let invalid_time = if column == "auth_time" {
            now + 100
        } else {
            now - 100
        };
        sqlx::query(statement)
            .bind(invalid_time as i64)
            .bind(cookie.split_once('=').unwrap().1)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        rejected(post(&f, START, Some(&cookie), start_body(&key)).await, None).await;
    }
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn enrollment_and_delivery_errors_never_log_nonce_proof_destination_or_diagnostics() {
    use tracing::instrument::WithSubscriber;
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        for failed_delivery in [false, true] {
            let f = fixture(true, true, failed_delivery).await;
            let cookie = password_cookie(&f).await;
            let key = device_key();
            let response = post(&f, START, Some(&cookie), start_body(&key)).await;
            let d = f.delivery.requests.lock().unwrap().last().unwrap().clone();
            let nonce = d.data_json["nonce"].as_str().unwrap();
            let id = d.data_json["registration_id"].as_str().unwrap();
            let c = f
                .state
                .repo
                .get_push_registration(&"corp".into(), "user-1", id)
                .await
                .unwrap()
                .unwrap();
            let mut req = finish_body(&c, nonce, &key);
            let proof = req["proof"].as_str().unwrap().to_owned();
            if failed_delivery {
                rejected(response, Some(nonce)).await;
            } else {
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                req["nonce"] = json!("!invalid!");
                rejected(post(&f, FINISH, Some(&cookie), req).await, Some(nonce)).await;
                assert_eq!(
                    post(&f, FINISH, Some(&cookie), finish_body(&c, nonce, &key))
                        .await
                        .status(),
                    StatusCode::NO_CONTENT
                );
            }
            let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            for secret in [
                DEST,
                nonce,
                proof.as_str(),
                "sensitive provider diagnostic",
                cookie.split_once('=').unwrap().1,
            ] {
                assert!(!captured.contains(secret), "secret found in logs");
            }
        }
    }
    .with_subscriber(subscriber)
    .await;
}

#[tokio::test]
async fn fresh_verified_email_session_is_an_existing_enrollment_method() {
    let mut f = fixture(true, true, false).await;
    configure_email_magic_link(&mut f, true).await;
    let cookie = session(&f, "user-1", "corp", &["email"], 0).await;
    let key = device_key();
    let (c, nonce) = begin(&f, &cookie, &key).await;
    assert_eq!(
        post(&f, FINISH, Some(&cookie), finish_body(&c, &nonce, &key))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn email_enrollment_requires_enabled_recent_verified_identity_without_stronger_factor() {
    let mut f = fixture(true, true, false).await;
    configure_email_magic_link(&mut f, false).await;
    let key = device_key();
    let disabled = session(&f, "user-1", "corp", &["email"], 0).await;
    rejected(
        post(&f, START, Some(&disabled), start_body(&key)).await,
        None,
    )
    .await;
    configure_email_magic_link(&mut f, true).await;
    let stale = session(&f, "user-1", "corp", &["email"], 301).await;
    rejected(post(&f, START, Some(&stale), start_body(&key)).await, None).await;
    let unverified = session(&f, "unverified-user", "corp", &["email"], 0).await;
    rejected(
        post(&f, START, Some(&unverified), start_body(&key)).await,
        None,
    )
    .await;
    totp(&f, true).await;
    let email_only = session(&f, "user-1", "corp", &["email"], 0).await;
    rejected(
        post(&f, START, Some(&email_only), start_body(&key)).await,
        None,
    )
    .await;
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}
