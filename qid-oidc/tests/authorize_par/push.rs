//! In-process registered-device tests, not a COSE interoperability claim.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use qid_core::{models::*, notification::*};
use serde_json::{Value as JsonValue, json};
use std::sync::Mutex;

type Fixture = (Router, Arc<SharedState<SqlRepository>>, Arc<Delivery>);
#[derive(Default)]
struct Delivery(Mutex<Vec<NotificationRequest>>);
#[async_trait::async_trait]
impl NotificationTransport for Delivery {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        self.0.lock().unwrap().push(request);
        Ok(NotificationResponse {
            status: 202,
            sent: true,
            provider_message_id: None,
        })
    }
}
async fn fixture(enabled: bool) -> Fixture {
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.mfa.push.enabled = enabled;
    config.realms[0]
        .authentication
        .mfa
        .push
        .resend_cooldown_seconds = 1;
    config.realms[0]
        .protocols
        .oidc
        .authorization_code
        .request_object_signing_alg_values
        .push("HS256".into());
    config.server.notification = Some(qid_core::config::ServerNotificationConfig {
        provider: "https://delivery.example.com".into(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 1,
    });
    let (app, state) = setup_with_config(config).await;
    drop(app);
    let delivery = Arc::new(Delivery::default());
    let state = Arc::new(
        Arc::try_unwrap(state)
            .ok()
            .unwrap()
            .with_notification_transport(delivery.clone()),
    );
    let app = qid_oidc::routes(&state.paths).with_state(state.clone());
    (app, state, delivery)
}
fn sign(key: &SigningKey, payload: Vec<u8>) -> Vec<u8> {
    let protected = vec![0xa1, 1, 0x26];
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
    let mut proof = Vec::new();
    ciborium::into_writer(
        &Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]),
        &mut proof,
    )
    .unwrap();
    proof
}
async fn enroll(state: &SharedState<SqlRepository>) -> SigningKey {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let nonce = URL_SAFE_NO_PAD.encode([1; 32]);
    let now = util::now_seconds();
    let registration = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "push-device".into(),
            realm_id: "test".into(),
            user_id: "par-user".into(),
            destination: "account-device-destination".into(),
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
        nonce_verifier: util::sha256_hex(nonce.as_bytes()),
        expires_at: now + 300,
        max_attempts: 5,
        attempt_count: 0,
    };
    assert!(
        state
            .repo
            .try_issue_push_registration(&registration, 5, 3600)
            .await
            .unwrap()
    );
    let proof = sign(
        &key,
        qid_mfa::push::registration_payload(&registration, &nonce).unwrap(),
    );
    qid_mfa::push::verify_registration(&registration, &nonce, &proof).unwrap();
    assert!(
        state
            .repo
            .attempt_push_registration(&registration, true, util::now_seconds())
            .await
            .unwrap()
    );
    key
}
async fn post_json(
    app: Router,
    path: String,
    cookie: Option<&str>,
    body: JsonValue,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    app.oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
fn completion(delivery: &NotificationRequest) -> JsonValue {
    json!({"realm_id": "test", "user_id": "par-user", "client_id": "par-client", "challenge_id": delivery.data_json["challenge_id"]})
}
async fn decide(
    app: Router,
    state: &SharedState<SqlRepository>,
    key: &SigningKey,
    delivery: &NotificationRequest,
    decision: PushDecision,
) -> axum::response::Response {
    let id = delivery.data_json["challenge_id"].as_str().unwrap();
    let c = state
        .repo
        .get_push_login(&"test".into(), "par-user", id)
        .await
        .unwrap()
        .unwrap();
    let nonce = delivery.data_json["nonce"].as_str().unwrap();
    let proof = sign(
        key,
        qid_mfa::push::login_payload(&c, nonce, decision).unwrap(),
    );
    post_json(app, format!("{}/push/decision", state.paths.authorize), None, json!({"realm_id": "test", "user_id": "par-user", "challenge_id": id, "nonce": nonce, "decision": decision, "proof": URL_SAFE_NO_PAD.encode(proof)})).await
}
async fn pending(
    app: Router,
    state: &SharedState<SqlRepository>,
    delivery: &Delivery,
    uri: String,
) -> (String, NotificationRequest) {
    let response = post_form(app, uri, LOGIN_FORM).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get("location").is_none());
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body = json_body(response).await;
    assert_eq!(body["challenge"], "push_required");
    assert!(body.get("nonce").is_none());
    assert!(
        state
            .repo
            .list_sessions("test", Some("par-user"))
            .await
            .unwrap()
            .is_empty()
    );
    let delivered = delivery.0.lock().unwrap().last().unwrap().clone();
    assert_eq!(delivered.channel, NotificationChannel::Push);
    assert_eq!(delivered.recipient, "account-device-destination");
    assert_eq!(body["challenge_id"], delivered.data_json["challenge_id"]);
    assert_eq!(
        body["transaction_number"],
        delivered.data_json["transaction_number"]
    );
    let number = body["transaction_number"].as_str().unwrap();
    assert_eq!(number.len(), 6);
    assert!(number.bytes().all(|b| b.is_ascii_digit()));
    (cookie, delivered)
}
async fn finish(
    app: Router,
    state: &SharedState<SqlRepository>,
    cookie: Option<&str>,
    req: JsonValue,
) -> axum::response::Response {
    post_json(
        app,
        format!("{}/push/complete", state.paths.authorize),
        cookie,
        req,
    )
    .await
}
fn refused(response: &axum::response::Response) {
    assert!(response.status().is_client_error());
    assert!(response.headers().get("location").is_none());
}

#[tokio::test]
async fn session_reuse_rechecks_enrollment_and_trusted_push_amr() {
    let (app, state, _) = fixture(true).await;
    create_browser_session(&state, "before-enrollment").await;
    let uri = authorize_query(&state, "");
    assert_code_issued(&get_uri(app.clone(), &uri, Some("__Host-qid=before-enrollment")).await);
    enroll(&state).await;
    assert_login_challenge(get_uri(app.clone(), &uri, Some("__Host-qid=before-enrollment")).await)
        .await;
    let mut session = state
        .repo
        .get_session("before-enrollment")
        .await
        .unwrap()
        .unwrap();
    session.id = "after-push".into();
    session.amr.push("push".into());
    state.repo.create_session(&session).await.unwrap();
    assert_code_issued(&get_uri(app.clone(), &uri, Some("__Host-qid=after-push")).await);

    // A prior TOTP or WebAuthn proof is already a second factor; push must not
    // become a blanket requirement on sessions that authenticated more strongly.
    for (session_id, factor) in [("after-totp", "totp"), ("after-webauthn", "webauthn")] {
        let mut stronger = session.clone();
        stronger.id = session_id.to_string();
        stronger.amr = vec!["pwd".to_string(), factor.to_string()];
        state.repo.create_session(&stronger).await.unwrap();
        assert_code_issued(
            &get_uri(app.clone(), &uri, Some(&format!("__Host-qid={session_id}"))).await,
        );
    }

    // A password-only session still needs push, and email remains separate
    // rather than being misclassified as an existing second factor.
    let mut password_only = session.clone();
    password_only.id = "password-only-after-enrollment".into();
    password_only.amr = vec!["pwd".to_string()];
    state.repo.create_session(&password_only).await.unwrap();
    assert_login_challenge(
        get_uri(
            app.clone(),
            &uri,
            Some("__Host-qid=password-only-after-enrollment"),
        )
        .await,
    )
    .await;
    let mut email_only = session.clone();
    email_only.id = "email-after-enrollment".into();
    email_only.amr = vec!["email".to_string()];
    state.repo.create_session(&email_only).await.unwrap();
    assert_code_issued(
        &get_uri(app.clone(), &uri, Some("__Host-qid=email-after-enrollment")).await,
    );

    // max_age and prompt still override an otherwise adequate session.
    assert_login_challenge(
        get_uri(
            app.clone(),
            authorize_query(&state, "&max_age=0"),
            Some("__Host-qid=after-push"),
        )
        .await,
    )
    .await;
    assert_login_challenge(
        get_uri(
            app.clone(),
            authorize_query(&state, "&prompt=login"),
            Some("__Host-qid=after-push"),
        )
        .await,
    )
    .await;
    let response = get_uri(
        app,
        authorize_query(&state, "&prompt=none"),
        Some("__Host-qid=before-enrollment"),
    )
    .await;
    assert!(redirect_location(&response).contains("error=login_required"));
}

#[tokio::test]
async fn par_resume_requires_device_and_exact_browser_then_issues_once() {
    let (app, state, delivery) = fixture(true).await;
    let key = enroll(&state).await;
    let uri = "urn:ietf:params:oauth:request_uri:push";
    let pkce = util::sha256_base64url("verifier");
    store_par_request(&state, uri, json!({"client_id": "par-client", "response_type": "code", "redirect_uri": "https://app.example.com/callback", "scope": "openid profile", "state": "par-push-state", "nonce": "par-push-nonce", "code_challenge": pkce, "code_challenge_method": "S256", "max_age": 0, "prompt": "login"})).await;
    let authorize = format!(
        "{}?request_uri={}",
        state.paths.authorize,
        urlencoding::encode(uri)
    );
    let (cookie, sent) = pending(app.clone(), &state, &delivery, authorize.clone()).await;
    let req = completion(&sent);
    // Delivery acceptance alone is not approval, and PAR is already spent.
    refused(&finish(app.clone(), &state, Some(&cookie), req.clone()).await);
    refused(&post_form(app.clone(), authorize, LOGIN_FORM).await);
    let bad_key = SigningKey::from_slice(&[9; 32]).unwrap();
    refused(&decide(app.clone(), &state, &bad_key, &sent, PushDecision::Approve).await);
    assert_eq!(
        decide(app.clone(), &state, &key, &sent, PushDecision::Approve)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    refused(&decide(app.clone(), &state, &key, &sent, PushDecision::Approve).await);
    refused(&finish(app.clone(), &state, None, req.clone()).await);
    let other_cookie = format!("__Host-qid-oidc-push={}", URL_SAFE_NO_PAD.encode([42; 32]));
    refused(&finish(app.clone(), &state, Some(&other_cookie), req.clone()).await);
    for field in ["realm_id", "user_id", "client_id", "challenge_id"] {
        let mut substituted = req.clone();
        substituted[field] = json!("another-request");
        refused(&finish(app.clone(), &state, Some(&cookie), substituted).await);
    }
    let (first, second) = tokio::join!(
        finish(app.clone(), &state, Some(&cookie), req.clone()),
        finish(app.clone(), &state, Some(&cookie), req.clone())
    );
    let success = if first.status() == StatusCode::TEMPORARY_REDIRECT {
        refused(&second);
        first
    } else {
        refused(&first);
        second
    };
    assert_code_issued(&success);
    let location = redirect_location(&success);
    assert!(location.contains("state=par-push-state"));
    let code = extract_query_param(&location, "code").unwrap();
    let stored = state
        .repo
        .get_authorization_code(&util::sha256_base64url(&code))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.nonce.as_deref(), Some("par-push-nonce"));
    assert_eq!(stored.code_challenge.as_deref(), Some(pkce.as_str()));
    assert_eq!(stored.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(stored.scopes, vec!["openid", "profile"]);
    assert_eq!(stored.amr, vec!["pwd", "push"]);
    assert_eq!(stored.session_id, None);
    refused(&finish(app, &state, Some(&cookie), req).await);
}

#[tokio::test]
async fn two_pending_requests_cannot_exchange_browser_binding_or_device_signature() {
    let (app, state, delivery) = fixture(true).await;
    let key = enroll(&state).await;
    let (cookie1, sent1) =
        pending(app.clone(), &state, &delivery, authorize_query(&state, "")).await;
    let (cookie2, sent2) = pending(
        app.clone(),
        &state,
        &delivery,
        authorize_query(&state, "&resource=https%3A%2F%2Fapi.example.com"),
    )
    .await;
    let first = state
        .repo
        .get_push_login(
            &"test".into(),
            "par-user",
            sent1.data_json["challenge_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let nonce1 = sent1.data_json["nonce"].as_str().unwrap();
    let proof1 = sign(
        &key,
        qid_mfa::push::login_payload(&first, nonce1, PushDecision::Approve).unwrap(),
    );
    refused(&post_json(app.clone(), format!("{}/push/decision", state.paths.authorize), None, json!({"realm_id": "test", "user_id": "par-user", "challenge_id": sent2.data_json["challenge_id"], "nonce": nonce1, "decision": "approve", "proof": URL_SAFE_NO_PAD.encode(proof1)})).await);
    assert_eq!(
        decide(app.clone(), &state, &key, &sent1, PushDecision::Approve)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    refused(&finish(app.clone(), &state, Some(&cookie2), completion(&sent1)).await);
    refused(&finish(app.clone(), &state, Some(&cookie1), completion(&sent2)).await);
    refused(&finish(app.clone(), &state, Some(&cookie2), completion(&sent2)).await);
    assert_code_issued(&finish(app, &state, Some(&cookie1), completion(&sent1)).await);
}

#[tokio::test]
async fn denial_and_revocation_never_complete() {
    let (app, state, delivery) = fixture(true).await;
    let key = enroll(&state).await;
    let (cookie, sent) = pending(app.clone(), &state, &delivery, authorize_query(&state, "")).await;
    assert_eq!(
        decide(app.clone(), &state, &key, &sent, PushDecision::Deny)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    refused(&finish(app.clone(), &state, Some(&cookie), completion(&sent)).await);
    refused(&decide(app.clone(), &state, &key, &sent, PushDecision::Approve).await);
    let (cookie, sent) = pending(app.clone(), &state, &delivery, authorize_query(&state, "")).await;
    assert_eq!(
        decide(app.clone(), &state, &key, &sent, PushDecision::Approve)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        state
            .repo
            .revoke_push_authenticator(
                &"test".into(),
                "par-user",
                "push-device",
                util::now_seconds()
            )
            .await
            .unwrap()
    );
    refused(&finish(app, &state, Some(&cookie), completion(&sent)).await);
}

#[tokio::test]
async fn enabled_or_disabled_delivery_never_bypasses_enrollment() {
    let (app, state, delivery) = fixture(false).await;
    // No registration preserves password behavior even when push is disabled.
    assert_code_issued(&post_form(app.clone(), authorize_query(&state, ""), LOGIN_FORM).await);
    enroll(&state).await;
    refused(&post_form(app, authorize_query(&state, ""), LOGIN_FORM).await);
    assert!(delivery.0.lock().unwrap().is_empty());
    assert!(
        state
            .repo
            .list_sessions("test", Some("par-user"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn expired_continuation_cannot_resume_even_with_current_signed_approval() {
    use sha2::{Digest, Sha256};
    let (app, state, _) = fixture(true).await;
    let key = enroll(&state).await;
    let now = util::now_seconds();
    let nonce = URL_SAFE_NO_PAD.encode([31; 32]);
    let binding = URL_SAFE_NO_PAD.encode([32; 32]);
    let challenge = PushLoginChallenge {
        id: "expired-oidc".into(),
        realm_id: "test".into(),
        user_id: "par-user".into(),
        authenticator_id: "push-device".into(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: util::sha256_hex(nonce.as_bytes()),
        browser_binding_verifier: util::sha256_hex(
            json!(["qid:oidc:push:v1", "par-client", binding])
                .to_string()
                .as_bytes(),
        ),
        resend_admitted_at: Vec::new(),
        created_at: now,
        expires_at: now + 300,
        max_attempts: 5,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    };
    assert!(
        state
            .repo
            .try_issue_push_login(&challenge, 5, 3600)
            .await
            .unwrap()
    );
    // Seed an already expired continuation without a wall-clock sleep. Storage
    // accepts historical server timestamps; HTTP must still refuse to consume it.
    state
        .repo
        .create_oidc_continuation(
            &OidcAuthorizationContinuation {
                id: challenge.id.clone(),
                realm_id: "test".into(),
                user_id: "par-user".into(),
                client_id: "par-client".into(),
                context_json: r#"{"version":1}"#.into(),
                browser_binding_sha256: Sha256::digest(binding.as_bytes()).into(),
                created_at: now - 10,
                expires_at: now - 1,
            },
            now - 10,
        )
        .await
        .unwrap();
    let delivery = NotificationRequest {
        channel: NotificationChannel::Push,
        provider: String::new(),
        recipient: String::new(),
        subject: None,
        body: String::new(),
        template_id: None,
        data_json: json!({"challenge_id": challenge.id, "nonce": nonce}),
    };
    assert_eq!(
        decide(app.clone(), &state, &key, &delivery, PushDecision::Approve)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    refused(
        &finish(
            app,
            &state,
            Some(&format!("__Host-qid-oidc-push={binding}")),
            completion(&delivery),
        )
        .await,
    );
}

#[tokio::test]
async fn resolved_jar_preserves_response_modes_and_original_dpop_key() {
    for mode in ["form_post", "jwt"] {
        let (app, state, delivery) = fixture(true).await;
        let key = enroll(&state).await;
        let mut extra = HashMap::new();
        for (name, value) in [
            ("client_id", json!("par-client")),
            ("response_type", json!("code")),
            ("redirect_uri", json!("https://app.example.com/callback")),
            ("scope", json!("openid profile")),
            ("state", json!("jar-push-state")),
            ("nonce", json!("jar-push-nonce")),
            ("resource", json!("https://api.example.com")),
            (
                "authorization_details",
                json!([{"type": "account_information", "actions": ["read"]}]),
            ),
            ("response_mode", json!(mode)),
            ("code_challenge", json!(util::sha256_base64url("verifier"))),
            ("code_challenge_method", json!("S256")),
        ] {
            extra.insert(name.into(), value);
        }
        let jar = signed_request_object(&state, "push-jar", "push-jar-key", extra).await;
        let original_key = dpop_test_key();
        let proof = dpop_proof(
            "push-original",
            "POST",
            "https://id.example.com/oauth2/authorize",
            None,
            Some(original_key.clone()),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!(
                        "{}?request={}",
                        state.paths.authorize,
                        urlencoding::encode(&jar)
                    ))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("DPoP", proof)
                    .body(Body::from(LOGIN_FORM))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let sent = delivery.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(
            decide(app.clone(), &state, &key, &sent, PushDecision::Approve)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        // Completion cannot inject new protocol fields or a replacement DPoP key.
        let mut substitute = completion(&sent);
        substitute["redirect_uri"] = json!("https://other.example.com/");
        refused(&finish(app.clone(), &state, Some(&cookie), substitute).await);
        let other_key = generate_es256("replacement").unwrap();
        let other_proof = dpop_proof(
            "push-replacement",
            "POST",
            "https://id.example.com/oauth2/authorize/push/complete",
            None,
            Some((other_key.private_pem, other_key.public_jwk)),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{}/push/complete", state.paths.authorize))
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("DPoP", other_proof)
                    .body(Body::from(completion(&sent).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let code = if mode == "form_post" {
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains("https://app.example.com/callback"));
            assert!(html.contains("jar-push-state"));
            let prefix = "name=\"code\" value=\"";
            html.split_once(prefix)
                .unwrap()
                .1
                .split('"')
                .next()
                .unwrap()
                .to_owned()
        } else {
            let location = redirect_location(&response);
            assert!(!location.contains("?code="));
            let jwt = extract_query_param(&location, "response").unwrap();
            let claims = state.signer.decode_signature_only(&jwt).unwrap().claims;
            assert_eq!(claims.aud, Some(Audience::single("par-client")));
            assert_eq!(claims.extra["state"], "jar-push-state");
            let jwk = serde_json::to_value(&original_key.1).unwrap();
            let canonical =
                json!({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
                    .to_string();
            assert_eq!(claims.extra["apv"], util::sha256_base64url(&canonical));
            claims.extra["code"].as_str().unwrap().to_owned()
        };
        let stored = state
            .repo
            .get_authorization_code(&util::sha256_base64url(&code))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.nonce.as_deref(), Some("jar-push-nonce"));
        assert_eq!(stored.resource, vec!["https://api.example.com"]);
        assert_eq!(
            stored.authorization_details,
            Some(json!([{"type": "account_information", "actions": ["read"]}]))
        );
        assert_eq!(stored.amr, vec!["pwd", "push"]);
    }
}

#[tokio::test]
async fn missing_notification_transport_is_not_password_fallback() {
    let (app, state, _) = fixture(true).await;
    enroll(&state).await;
    drop(app);
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    state.notification_transport = None;
    let state = Arc::new(state);
    let app = qid_oidc::routes(&state.paths).with_state(state.clone());
    refused(&post_form(app, authorize_query(&state, ""), LOGIN_FORM).await);
}

#[tokio::test]
async fn resend_keeps_par_continuation_and_number_but_invalidates_old_signed_prompts() {
    let (app, state, delivery) = fixture(true).await;
    let key = enroll(&state).await;
    let uri = "urn:ietf:params:oauth:request_uri:push-resend";
    let pkce = util::sha256_base64url("resend-verifier");
    store_par_request(&state, uri, json!({"client_id": "par-client", "response_type": "code", "redirect_uri": "https://app.example.com/callback", "scope": "openid profile", "state": "resend-state", "nonce": "resend-nonce", "code_challenge": pkce, "code_challenge_method": "S256", "response_mode": "query"})).await;
    let authorize = format!(
        "{}?request_uri={}",
        state.paths.authorize,
        urlencoding::encode(uri)
    );
    let (cookie, old) = pending(app.clone(), &state, &delivery, authorize.clone()).await;
    let req = completion(&old);
    let old_c = state
        .repo
        .get_push_login(
            &"test".into(),
            "par-user",
            old.data_json["challenge_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let old_nonce = old.data_json["nonce"].as_str().unwrap();
    let old_proofs: Vec<_> = [PushDecision::Approve, PushDecision::Deny]
        .into_iter()
        .map(|decision| {
            let proof = sign(
                &key,
                qid_mfa::push::login_payload(&old_c, old_nonce, decision).unwrap(),
            );
            json!({"realm_id": "test", "user_id": "par-user", "challenge_id": old_c.id,
            "nonce": old_nonce, "decision": decision, "proof": URL_SAFE_NO_PAD.encode(proof)})
        })
        .collect();
    let path = format!("{}/push/resend", state.paths.authorize);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    refused(&post_json(app.clone(), path.clone(), None, req.clone()).await);
    let wrong_cookie = format!("__Host-qid-oidc-push={}", URL_SAFE_NO_PAD.encode([42; 32]));
    refused(&post_json(app.clone(), path.clone(), Some(&wrong_cookie), req.clone()).await);
    let direct_cookie = cookie.replace("oidc-push", "password-push");
    refused(&post_json(app.clone(), path.clone(), Some(&direct_cookie), req.clone()).await);
    for field in ["realm_id", "user_id", "client_id", "challenge_id"] {
        let mut wrong = req.clone();
        wrong[field] = json!("other");
        refused(&post_json(app.clone(), path.clone(), Some(&cookie), wrong).await);
    }
    assert_eq!(delivery.0.lock().unwrap().len(), 1);
    let response = post_json(app.clone(), path.clone(), Some(&cookie), req.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response = json_body(response).await;
    let new = delivery.0.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        response["transaction_number"],
        old.data_json["transaction_number"]
    );
    assert_eq!(
        response["transaction_number"],
        new.data_json["transaction_number"]
    );
    assert_eq!(new.data_json["challenge_id"], old.data_json["challenge_id"]);
    assert_eq!(new.data_json["expires_at"], old.data_json["expires_at"]);
    assert_ne!(new.data_json["nonce"], old.data_json["nonce"]);
    for proof in old_proofs {
        refused(
            &post_json(
                app.clone(),
                format!("{}/push/decision", state.paths.authorize),
                None,
                proof,
            )
            .await,
        );
    }
    refused(&finish(app.clone(), &state, Some(&cookie), req.clone()).await);
    refused(&post_form(app.clone(), authorize, LOGIN_FORM).await); // PAR remains one-use
    assert_eq!(
        decide(app.clone(), &state, &key, &new, PushDecision::Approve)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    refused(&post_json(app.clone(), path, Some(&cookie), req.clone()).await);
    let response = finish(app.clone(), &state, Some(&cookie), req.clone()).await;
    assert_code_issued(&response);
    let location = redirect_location(&response);
    assert!(location.contains("state=resend-state"));
    let code = extract_query_param(&location, "code").unwrap();
    let stored = state
        .repo
        .get_authorization_code(&util::sha256_base64url(&code))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.nonce.as_deref(), Some("resend-nonce"));
    assert_eq!(stored.code_challenge.as_deref(), Some(pkce.as_str()));
    assert_eq!(stored.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(stored.amr, vec!["pwd", "push"]);
    refused(&finish(app, &state, Some(&cookie), req).await);
}
