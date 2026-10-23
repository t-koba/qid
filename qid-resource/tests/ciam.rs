use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{Argon2idCostConfig, QidConfig},
    models::{PasswordResetToken, User},
    state::SharedState,
    tenant::RealmId,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_resource_ciam");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

async fn setup() -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    setup_with_realms(&[]).await
}

async fn setup_with_realms(
    extra_realms: &[&str],
) -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    setup_with_config(test_helpers::test_config(), extra_realms).await
}

async fn setup_with_config(
    config: QidConfig,
    extra_realms: &[&str],
) -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    setup_with_transport(config, extra_realms, None).await
}

async fn setup_with_transport(
    mut config: QidConfig,
    extra_realms: &[&str],
    transport: Option<Arc<dyn qid_core::notification::NotificationTransport>>,
) -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    for realm in extra_realms {
        let mut realm_config = config.realms[0].clone();
        realm_config.id = (*realm).to_string();
        realm_config.issuer = format!("https://id.example.com/{realm}");
        config.realms.push(realm_config);
    }
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-ciam".to_string(),
        realm_id: "test".to_string(),
        email: Some("ciam@example.com".to_string()),
        email_verified: false,
        display_name: Some("CIAM User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    for realm in extra_realms {
        repo.create_realm(
            &"tenant-1".into(),
            &(*realm).into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let contexts = qid_crypto::resolve_password_contexts(&config).unwrap();
    let mut state = SharedState::new(config, repo, signer, serde_json::json!({})).unwrap();
    state.password_credentials = contexts;
    state.notification_transport = transport;
    let state = Arc::new(state);
    let app = qid_resource::resource_routes(&state.paths).with_state(state.clone());
    (app, state)
}

async fn add_session(state: &Arc<SharedState<SqlRepository>>, user_id: &str) -> String {
    add_session_in_realm(state, "test", user_id).await
}

async fn add_session_in_realm(
    state: &Arc<SharedState<SqlRepository>>,
    realm: &str,
    user_id: &str,
) -> String {
    let cookie_name = &state.plan.realm(realm).unwrap().browser_session.cookie_name;
    let now = qid_core::util::now_seconds();
    let session = qid_core::models::Session {
        id: format!("ciam-session-{user_id}"),
        realm_id: realm.to_string(),
        user_id: user_id.to_string(),
        auth_time: now,
        acr: None,
        amr: Vec::new(),
        absolute_expires_at: now + 3600,
        idle_expires_at: now + 900,
        revoked: false,
        created_at: now,
        cnf: None,
    };
    state.repo.create_session(&session).await.unwrap();
    format!("{}={}", cookie_name, session.id)
}

fn with_cookie(req: Request<Body>, cookie: &str) -> Request<Body> {
    let (parts, body) = req.into_parts();
    let mut parts = parts;
    parts
        .headers
        .insert(axum::http::header::COOKIE, cookie.parse().unwrap());
    Request::from_parts(parts, body)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn ciam_consent_grant_drives_evaluation_and_privacy_dashboard() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let grant_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/grants")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "id":"consent-route-1",
                    "realm_id":"ignored",
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "granted_claims":["email"],
                    "terms_version":"2026-06",
                    "granted_at_epoch_seconds":1800000000,
                    "revoked":false
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let grant_response = app.clone().oneshot(grant_request).await.unwrap();
    assert_eq!(grant_response.status(), StatusCode::CREATED);

    let evaluate_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "requested_claims":["sub","email","phone"],
                    "granted_claims":[],
                    "sensitive_claims":["email","phone"]
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let evaluate_response = app.clone().oneshot(evaluate_request).await.unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    let evaluated = json(evaluate_response).await;
    assert_eq!(
        evaluated["evaluation"]["released_claims"],
        serde_json::json!(["email", "sub"])
    );
    assert_eq!(
        evaluated["evaluation"]["denied_claims"],
        serde_json::json!(["phone"])
    );

    let dashboard_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-ciam")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let dashboard_response = app.clone().oneshot(dashboard_request).await.unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = json(dashboard_response).await;
    assert_eq!(dashboard["consents"][0]["id"], "consent-route-1");
    assert_eq!(dashboard["identity_links"], serde_json::json!([]));
}

#[tokio::test]
async fn ciam_consent_grant_id_is_bound_to_owner() {
    let (app, state) = setup().await;
    state
        .repo
        .create_user(&User {
            id: "user-attacker".to_string(),
            realm_id: "test".to_string(),
            email: Some("attacker@example.com".to_string()),
            email_verified: false,
            display_name: Some("Attacker".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    let victim_cookie = add_session(&state, "user-ciam").await;
    let attacker_cookie = add_session(&state, "user-attacker").await;

    let victim_grant = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/grants")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "id":"consent-owner-route",
                    "realm_id":"ignored",
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "granted_claims":["email"],
                    "terms_version":"2026-06",
                    "granted_at_epoch_seconds":1800000000,
                    "revoked":false
                }"#,
            ))
            .unwrap(),
        &victim_cookie,
    );
    let victim_response = app.clone().oneshot(victim_grant).await.unwrap();
    assert_eq!(victim_response.status(), StatusCode::CREATED);

    let attacker_grant = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/grants")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "id":"consent-owner-route",
                    "realm_id":"ignored",
                    "user_id":"user-attacker",
                    "client_id":"client-ciam",
                    "granted_claims":["phone"],
                    "terms_version":"2026-06",
                    "granted_at_epoch_seconds":1800000000,
                    "revoked":false
                }"#,
            ))
            .unwrap(),
        &attacker_cookie,
    );
    let attacker_response = app.clone().oneshot(attacker_grant).await.unwrap();
    assert_eq!(attacker_response.status(), StatusCode::CONFLICT);

    let dashboard_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-ciam")
            .body(Body::empty())
            .unwrap(),
        &victim_cookie,
    );
    let dashboard_response = app.clone().oneshot(dashboard_request).await.unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = json(dashboard_response).await;
    assert_eq!(dashboard["consents"].as_array().map(Vec::len), Some(1));
    assert_eq!(dashboard["consents"][0]["id"], "consent-owner-route");
    assert_eq!(
        dashboard["consents"][0]["granted_claims"],
        serde_json::json!(["email"])
    );

    let evaluate_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "requested_claims":["email","phone"],
                    "granted_claims":[],
                    "sensitive_claims":["email","phone"]
                }"#,
            ))
            .unwrap(),
        &victim_cookie,
    );
    let evaluate_response = app.clone().oneshot(evaluate_request).await.unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    let evaluated = json(evaluate_response).await;
    assert_eq!(
        evaluated["evaluation"]["released_claims"],
        serde_json::json!(["email"])
    );
    assert_eq!(
        evaluated["evaluation"]["denied_claims"],
        serde_json::json!(["phone"])
    );

    let attacker_dashboard = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-attacker")
            .body(Body::empty())
            .unwrap(),
        &attacker_cookie,
    );
    let attacker_dashboard_response = app.oneshot(attacker_dashboard).await.unwrap();
    assert_eq!(attacker_dashboard_response.status(), StatusCode::OK);
    let attacker_view = json(attacker_dashboard_response).await;
    assert_eq!(attacker_view["consents"], serde_json::json!([]));
}

#[tokio::test]
async fn ciam_identity_link_id_cannot_be_reused_by_a_foreign_realm_user() {
    let (app, state) = setup().await;
    state
        .repo
        .create_realm(
            &"tenant-1".into(),
            &"victim-realm".into(),
            "https://victim.example.com",
            None,
        )
        .await
        .unwrap();
    state
        .repo
        .create_user(&User {
            id: "victim-user".to_string(),
            realm_id: "victim-realm".to_string(),
            email: Some("victim@example.com".to_string()),
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    let victim = qid_core::models::CiamIdentityLink {
        id: "link-victim".to_string(),
        realm_id: "victim-realm".to_string(),
        user_id: "victim-user".to_string(),
        provider: "google".to_string(),
        external_subject: "victim-subject".to_string(),
        external_email: Some("victim@example.com".to_string()),
        profile_json: serde_json::json!({"name": "Victim"}),
        linked_at_epoch_seconds: 1_800_000_000,
        verified: true,
    };
    state.repo.store_ciam_identity_link(&victim).await.unwrap();

    let cookie = add_session(&state, "user-ciam").await;
    let mut collision = victim.clone();
    collision.realm_id = "test".to_string();
    collision.user_id = "user-ciam".to_string();
    collision.external_email = Some("attacker@example.com".to_string());
    collision.profile_json = serde_json::json!({"name": "Attacker"});
    collision.verified = false;
    let request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/identity-links")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&collision).unwrap()))
            .unwrap(),
        &cookie,
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .repo
            .get_ciam_identity_link(&"victim-realm".into(), &victim.id)
            .await
            .unwrap(),
        Some(victim.clone())
    );
    assert_eq!(
        state
            .repo
            .list_ciam_identity_links(&"victim-realm".into(), "victim-user")
            .await
            .unwrap(),
        vec![victim]
    );
    assert!(
        state
            .repo
            .list_ciam_identity_links(&"test".into(), "user-ciam")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn ciam_session_cannot_assert_external_identity_links() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let realm = RealmId("test".to_string());
    let incumbent = qid_core::models::CiamIdentityLink {
        id: "trusted-link".to_string(),
        realm_id: realm.0.clone(),
        user_id: "user-ciam".to_string(),
        provider: "google".to_string(),
        external_subject: "trusted-subject".to_string(),
        external_email: None,
        profile_json: serde_json::json!({}),
        linked_at_epoch_seconds: 1_800_000_400,
        verified: true,
    };
    state
        .repo
        .store_ciam_identity_link(&incumbent)
        .await
        .unwrap();
    let audits_before = serde_json::to_value(
        state
            .repo
            .list_audit_events(Some(&realm), 10)
            .await
            .unwrap(),
    )
    .unwrap();
    for verified in [true, false] {
        for id in ["new-link", "trusted-link"] {
            let mut submitted = incumbent.clone();
            submitted.id = id.to_string();
            submitted.verified = verified;
            submitted.profile_json = serde_json::json!({"name": "Untrusted update"});
            let request = || {
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/test/ciam/identity-links")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&submitted).unwrap()))
                    .unwrap()
            };
            // Authentication must still run before the proof-required rejection.
            let unauthenticated = app.clone().oneshot(request()).await.unwrap();
            assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
            let response = app
                .clone()
                .oneshot(with_cookie(request(), &cookie))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                state
                    .repo
                    .list_ciam_identity_links(&realm, "user-ciam")
                    .await
                    .unwrap(),
                vec![incumbent.clone()]
            );
            assert_eq!(
                serde_json::to_value(
                    state
                        .repo
                        .list_audit_events(Some(&realm), 10)
                        .await
                        .unwrap()
                )
                .unwrap(),
                audits_before
            );
        }
    }
}

#[tokio::test]
async fn ciam_trusted_identity_links_are_listed_lookupable_and_deletions_audited() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    // Only a trusted provider-validated writer can establish this mapping.
    let link = qid_core::models::CiamIdentityLink {
        id: "link-route-1".to_string(),
        realm_id: "test".to_string(),
        user_id: "user-ciam".to_string(),
        provider: "google".to_string(),
        external_subject: "google-subject-1".to_string(),
        external_email: Some("social@example.com".to_string()),
        profile_json: serde_json::json!({"name": "Social User"}),
        linked_at_epoch_seconds: 1_800_000_400,
        verified: true,
    };
    state.repo.store_ciam_identity_link(&link).await.unwrap();

    let list_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/users/user-ciam/identity-links")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let links = json(list_response).await;
    assert_eq!(links[0]["provider"], "google");

    let lookup_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/identity-links/lookup")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "provider":"google",
                    "external_subject":"google-subject-1"
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let lookup_response = app.clone().oneshot(lookup_request).await.unwrap();
    assert_eq!(lookup_response.status(), StatusCode::OK);
    let lookup = json(lookup_response).await;
    assert_eq!(lookup["id"], "link-route-1");

    let dashboard_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-ciam")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let dashboard_response = app.clone().oneshot(dashboard_request).await.unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = json(dashboard_response).await;
    assert_eq!(dashboard["identity_links"][0]["id"], "link-route-1");

    let delete_request = with_cookie(
        Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/test/ciam/identity-links/link-route-1")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let delete_response = app.oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let realm_id = RealmId("test".to_string());
    let audits = state
        .repo
        .list_audit_events(Some(&realm_id), 10)
        .await
        .unwrap();
    let actions = audits
        .iter()
        .map(|event| event.action.as_str())
        .collect::<Vec<_>>();
    assert!(!actions.contains(&"ciam.identity_link.create"));
    assert!(actions.contains(&"ciam.identity_link.delete"));
    assert!(
        audits
            .iter()
            .all(|event| event.metadata_json.get("external_subject").is_none())
    );
}

#[tokio::test]
async fn ciam_password_reset_issue_route_fails_without_delivery() {
    let (app, state) = setup().await;
    let issue_requests = [(
        "/api/v1/test/ciam/password-reset/issue",
        r#"{
                "user_id":"user-ciam",
                "device_id":"device-1",
                "risk":{"score":10},
                "now_epoch_seconds":1800000100,
                "ttl_seconds":900
            }"#,
    )];
    for (uri, body) in issue_requests {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let response = json(response).await;
        assert_eq!(response["error"], "challenge delivery is not implemented");
        for field in ["id", "delivery_ref", "delivery_secret", "code", "token"] {
            assert!(
                response.get(field).is_none(),
                "unexpected {field} in response"
            );
        }
    }
    // The issue routes must persist nothing: the user's email stays
    // unverified and no audit event records a challenge that was never
    // delivered.
    let realm_id = RealmId::from("test");
    let user = state
        .repo
        .get_user_by_id_in_realm(&realm_id, "user-ciam")
        .await
        .unwrap()
        .expect("the user exists");
    assert!(
        !user.email_verified,
        "the 501 routes must not verify an email"
    );
    let audits = state
        .repo
        .list_audit_events(Some(&realm_id), 10)
        .await
        .unwrap();
    assert!(
        audits.is_empty(),
        "the 501 routes must not write an audit event"
    );
}

#[tokio::test]
async fn ciam_password_reset_validates_and_atomically_replaces_credentials() {
    assert_atomic_password_reset(test_helpers::test_config()).await;
}

#[tokio::test]
async fn ciam_password_reset_uses_resolved_pepper_and_preserves_atomic_replacement() {
    let path = std::env::temp_dir().join(format!("qid-reset-pepper-{}", ulid::Ulid::new()));
    std::fs::write(&path, b"test-only-reset-pepper").unwrap();
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.password.argon2id = Argon2idCostConfig {
        memory_kib: 8,
        time_cost: 1,
        parallelism: 1,
    };
    config.realms[0].authentication.password.pepper =
        Some(qid_core::config::PasswordPepperConfig {
            active: "key1".into(),
            keys: [(
                "key1".into(),
                qid_core::config::PasswordSecretSource::File {
                    file: path.to_str().unwrap().into(),
                },
            )]
            .into(),
        });
    assert_atomic_password_reset(config).await;
    std::fs::remove_file(path).unwrap();
}

async fn assert_atomic_password_reset(config: QidConfig) {
    let peppered = config.realms[0].authentication.password.pepper.is_some();
    let (app, state) = setup_with_config(config, &["other"]).await;
    let now = qid_core::util::now_seconds();
    let expected_token = "known-valid-reset-token";
    let token = qid_core::models::PasswordResetToken {
        id: "reset-known".to_string(),
        realm_id: "test".to_string(),
        user_id: "user-ciam".to_string(),
        token_hash: qid_core::util::sha256_base64url(expected_token),
        device_id: Some("device-1".to_string()),
        risk_json: serde_json::json!({"score":10}),
        expires_at_epoch_seconds: now + 900,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: now,
    };
    state
        .repo
        .store_password_reset_token(&token)
        .await
        .expect("seed password reset token failed");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/test/ciam/password-reset/consume")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "token_id":"reset-known",
                        "token":"wrong-reset-token",
                        "device_id":"device-1",
                        "new_password":"new-secure-password",
                        "now_epoch_seconds":1800000200
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .repo
            .get_password_credential("user-ciam")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        state
            .repo
            .get_password_reset_token("reset-known")
            .await
            .unwrap()
            .unwrap()
            .consumed_at_epoch_seconds,
        None
    );

    for (realm, password, expected) in [
        ("other", "wrong-realm-password", StatusCode::BAD_REQUEST),
        ("test", "new-secure-password", StatusCode::OK),
        ("test", "replay-secure-password", StatusCode::BAD_REQUEST),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/{realm}/ciam/password-reset/consume"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "token_id": "reset-known", "token": expected_token,
                            "device_id": "device-1", "new_password": password,
                            "now_epoch_seconds": 1
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let credential = state
            .repo
            .get_password_credential("user-ciam")
            .await
            .unwrap();
        let token = state
            .repo
            .get_password_reset_token("reset-known")
            .await
            .unwrap()
            .unwrap();
        if realm == "other" {
            assert!(credential.is_none());
            assert!(token.consumed_at_epoch_seconds.is_none());
        } else {
            let credential = credential.unwrap();
            let owner = qid_crypto::realm_password_context(&state, "test").unwrap();
            assert_eq!(
                owner.verify("new-secure-password", &credential),
                (true, false)
            );
            assert_eq!(credential.hash.contains("keyid=a2V5MQ"), peppered);
            assert!(!credential.hash.contains("test-only-reset-pepper"));
            assert_eq!(credential.algorithm, qid_crypto::ARGON2ID_ALGORITHM);
            assert!(token.consumed_at_epoch_seconds.unwrap() >= now);
        }
    }
}

#[tokio::test]
async fn ciam_protection_evaluation_rate_limits_and_records_audit() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let protection_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/protection/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                "user_id":"user-ciam",
                "client_id":"client-ciam",
                "action":"login",
                "ip":"203.0.113.10",
                "asn":"64500",
                "device_id":"device-1",
                "user_agent":"test-agent",
                "known_bad_ip":false,
                "automation_signals":[],
                "recent_attempts":25,
                "failed_attempts":10,
                "window_seconds":300,
                "now_epoch_seconds":1800000300
            }"#,
            ))
            .unwrap(),
        &cookie,
    );

    let response = app.oneshot(protection_request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["decision"]["outcome"], "rate_limit");
    assert_eq!(body["decision"]["retry_after_seconds"], 300);
    assert!(
        body["decision"]["rate_limit_key"]
            .as_str()
            .unwrap()
            .starts_with("ciam_rate_")
    );
    let realm_id = RealmId("test".to_string());
    let audits = state
        .repo
        .list_audit_events(Some(&realm_id), 10)
        .await
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].action, "ciam.protection.evaluate");
    assert_eq!(audits[0].actor, "user-ciam");
    assert_eq!(audits[0].metadata_json["outcome"], "rate_limit");
}

#[tokio::test]
async fn ciam_progressive_profiles_keep_concatenation_collision_owners_independent() {
    let (app, state) = setup_with_realms(&["team_blue", "team"]).await;
    let owners = [("team_blue", "person"), ("team", "blue_person")];
    for (realm, user) in owners {
        state
            .repo
            .create_user(&User {
                id: user.to_string(),
                realm_id: realm.to_string(),
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
    // Exercise each route's profile creation path as well as same-owner updates.
    let cookies = [
        add_session_in_realm(&state, owners[0].0, owners[0].1).await,
        add_session_in_realm(&state, owners[1].0, owners[1].1).await,
    ];
    for create_action in ["profile/submit", "passwordless/migrate"] {
        for (realm, user) in owners {
            state
                .repo
                .delete_ciam_progressive_profile(&realm.into(), user)
                .await
                .unwrap();
        }
        for action in [create_action, "profile/submit", "passwordless/migrate"] {
            for ((realm, user), cookie) in owners.into_iter().zip(&cookies) {
                let response = app
                    .clone()
                    .oneshot(with_cookie(
                        Request::builder()
                            .method(Method::POST)
                            .uri(format!("/api/v1/{realm}/ciam/{action}"))
                            .header("Content-Type", "application/json")
                            .body(Body::from(
                                serde_json::json!({
                                    "user_id": user,
                                    "profile": {"name": user},
                                })
                                .to_string(),
                            ))
                            .unwrap(),
                        cookie,
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{realm}/{action}");
            }
        }
        let first = state
            .repo
            .get_ciam_progressive_profile(&"team_blue".into(), "person")
            .await
            .unwrap()
            .unwrap();
        let second = state
            .repo
            .get_ciam_progressive_profile(&"team".into(), "blue_person")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(first.id, second.id);
        for (profile, (realm, user)) in [first, second].into_iter().zip(owners) {
            assert_eq!(profile.realm_id, realm);
            assert_eq!(profile.user_id, user);
            assert_eq!(profile.profile_json, serde_json::json!({"name": user}));
            assert!(profile.passwordless_migrated_at.is_some());
        }
    }
}

#[tokio::test]
async fn ciam_password_reset_creates_the_credential_with_the_realm_argon2id_cost() {
    // The realm states the cost the product hashes with, so the credential
    // a reset creates carries that cost rather than a library default.
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.password.argon2id = Argon2idCostConfig {
        memory_kib: 32768,
        time_cost: 3,
        parallelism: 1,
    };
    let (app, state) = setup_with_config(config, &[]).await;
    let now = qid_core::util::now_seconds();
    let token = PasswordResetToken {
        id: "reset-cost".to_string(),
        realm_id: "test".to_string(),
        user_id: "user-ciam".to_string(),
        token_hash: qid_core::util::sha256_base64url("known-valid-reset-token"),
        device_id: Some("device-1".to_string()),
        risk_json: serde_json::json!({"score":10}),
        expires_at_epoch_seconds: now + 900,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: now,
    };
    state
        .repo
        .store_password_reset_token(&token)
        .await
        .expect("seed password reset token failed");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/test/ciam/password-reset/consume")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "token_id":"reset-cost",
                        "token":"known-valid-reset-token",
                        "device_id":"device-1",
                        "new_password":"new-secure-password",
                        "now_epoch_seconds":1800000200
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let credential = state
        .repo
        .get_password_credential("user-ciam")
        .await
        .unwrap()
        .expect("the reset stored a credential");
    assert!(
        credential.hash.contains("m=32768"),
        "the realm's memory cost applies: {}",
        credential.hash
    );
    assert!(
        credential.hash.contains("t=3"),
        "the realm's time cost applies: {}",
        credential.hash
    );
}

#[derive(Default)]
struct VerificationDelivery {
    requests: std::sync::Mutex<Vec<qid_core::notification::NotificationRequest>>,
    outcome: AtomicU16,
}

#[async_trait::async_trait]
impl qid_core::notification::NotificationTransport for VerificationDelivery {
    async fn send(
        &self,
        request: qid_core::notification::NotificationRequest,
    ) -> Result<qid_core::notification::NotificationResponse, String> {
        // Even debug logging by a transport must not reveal delivery content.
        tracing::debug!(?request, "mock delivery");
        self.requests.lock().unwrap().push(request.clone());
        let status = self.outcome.load(Ordering::Relaxed);
        if status == 0 {
            return Err(format!("untrusted adapter error {}", request.body));
        }
        Ok(qid_core::notification::NotificationResponse {
            status,
            sent: status != 202,
            provider_message_id: Some(request.body),
        })
    }
}

fn verification_config() -> QidConfig {
    let mut config = test_helpers::test_config();
    config.server.notification = Some(qid_core::config::ServerNotificationConfig {
        provider: "https://delivery.example.com/private-adapter".into(),
        timeout_seconds: 10,
    });
    config
}

async fn verification_post(
    app: &axum::Router,
    realm: &str,
    action: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/{realm}/ciam/verification/{action}"))
        .header("Content-Type", "application/json");
    if let Some(cookie) = cookie {
        req = req.header("Cookie", cookie);
    }
    app.clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn delivered(
    app: &axum::Router,
    cookie: &str,
    delivery: &VerificationDelivery,
) -> (String, String) {
    let response =
        verification_post(app, "test", "issue", Some(cookie), serde_json::json!({})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body.as_object().unwrap().len(), 2);
    let id = body["challenge_id"].as_str().unwrap().to_owned();
    let requests = delivery.requests.lock().unwrap();
    let request = requests.last().unwrap();
    assert_eq!(
        request.channel,
        qid_core::notification::NotificationChannel::Email
    );
    assert_eq!(request.recipient, "ciam@example.com");
    assert!(request.body.contains(&id));
    let code = request
        .body
        .lines()
        .find_map(|line| line.strip_prefix("Code: "))
        .unwrap()
        .to_owned();
    assert_eq!(code.len(), 43);
    let debug = format!("{request:?}");
    for secret in [&code, &request.recipient, &request.provider] {
        assert!(!debug.contains(secret));
        assert!(!body.to_string().contains(secret));
    }
    (id, code)
}

fn confirmation(id: &str, code: &str) -> serde_json::Value {
    serde_json::json!({"challenge_id":id,"code":code})
}

#[tokio::test]
async fn email_verification_requires_session_configuration_and_accepted_delivery() {
    let delivery = Arc::new(VerificationDelivery::default());
    for (config, transport) in [
        (test_helpers::test_config(), None),
        (verification_config(), None),
        (
            test_helpers::test_config(),
            Some(delivery.clone() as Arc<dyn qid_core::notification::NotificationTransport>),
        ),
    ] {
        let (app, state) = setup_with_transport(config, &[], transport).await;
        assert_eq!(
            verification_post(&app, "test", "issue", None, serde_json::json!({}))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let cookie = add_session(&state, "user-ciam").await;
        assert_eq!(
            verification_post(&app, "test", "issue", Some(&cookie), serde_json::json!({}))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let (app, state) =
        setup_with_transport(verification_config(), &[], Some(delivery.clone())).await;
    let cookie = add_session(&state, "user-ciam").await;
    // No request authority other than the session and trusted stored email.
    for field in [
        "user_id",
        "address",
        "channel",
        "purpose",
        "now_epoch_seconds",
        "ttl_seconds",
        "code_hash",
        "expires_at_epoch_seconds",
    ] {
        assert_eq!(
            verification_post(
                &app,
                "test",
                "issue",
                Some(&cookie),
                serde_json::json!({field:"forged"})
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let mut body = confirmation("unknown", "code");
        body[field] = "forged".into();
        assert_eq!(
            verification_post(&app, "test", "confirm", Some(&cookie), body)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for status in [0, 202, 400, 500] {
        delivery.outcome.store(status, Ordering::Relaxed);
        let response =
            verification_post(&app, "test", "issue", Some(&cookie), serde_json::json!({})).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json(response).await.to_string();
        let request = delivery.requests.lock().unwrap().last().unwrap().clone();
        assert!(!body.contains("Code:"));
        assert!(!body.contains(&request.recipient));
        let id = request
            .body
            .lines()
            .next()
            .unwrap()
            .strip_prefix("Email verification challenge: ")
            .unwrap();
        assert!(
            state
                .repo
                .get_ciam_verification_challenge(&"test".into(), id)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        state
            .repo
            .list_audit_events(Some(&"test".into()), 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn email_verification_survives_state_restart_is_session_bound_and_one_use() {
    let delivery = Arc::new(VerificationDelivery::default());
    delivery.outcome.store(200, Ordering::Relaxed);
    let (app, state) =
        setup_with_transport(verification_config(), &["other"], Some(delivery.clone())).await;
    let cookie = add_session(&state, "user-ciam").await;
    let (id, code) = delivered(&app, &cookie, &delivery).await;
    let challenge = state
        .repo
        .get_ciam_verification_challenge(&"test".into(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        challenge.expires_at_epoch_seconds - challenge.created_at_epoch_seconds,
        600
    );
    assert!(!serde_json::to_string(&challenge).unwrap().contains(&code));
    let audits = state
        .repo
        .list_audit_events(Some(&"test".into()), 100)
        .await
        .unwrap();
    let audit = serde_json::to_string(&audits).unwrap();
    assert!(audit.contains(&id));
    assert!(audit.contains("200"));
    for secret in [
        &code,
        "ciam@example.com",
        "private-adapter",
        "provider_message_id",
    ] {
        assert!(!audit.contains(secret));
    }
    assert_eq!(
        verification_post(&app, "test", "confirm", None, confirmation(&id, &code))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        verification_post(
            &app,
            "other",
            "confirm",
            Some(&cookie),
            confirmation(&id, &code)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut user = state
        .repo
        .get_user_by_id("user-ciam")
        .await
        .unwrap()
        .unwrap();
    user.id = "another-user".into();
    user.email = Some("another@example.com".into());
    state.repo.create_user(&user).await.unwrap();
    let other_cookie = add_session(&state, &user.id).await;
    assert_eq!(
        verification_post(
            &app,
            "test",
            "confirm",
            Some(&other_cookie),
            confirmation(&id, &code)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    user.id = "realm-other-user".into();
    user.realm_id = "other".into();
    state.repo.create_user(&user).await.unwrap();
    let foreign_cookie = add_session_in_realm(&state, "other", &user.id).await;
    assert_eq!(
        verification_post(
            &app,
            "other",
            "confirm",
            Some(&foreign_cookie),
            confirmation(&id, &code)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        state
            .repo
            .get_ciam_verification_challenge(&"test".into(), &id)
            .await
            .unwrap()
            .unwrap()
            .attempt_count,
        0
    );
    // Fresh state has no transport. Confirmation is based only on persisted
    // authority, so it works after a restart/outage.
    let fresh = Arc::new(
        SharedState::new(
            state.config.clone(),
            state.repo.clone(),
            Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests")),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let app = qid_resource::resource_routes(&fresh.paths).with_state(fresh);
    for (status, verified) in [(StatusCode::OK, true), (StatusCode::BAD_REQUEST, true)] {
        assert_eq!(
            verification_post(
                &app,
                "test",
                "confirm",
                Some(&cookie),
                confirmation(&id, &code)
            )
            .await
            .status(),
            status
        );
        assert_eq!(
            state
                .repo
                .get_user_by_id("user-ciam")
                .await
                .unwrap()
                .unwrap()
                .email_verified,
            verified
        );
    }
    let row = state
        .repo
        .get_ciam_verification_challenge(&"test".into(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.attempt_count, 1);
    assert!(row.consumed_at_epoch_seconds.is_some());
}

#[tokio::test]
async fn email_verification_bounds_attempts_rejects_stale_email_and_expiry() {
    let delivery = Arc::new(VerificationDelivery::default());
    delivery.outcome.store(204, Ordering::Relaxed);
    let mut config = verification_config();
    config.realms[0]
        .authentication
        .email_verification
        .max_attempts = 2;
    config.realms[0]
        .authentication
        .email_verification
        .ttl_seconds = 60;
    let (app, state) = setup_with_transport(config, &[], Some(delivery.clone())).await;
    let cookie = add_session(&state, "user-ciam").await;
    let (id, code) = delivered(&app, &cookie, &delivery).await;
    assert_eq!(
        verification_post(
            &app,
            "test",
            "confirm",
            Some(&cookie),
            confirmation(&id, &"x".repeat(129))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    for candidate in ["wrong", "", &code] {
        assert_eq!(
            verification_post(
                &app,
                "test",
                "confirm",
                Some(&cookie),
                confirmation(&id, candidate)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let row = state
        .repo
        .get_ciam_verification_challenge(&"test".into(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.expires_at_epoch_seconds - row.created_at_epoch_seconds,
        60
    );
    assert_eq!(row.attempt_count, 2);
    assert!(row.consumed_at_epoch_seconds.is_none());
    let (stale, code) = delivered(&app, &cookie, &delivery).await;
    let mut user = state
        .repo
        .get_user_by_id("user-ciam")
        .await
        .unwrap()
        .unwrap();
    user.email = Some("new@example.com".into());
    state.repo.update_user(&user).await.unwrap();
    assert_eq!(
        verification_post(
            &app,
            "test",
            "confirm",
            Some(&cookie),
            confirmation(&stale, &code)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let mut expired = row;
    expired.id = "expired-challenge".into();
    expired.address = "new@example.com".into();
    expired.attempt_count = 0;
    expired.expires_at_epoch_seconds = qid_core::util::now_seconds().saturating_sub(1);
    expired.created_at_epoch_seconds = expired.expires_at_epoch_seconds.saturating_sub(10);
    state
        .repo
        .store_ciam_verification_challenge(&expired)
        .await
        .unwrap();
    for id in [&expired.id, "unknown"] {
        assert_eq!(
            verification_post(
                &app,
                "test",
                "confirm",
                Some(&cookie),
                confirmation(id, &code)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for id in [&stale, &expired.id] {
        let row = state
            .repo
            .get_ciam_verification_challenge(&"test".into(), id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.attempt_count, 0);
        assert!(row.consumed_at_epoch_seconds.is_none());
    }
    assert!(
        !state
            .repo
            .get_user_by_id("user-ciam")
            .await
            .unwrap()
            .unwrap()
            .email_verified
    );
}

#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn email_verification_logs_are_redacted_even_for_secret_bearing_adapter_errors() {
    use tracing::instrument::WithSubscriber;
    let delivery = Arc::new(VerificationDelivery::default());
    let (app, state) =
        setup_with_transport(verification_config(), &[], Some(delivery.clone())).await;
    let cookie = add_session(&state, "user-ciam").await;
    let capture = LogCapture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    async {
        delivery.outcome.store(200, Ordering::Relaxed);
        let (id, code) = delivered(&app, &cookie, &delivery).await;
        assert_eq!(
            verification_post(
                &app,
                "test",
                "confirm",
                Some(&cookie),
                confirmation(&id, &code)
            )
            .await
            .status(),
            StatusCode::OK
        );
        delivery.outcome.store(0, Ordering::Relaxed);
        assert_eq!(
            verification_post(&app, "test", "issue", Some(&cookie), serde_json::json!({}))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    .with_subscriber(subscriber)
    .await;
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("mock delivery"));
    for request in delivery.requests.lock().unwrap().iter() {
        let code = request
            .body
            .lines()
            .find_map(|line| line.strip_prefix("Code: "))
            .unwrap();
        for secret in [
            code,
            &request.recipient,
            &request.provider,
            "untrusted adapter error",
        ] {
            assert!(!logs.contains(secret), "logs exposed delivery data");
        }
    }
}
