use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{models::User, state::SharedState, test_helpers, util};
use qid_crypto::{LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};
use qid_oauth::endpoints::{TokenIssueClaims, issue_access_token};
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_vc");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let value = name.to_string_lossy();
            if value.starts_with("test_") && value.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let sequence = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{sequence}.db"));
    format!("sqlite:{}", path.display())
}

fn vc_keyring(realm: &str, name: &str) -> qid_core::config::KeyringConfig {
    qid_core::config::KeyringConfig {
        name: name.into(),
        realm_id: Some(realm.into()),
        purposes: vec!["other:vc_issuer".into()],
        signer: Default::default(),
        rotation: Default::default(),
    }
}

async fn setup() -> (Router, Arc<SharedState<SqlRepository>>, User) {
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
    let user = User {
        id: "vc-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("vc@example.com".to_string()),
        email_verified: true,
        display_name: Some("VC User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.unwrap();

    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-vc"));
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.vc.issuer_key_ref = Some("vc-test".into());
    config.crypto.keyrings = vec![
        qid_core::config::KeyringConfig {
            name: "oidc-primary".into(),
            realm_id: None,
            purposes: vec!["oidc_token".into()],
            signer: Default::default(),
            rotation: Default::default(),
        },
        vc_keyring("test", "vc-test"),
    ];
    let mut state = SharedState::new(config, repo, signer, serde_json::json!({})).unwrap();
    state.vc_issuer_signers.insert(
        "test".into(),
        Arc::new(LocalSigner::from_secret("vc-test", b"dedicated-vc-secret")),
    );
    let state = Arc::new(state);
    let app = qid_vc::vc_routes::<SqlRepository>().with_state(state.clone());
    (app, state, user)
}

async fn issue_identity_access_token(state: &SharedState<SqlRepository>, user: &User) -> String {
    let (access_token, _) = issue_access_token(
        state,
        "https://id.example.com",
        user,
        "vc-client",
        "test",
        &["openid".to_string(), "qid_identity".to_string()],
        TokenIssueClaims {
            authorization_code: None,
            access_token: None,
            access_expires_at: None,
            session_id: None,
            audience: None,
            resource: None,
            authorization_details: None,
            cnf: None,
            auth_time: Some(util::now_seconds()),
            acr: None,
            amr: Some(&["pwd".to_string()]),
            nonce: None,
            act: None,
        },
    )
    .await
    .unwrap();
    access_token
}

fn credential_proof(private_pem: &str, public_jwk: &qid_crypto::Jwk, nonce: &str) -> String {
    credential_proof_for_issuer(private_pem, public_jwk, nonce, "https://id.example.com")
}

fn credential_proof_for_issuer(
    private_pem: &str,
    public_jwk: &qid_crypto::Jwk,
    nonce: &str,
    issuer: &str,
) -> String {
    let binding = qid_vc::holder_binding_from_jwk(public_jwk).unwrap();
    sign_es256_jwt_with_jwk_header(
        private_pem.as_bytes(),
        public_jwk,
        "openid4vci-proof+jwt",
        &serde_json::json!({
            "iss": binding.jwk_thumbprint,
            "aud": issuer,
            "nonce": nonce,
            "iat": util::now_seconds(),
            "jti": format!("proof-{}", ulid::Ulid::new()),
            "cnf": { "jkt": binding.jwk_thumbprint }
        }),
    )
    .unwrap()
}

#[tokio::test]
async fn credential_endpoint_issues_sd_jwt_for_authorized_scope() {
    let (app, state, user) = setup().await;
    let holder_key = generate_es256("holder").unwrap();
    let holder_thumbprint = qid_vc::holder_binding_from_jwk(&holder_key.public_jwk)
        .unwrap()
        .jwk_thumbprint;
    let nonce = "credential-nonce-1";
    let proof = credential_proof(&holder_key.private_pem, &holder_key.public_jwk, nonce);
    let (access_token, _) = issue_access_token(
        &state,
        "https://id.example.com",
        &user,
        "vc-client",
        "test",
        &["openid".to_string(), "qid_identity".to_string()],
        TokenIssueClaims {
            authorization_code: None,
            access_token: None,
            access_expires_at: None,
            session_id: None,
            audience: None,
            resource: None,
            authorization_details: None,
            cnf: None,
            auth_time: Some(util::now_seconds()),
            acr: None,
            amr: Some(&["pwd".to_string()]),
            nonce: None,
            act: None,
        },
    )
    .await
    .unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/credential")
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "credential_configuration_id": "qid_identity_sd_jwt",
                "claims": ["sub", "email", "name"],
                "selectively_disclosed_claims": ["email"],
                "lifetime_seconds": 900,
                "holder_jwk": holder_key.public_jwk,
                "proof": { "jwt": proof },
                "nonce": nonce
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let credential_jwt = body["credential"].as_str().unwrap().to_string();
    let token_data = state.vc_issuer_signers["test"]
        .decode_signature_only(&credential_jwt)
        .unwrap();
    let vc = token_data.claims.extra.get("vc").unwrap();

    let credential_id = vc["status"]["credential_id"].as_str().unwrap().to_string();
    assert_eq!(body["format"], "sd_jwt_vc");
    assert_eq!(vc["issuer"], "https://id.example.com");
    assert_eq!(vc["subject"], "vc-user");
    assert_eq!(vc["visible_claims"]["sub"], "vc-user");
    assert_eq!(vc["visible_claims"]["name"], "VC User");
    assert!(vc["visible_claims"]["email"].is_null());
    assert_eq!(vc["disclosures"][0]["claim_name"], "email");
    assert_eq!(vc["holder_binding"]["jwk_thumbprint"], holder_thumbprint);
    assert_eq!(
        vc["status"]["status_list_uri"],
        format!("https://id.example.com/vc/v1/status/{credential_id}")
    );

    let status_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/vc/v1/status/{credential_id}"))
        .body(Body::empty())
        .unwrap();
    let status_response = app.clone().oneshot(status_request).await.unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_bytes = status_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let status_body: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();
    assert_eq!(status_body["credential_id"], credential_id);
    assert_eq!(status_body["revoked"], false);
    assert!(status_body["expires_at"].as_u64().is_some());
    // The public lookup carries no subject identity or revocation details.
    assert!(status_body.get("subject").is_none());
    assert!(status_body.get("revocation_reason").is_none());
    assert!(status_body.get("revoked_at").is_none());

    let issued_at = vc["issued_at"].as_u64().unwrap();
    let proof = sign_es256_jwt_with_jwk_header(
        holder_key.private_pem.as_bytes(),
        &holder_key.public_jwk,
        "openid4vp-proof+jwt",
        &serde_json::json!({
            "iss": holder_thumbprint,
            "aud": "https://verifier.example",
            "nonce": "nonce-1",
            "iat": issued_at,
            "jti": "proof-1",
            "credential_id": credential_id,
            "cnf": { "jkt": holder_thumbprint }
        }),
    )
    .unwrap();
    let email_salt = body["disclosures"][0]["salt"].as_str().unwrap();
    let verify_body = serde_json::json!({
        "credential": body["credential"].clone(),
        "disclosed_claims": {
            "email": { "value": "vc@example.com", "salt": email_salt }
        },
        "required_claims": ["sub", "email"],
        "now_epoch_seconds": issued_at,
        "presentation_proof": { "jwt": proof },
        "expected_audience": "https://verifier.example",
        "nonce": "nonce-1"
    });
    let verify_request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/presentation/verify")
        .header("content-type", "application/json")
        .body(Body::from(verify_body.to_string()))
        .unwrap();
    let verify_response = app.clone().oneshot(verify_request).await.unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_bytes = verify_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let verify_result: serde_json::Value = serde_json::from_slice(&verify_bytes).unwrap();
    assert_eq!(verify_result["credential_id"], credential_id);
    assert_eq!(verify_result["verified_claims"]["email"], "vc@example.com");

    let revoke_request = Request::builder()
        .method(Method::POST)
        .uri(format!("/vc/v1/status/{credential_id}/revoke"))
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "reason": "account_closed" }).to_string(),
        ))
        .unwrap();
    let revoke_response = app.clone().oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_bytes = revoke_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let revoke_body: serde_json::Value = serde_json::from_slice(&revoke_bytes).unwrap();
    assert_eq!(revoke_body["credential_id"], credential_id);
    assert_eq!(revoke_body["revoked"], true);
    assert_eq!(revoke_body["revocation_reason"], "account_closed");

    let revoked_verify_request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/presentation/verify")
        .header("content-type", "application/json")
        .body(Body::from(verify_body.to_string()))
        .unwrap();
    let revoked_verify_response = app.clone().oneshot(revoked_verify_request).await.unwrap();
    assert_eq!(revoked_verify_response.status(), StatusCode::BAD_REQUEST);
    let revoked_verify_bytes = revoked_verify_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let revoked_verify_body: serde_json::Value =
        serde_json::from_slice(&revoked_verify_bytes).unwrap();
    assert_eq!(revoked_verify_body["error"], "invalid_request");
}

#[tokio::test]
async fn credential_revoke_requires_credential_owner() {
    let (app, state, user) = setup().await;
    let owner_token = issue_identity_access_token(&state, &user).await;
    let holder_key = generate_es256("revoke-owner-holder").unwrap();
    let nonce = "credential-revoke-nonce";
    let proof = credential_proof(&holder_key.private_pem, &holder_key.public_jwk, nonce);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/credential")
        .header("authorization", format!("Bearer {owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "credential_configuration_id": "qid_identity_sd_jwt",
                "claims": ["sub"],
                "selectively_disclosed_claims": [],
                "lifetime_seconds": 900,
                "holder_jwk": holder_key.public_jwk,
                "proof": { "jwt": proof },
                "nonce": nonce
            })
            .to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let credential_jwt = body["credential"].as_str().unwrap();
    let token_data = state.vc_issuer_signers["test"]
        .decode_signature_only(credential_jwt)
        .unwrap();
    let credential_id = token_data.claims.extra["vc"]["status"]["credential_id"]
        .as_str()
        .unwrap()
        .to_string();

    let other = User {
        id: "other-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("other@example.com".to_string()),
        email_verified: true,
        display_name: Some("Other User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&other).await.unwrap();
    let other_token = issue_identity_access_token(&state, &other).await;

    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/vc/v1/status/{credential_id}/revoke"))
                .header("authorization", format!("Bearer {other_token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"owner_request"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::UNAUTHORIZED);
    let status = state
        .repo
        .get_vc_credential_status(&credential_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!status.revoked);

    let revoke_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/vc/v1/status/{credential_id}/revoke"))
                .header("authorization", format!("Bearer {owner_token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"owner_request"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn credential_endpoint_rejects_missing_scope() {
    let (app, state, user) = setup().await;
    let (access_token, _) = issue_access_token(
        &state,
        "https://id.example.com",
        &user,
        "vc-client",
        "test",
        &["openid".to_string()],
        TokenIssueClaims {
            authorization_code: None,
            access_token: None,
            access_expires_at: None,
            session_id: None,
            audience: None,
            resource: None,
            authorization_details: None,
            cnf: None,
            auth_time: None,
            acr: None,
            amr: None,
            nonce: None,
            act: None,
        },
    )
    .await
    .unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/credential")
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn credential_issuer_metadata_advertises_supported_configuration() {
    let (app, _, _) = setup().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/openid-credential-issuer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["credential_issuer"], "https://id.example.com");
    assert_eq!(
        body["credential_configurations_supported"]["qid_identity_sd_jwt"]["scope"],
        "openid qid_identity"
    );
}

#[tokio::test]
async fn credential_second_issuance_revokes_independently() {
    async fn issue_credential(
        app: Router,
        access_token: &str,
        holder: &qid_crypto::jwk::GeneratedKeyPair,
        nonce: &str,
        lifetime_seconds: u64,
    ) -> (String, String) {
        let proof = credential_proof(&holder.private_pem, &holder.public_jwk, nonce);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/vc/v1/credential")
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "credential_configuration_id": "qid_identity_sd_jwt",
                    "claims": ["sub", "email", "name"],
                    "selectively_disclosed_claims": ["email"],
                    "lifetime_seconds": lifetime_seconds,
                    "holder_jwk": holder.public_jwk,
                    "proof": { "jwt": proof },
                    "nonce": nonce
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (
            body["credential"].as_str().unwrap().to_string(),
            body["disclosures"][0]["salt"].as_str().unwrap().to_string(),
        )
    }

    fn credential_id_of(state: &Arc<SharedState<SqlRepository>>, credential_jwt: &str) -> String {
        let token_data = state.vc_issuer_signers["test"]
            .decode_signature_only(credential_jwt)
            .unwrap();
        token_data.claims.extra.get("vc").unwrap()["status"]["credential_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    let (app, state, user) = setup().await;
    let access_token = issue_identity_access_token(&state, &user).await;
    let first_holder = generate_es256("holder-first").unwrap();
    let second_holder = generate_es256("holder-second").unwrap();
    let (first_jwt, _) = issue_credential(
        app.clone(),
        &access_token,
        &first_holder,
        "nonce-first",
        900,
    )
    .await;
    let (second_jwt, second_salt) = issue_credential(
        app.clone(),
        &access_token,
        &second_holder,
        "nonce-second",
        3600,
    )
    .await;
    let first_id = credential_id_of(&state, &first_jwt);
    let second_id = credential_id_of(&state, &second_jwt);
    assert_ne!(
        first_id, second_id,
        "separate issuances must not share an identifier"
    );

    // Revoking the first credential leaves the second verifiable.
    let revoke_request = Request::builder()
        .method(Method::POST)
        .uri(format!("/vc/v1/status/{first_id}/revoke"))
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "reason": "key_compromised" }).to_string(),
        ))
        .unwrap();
    let revoke_response = app.clone().oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let thumbprint = qid_vc::holder_binding_from_jwk(&second_holder.public_jwk)
        .unwrap()
        .jwk_thumbprint;
    let proof = sign_es256_jwt_with_jwk_header(
        second_holder.private_pem.as_bytes(),
        &second_holder.public_jwk,
        "openid4vp-proof+jwt",
        &serde_json::json!({
            "iss": thumbprint,
            "aud": "https://verifier.example",
            "nonce": "nonce-verify",
            "iat": util::now_seconds(),
            "jti": "proof-second",
            "credential_id": second_id,
            "cnf": { "jkt": thumbprint }
        }),
    )
    .unwrap();
    let verify_request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/presentation/verify")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "credential": second_jwt,
                "disclosed_claims": { "email": { "value": "vc@example.com", "salt": second_salt } },
                "required_claims": ["sub", "email"],
                "presentation_proof": { "jwt": proof },
                "expected_audience": "https://verifier.example",
                "nonce": "nonce-verify"
            })
            .to_string(),
        ))
        .unwrap();
    let verify_response = app.clone().oneshot(verify_request).await.unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn credential_issuance_rejects_overflowing_lifetime() {
    let (app, state, user) = setup().await;
    let access_token = issue_identity_access_token(&state, &user).await;
    let holder = generate_es256("holder-overflow").unwrap();
    let proof = credential_proof(&holder.private_pem, &holder.public_jwk, "nonce-overflow");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/vc/v1/credential")
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "credential_configuration_id": "qid_identity_sd_jwt",
                "claims": ["sub"],
                "lifetime_seconds": u64::MAX,
                "holder_jwk": holder.public_jwk,
                "proof": { "jwt": proof },
                "nonce": "nonce-overflow"
            })
            .to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn credential_issuance_enforces_configured_lifetime_ceiling() {
    // The default ceiling (86400) is representable, so only the policy
    // ceiling can reject 86401; the boundary value itself must succeed.
    async fn issue_with_lifetime(
        app: Router,
        access_token: &str,
        holder_private_pem: &str,
        holder_jwk: &qid_crypto::Jwk,
        nonce: &str,
        lifetime_seconds: u64,
    ) -> StatusCode {
        let proof = credential_proof(holder_private_pem, holder_jwk, nonce);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/vc/v1/credential")
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "credential_configuration_id": "qid_identity_sd_jwt",
                    "claims": ["sub"],
                    "lifetime_seconds": lifetime_seconds,
                    "holder_jwk": holder_jwk,
                    "proof": { "jwt": proof },
                    "nonce": nonce
                })
                .to_string(),
            ))
            .unwrap();
        app.oneshot(request).await.unwrap().status()
    }

    let (app, state, user) = setup().await;
    let access_token = issue_identity_access_token(&state, &user).await;
    let holder = generate_es256("holder-ceiling").unwrap();
    for (nonce, lifetime, expected) in [
        ("nonce-ceiling-ok", 86400, StatusCode::OK),
        ("nonce-ceiling-over", 86401, StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            issue_with_lifetime(
                app.clone(),
                &access_token,
                &holder.private_pem,
                &holder.public_jwk,
                nonce,
                lifetime,
            )
            .await,
            expected,
            "lifetime {lifetime} must map to {expected:?}"
        );
    }
}

#[tokio::test]
async fn credential_concurrent_issuances_use_distinct_revocable_identifiers() {
    use std::collections::HashSet;

    const PARALLEL_ISSUANCES: usize = 8;

    let (app, state, user) = setup().await;
    let access_token = issue_identity_access_token(&state, &user).await;

    // Same subject issued back-to-back (same second) with distinct holders and
    // alternating lifetimes, so a time/claim-derived identifier would collide.
    let mut handles = Vec::with_capacity(PARALLEL_ISSUANCES);
    for index in 0..PARALLEL_ISSUANCES {
        let app = app.clone();
        let access_token = access_token.clone();
        let holder = generate_es256(format!("holder-concurrent-{index}")).unwrap();
        let lifetime_seconds = if index % 2 == 0 { 900 } else { 3600 };
        let nonce = format!("nonce-concurrent-{index}");
        handles.push(tokio::spawn(async move {
            let proof = credential_proof(&holder.private_pem, &holder.public_jwk, &nonce);
            let request = Request::builder()
                .method(Method::POST)
                .uri("/vc/v1/credential")
                .header("authorization", format!("Bearer {access_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "credential_configuration_id": "qid_identity_sd_jwt",
                        "claims": ["sub", "email"],
                        "selectively_disclosed_claims": [],
                        "lifetime_seconds": lifetime_seconds,
                        "holder_jwk": holder.public_jwk,
                        "proof": { "jwt": proof },
                        "nonce": nonce
                    })
                    .to_string(),
                ))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            body["credential"].as_str().unwrap().to_string()
        }));
    }

    let mut credential_jwts = Vec::with_capacity(PARALLEL_ISSUANCES);
    for handle in handles {
        credential_jwts.push(handle.await.unwrap());
    }

    let mut credential_ids = Vec::with_capacity(PARALLEL_ISSUANCES);
    for credential_jwt in &credential_jwts {
        let token_data = state.vc_issuer_signers["test"]
            .decode_signature_only(credential_jwt)
            .unwrap();
        credential_ids.push(
            token_data.claims.extra["vc"]["status"]["credential_id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(
        credential_ids.iter().collect::<HashSet<_>>().len(),
        PARALLEL_ISSUANCES,
        "concurrent issuances must not share an identifier"
    );
    for credential_id in &credential_ids {
        let stored = state
            .repo
            .get_vc_credential_status(credential_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.revoked);
    }
}

#[tokio::test]
async fn realm_issuers_isolate_credentials_keys_status_and_metadata() {
    let (app, state, first_user) = setup().await;
    drop(app);
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    state.config.realms[0].issuer = "https://id.example.com/realms/test".into();
    let mut second_realm = state.config.realms[0].clone();
    second_realm.id = "second".into();
    second_realm.issuer = "https://id.example.com/realms/second/".into();
    second_realm.protocols.vc.issuer_key_ref = Some("second-vc".into());
    state
        .repo
        .create_realm(
            &"tenant-1".into(),
            &"second".into(),
            &second_realm.issuer,
            None,
        )
        .await
        .unwrap();
    state.config.realms.push(second_realm);
    state
        .config
        .crypto
        .keyrings
        .push(vc_keyring("second", "second-vc"));
    state.vc_issuer_signers.insert(
        "second".into(),
        Arc::new(LocalSigner::from_secret("second-vc", b"another-vc-secret")),
    );
    state.plan = qid_core::plan::RuntimePlan::from_config(&state.config).unwrap();
    let mut second_user = first_user.clone();
    second_user.id = "second-user".into();
    second_user.realm_id = "second".into();
    state.repo.create_user(&second_user).await.unwrap();
    let state = Arc::new(state);
    let holder = generate_es256("holder").unwrap();
    let binding = qid_vc::holder_binding_from_jwk(&holder.public_jwk).unwrap();

    for user in [&first_user, &second_user] {
        let realm = state.plan.realm(&user.realm_id).unwrap();
        let id_token = qid_oauth::endpoints::issue_id_token(
            &state,
            &realm.issuer,
            user,
            "vc-client",
            &realm.id,
            &["openid".into()],
            TokenIssueClaims::default(),
            None,
        )
        .unwrap();
        assert_eq!(
            state
                .signer
                .decode_signature_only(&id_token)
                .unwrap()
                .claims
                .iss
                .as_deref(),
            Some(realm.issuer.as_str())
        );
        for signer in state.vc_issuer_signers.values() {
            assert!(signer.decode_signature_only(&id_token).is_err());
        }
        let (access_token, _) = issue_access_token(
            &state,
            &realm.issuer,
            user,
            "vc-client",
            &realm.id,
            &["openid".into(), "qid_identity".into()],
            TokenIssueClaims::default(),
        )
        .await
        .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let nonce = "realm-nonce";
        let make_request = |audience: &str| {
            serde_json::from_value(serde_json::json!({
            "claims": ["sub"], "holder_jwk": holder.public_jwk,
            "proof": { "jwt": credential_proof_for_issuer(&holder.private_pem, &holder.public_jwk, nonce, audience) },
            "nonce": nonce,
        })).unwrap()
        };
        // The shared deployment endpoint is not the issuing realm's proof audience.
        assert!(
            qid_vc::issue_credential_from_bearer(
                &state,
                &headers,
                make_request(&state.plan.public_base_url)
            )
            .await
            .is_err()
        );
        let issued =
            qid_vc::issue_credential_from_bearer(&state, &headers, make_request(&realm.issuer))
                .await
                .unwrap();
        let signer = &state.vc_issuer_signers[&realm.id];
        let token = signer.decode_signature_only(&issued.credential).unwrap();
        assert_eq!(token.claims.iss.as_deref(), Some(realm.issuer.as_str()));
        assert_eq!(token.claims.extra["vc"]["issuer"], realm.issuer);
        assert!(
            state
                .signer
                .decode_signature_only(&issued.credential)
                .is_err()
        );
        for (id, other_signer) in &state.vc_issuer_signers {
            if id != &realm.id {
                assert!(
                    other_signer
                        .decode_signature_only(&issued.credential)
                        .is_err()
                );
            }
        }
        let presentation_proof = sign_es256_jwt_with_jwk_header(
            holder.private_pem.as_bytes(),
            &holder.public_jwk,
            "openid4vp-proof+jwt",
            &serde_json::json!({
                "iss": binding.jwk_thumbprint, "aud": "https://verifier.example",
                "nonce": nonce, "iat": util::now_seconds(), "jti": "presentation",
                "credential_id": token.claims.extra["vc"]["status"]["credential_id"],
                "cnf": { "jkt": binding.jwk_thumbprint }
            }),
        )
        .unwrap();
        let request: qid_vc::PresentationVerificationRequest = serde_json::from_value(serde_json::json!({
            "credential": issued.credential, "presentation_proof": { "jwt": presentation_proof },
            "expected_audience": "https://verifier.example", "nonce": nonce
        })).unwrap();
        let verified = qid_vc::verify_presentation_with_status(&state, request.clone())
            .await
            .unwrap();
        assert_eq!(verified.issuer, realm.issuer);
        // Neither the primary signer nor another realm can assert this issuer.
        for (id, other_signer) in &state.vc_issuer_signers {
            if id == &realm.id {
                continue;
            }
            let mut forged = request.clone();
            forged.credential = other_signer.sign(&token.claims).unwrap();
            assert!(
                qid_vc::verify_presentation_with_status(&state, forged)
                    .await
                    .unwrap_err()
                    .message()
                    .contains("signature")
            );
        }
        let mut forged = request.clone();
        forged.credential = state.signer.sign(&token.claims).unwrap();
        assert!(
            qid_vc::verify_presentation_with_status(&state, forged)
                .await
                .is_err()
        );
        let mut foreign_claims = token.claims.clone();
        foreign_claims.iss = Some("https://untrusted.example".into());
        let mut forged = request.clone();
        forged.credential = signer.sign(&foreign_claims).unwrap();
        assert!(
            qid_vc::verify_presentation_with_status(&state, forged)
                .await
                .unwrap_err()
                .message()
                .contains("untrusted")
        );
        // A signature is not enough if the status record belongs to another realm.
        let mut wrong_status_credential: qid_vc::SdJwtCredential =
            serde_json::from_value(token.claims.extra["vc"].clone()).unwrap();
        wrong_status_credential.status.credential_id = ulid::Ulid::new().to_string();
        let status =
            qid_vc::issuer::credential_status_record("wrong-realm", &wrong_status_credential);
        state
            .repo
            .store_vc_credential_status(&status)
            .await
            .unwrap();
        let mut claims = token.claims.clone();
        claims.extra.insert(
            "vc".into(),
            serde_json::to_value(wrong_status_credential).unwrap(),
        );
        let mut forged = request.clone();
        forged.credential = signer.sign(&claims).unwrap();
        assert!(
            qid_vc::verify_presentation_with_status(&state, forged)
                .await
                .unwrap_err()
                .message()
                .contains("another realm")
        );
    }
    let app = qid_vc::vc_routes::<SqlRepository>().with_state(state.clone());
    for (path, expected) in [
        ("/.well-known/openid-credential-issuer", None),
        ("/.well-known/openid-credential-issuer/", None),
        (
            "/.well-known/openid-credential-issuer/realms/test",
            Some("https://id.example.com/realms/test"),
        ),
        ("/.well-known/openid-credential-issuer/realms/second", None),
        (
            "/.well-known/openid-credential-issuer/realms/second/",
            Some("https://id.example.com/realms/second/"),
        ),
        ("/.well-known/openid-credential-issuer/realms/missing", None),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if expected.is_some() {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            }
        );
        if let Some(issuer) = expected {
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["credential_issuer"], issuer);
            assert_eq!(
                body["jwks_uri"],
                format!("https://id.example.com{}", state.paths.jwks)
            );
        }
    }
}

#[tokio::test]
async fn single_realm_metadata_path_matches_exact_issuer_identifier() {
    let (app, state, _) = setup().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["credential_issuer"], "https://id.example.com");
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-credential-issuer/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    drop(app);

    let mut state = Arc::try_unwrap(state).ok().unwrap();
    state.config.realms[0].issuer = "https://id.example.com/credentials/corp//".into();
    state.config.realms[0].display_name = None;
    state.plan = qid_core::plan::RuntimePlan::from_config(&state.config).unwrap();
    let app = qid_vc::vc_routes::<SqlRepository>().with_state(Arc::new(state));
    for (path, expected) in [
        ("/.well-known/openid-credential-issuer", false),
        ("/.well-known/openid-credential-issuer/", false),
        ("/.well-known/openid-credential-issuer/realms/test/", false),
        (
            "/.well-known/openid-credential-issuer/credentials/corp/",
            false,
        ),
        (
            "/.well-known/openid-credential-issuer/credentials/corp//",
            true,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status() == StatusCode::OK, expected, "{path}");
        if expected {
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(
                body["credential_issuer"],
                "https://id.example.com/credentials/corp//"
            );
            assert_eq!(body["display"][0]["name"], "test");
        }
    }
}
