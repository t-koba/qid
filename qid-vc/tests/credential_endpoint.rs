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
    let state = Arc::new(
        SharedState::new(
            test_helpers::test_config(),
            repo,
            signer,
            serde_json::json!({}),
        )
        .unwrap(),
    );
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
    let binding = qid_vc::holder_binding_from_jwk(public_jwk).unwrap();
    sign_es256_jwt_with_jwk_header(
        private_pem.as_bytes(),
        public_jwk,
        "openid4vci-proof+jwt",
        &serde_json::json!({
            "iss": binding.jwk_thumbprint,
            "aud": "https://id.example.com",
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
    let token_data = state.signer.decode_signature_only(&credential_jwt).unwrap();
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
    assert_eq!(status_body["subject"], "vc-user");
    assert_eq!(status_body["revoked"], false);

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
    let verify_body = serde_json::json!({
        "credential": body["credential"].clone(),
        "disclosed_claims": {
            "email": "vc@example.com"
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
    let token_data = state.signer.decode_signature_only(credential_jwt).unwrap();
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
