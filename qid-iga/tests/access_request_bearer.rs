mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    config::OAuthResourceServerConfig,
    models::{AccessToken, Client, ClientType, Session, User},
    state::SharedState,
    test_helpers,
    util::now_seconds,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

const AUDIENCE: &str = "api://iga";
const SCOPE: &str = "qid_iga_access_request";

#[tokio::test]
async fn bearer_access_requests_require_the_realm_audience_and_exact_scope_before_storage() {
    // Explicit stored tokens also cover empty audiences, which normal issuance
    // replaces with a client audience. A resource is never an audience substitute.
    for (name, configured, audiences, scopes, allowed) in [
        ("valid", true, vec![AUDIENCE], vec![SCOPE], true),
        (
            "multi-audience",
            true,
            vec!["api://other", AUDIENCE],
            vec!["openid", SCOPE],
            true,
        ),
        ("unconfigured", false, vec![AUDIENCE], vec![SCOPE], false),
        ("missing-audience", true, vec![], vec![SCOPE], false),
        (
            "wrong-audience",
            true,
            vec!["api://other"],
            vec![SCOPE],
            false,
        ),
        (
            "audience-prefix",
            true,
            vec!["api://iga/other"],
            vec![SCOPE],
            false,
        ),
        ("missing-scope", true, vec![AUDIENCE], vec![], false),
        (
            "wrong-scope",
            true,
            vec![AUDIENCE],
            vec!["qid_identity"],
            false,
        ),
        (
            "scope-prefix",
            true,
            vec![AUDIENCE],
            vec!["qid_iga_access_request_extra"],
            false,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let repo = Arc::new(
            FileRepository::new(dir.path().join("store.json").to_str().unwrap())
                .await
                .unwrap(),
        );
        repo.migrate().await.unwrap();
        repo.create_realm(
            &"test".into(),
            &"test".into(),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        common::seed_default_erp_catalog(&repo, "test").await;
        let mut config = test_helpers::test_config();
        config.realms[0].tenant_id = Some("test".into());
        config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
            audience: AUDIENCE.into(),
            resources: vec![],
            scopes: vec![SCOPE.into()],
            introspection_client_ids: vec![],
            require_sender_constraint: false,
            high_risk: false,
        }];
        config.realms[0].protocols.iga.access_request_audience =
            configured.then(|| AUDIENCE.into());
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let state = Arc::new(
            SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap(),
        );
        let jti = ulid::Ulid::new().to_string();
        let record: AccessToken = serde_json::from_value(serde_json::json!({
            "jti": jti, "family_id": null, "user_id": "user-1",
            "client_id": "iga-client", "realm_id": "test", "scopes": scopes,
            "audience": audiences, "resource": [AUDIENCE], "token_format": "opaque",
            "expires_at": now_seconds() + 300, "issued_at": now_seconds(), "revoked": false
        }))
        .unwrap();
        repo.create_access_token(&record).await.unwrap();
        let app = qid_iga::iga_routes().with_state(state);
        let response = app.oneshot(Request::builder()
            .method("POST").uri("/iga/v1/access-requests")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", qid_oauth::endpoints::encode_opaque_access_token(&jti)))
            .body(Body::from(serde_json::json!({
                "subject": "user-1", "entitlement": "app:erp:admin", "requested_duration_seconds": 3600
            }).to_string())).unwrap()).await.unwrap();
        assert_eq!(
            response.status(),
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            },
            "{name}"
        );
        let body = common::json(response).await;
        let stored = repo.list_iga_access_requests("test").await.unwrap();
        if allowed {
            assert_eq!(body["status"], "approval_required", "{name}");
            assert_eq!(stored.len(), 1, "{name}");
            assert_eq!(stored[0].id, body["id"].as_str().unwrap(), "{name}");
            assert_eq!(stored[0].subject, "user-1");
            assert_eq!(stored[0].approval_steps_json.as_array().unwrap().len(), 2);
        } else {
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("configured IGA audience"),
                "{name}: {body}"
            );
            assert!(stored.is_empty(), "denied request persisted: {name}");
        }
        // All repository owners are dropped before the temp directory, including
        // on Windows; each table case has a fresh isolated store.
        drop(repo);
    }
}

#[tokio::test]
async fn authorization_code_user_token_can_request_iga_access() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(
        FileRepository::new(dir.path().join("store.json").to_str().unwrap())
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    repo.create_realm(
        &"test".into(),
        &"test".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    common::seed_default_erp_catalog(&repo, "test").await;
    const REDIRECT: &str = "https://app.example.com/callback";
    repo.create_client(&Client {
        id: "iga-client-id".into(),
        realm_id: "test".into(),
        client_id: "iga-client".into(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".into(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: vec![],
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec![REDIRECT.into()],
        grant_types: vec!["authorization_code".into()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: vec![],
        post_logout_redirect_uris: vec![],
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
        require_pushed_authorization_requests: false,
    })
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-1".into(),
        realm_id: "test".into(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    // Start with an authenticated user session, not an AdminElevation or a
    // fabricated authorization code/access token. OIDC issues the actual code.
    let now = now_seconds();
    repo.create_session(&Session {
        id: "iga-browser-session".into(),
        realm_id: "test".into(),
        user_id: "user-1".into(),
        auth_time: now,
        acr: Some("urn:qid:acr:password".into()),
        amr: vec!["pwd".into()],
        idle_expires_at: now + 300,
        absolute_expires_at: now + 600,
        revoked: false,
        created_at: now,
        cnf: None,
    })
    .await
    .unwrap();
    let mut config = test_helpers::test_config();
    config.realms[0].tenant_id = Some("test".into());
    config.realms[0].protocols.iga.access_request_audience = Some(AUDIENCE.into());
    config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: AUDIENCE.into(),
        resources: vec![AUDIENCE.into()],
        scopes: vec![SCOPE.into()],
        introspection_client_ids: vec![],
        require_sender_constraint: false,
        high_risk: false,
    }];
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap());
    let app = qid_oidc::routes(&state.paths)
        .merge(qid_oauth::routes(&state.paths))
        .merge(qid_iga::iga_routes())
        .with_state(state.clone());
    let verifier = "iga-pkce-verifier-with-at-least-43-characters-long";
    let response = app.clone().oneshot(Request::builder()
        .uri(format!(
            "{}?client_id=iga-client&response_type=code&redirect_uri={}&resource={}&scope={SCOPE}&state=iga-state&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize, urlencoding::encode(REDIRECT),
            urlencoding::encode(AUDIENCE), qid_core::util::sha256_base64url(verifier)
        ))
        .header("cookie", "__Host-qid=iga-browser-session")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with(&format!("{REDIRECT}?")));
    let query: std::collections::HashMap<_, _> = location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .map(|pair| pair.split_once('=').unwrap())
        .collect();
    assert_eq!(query["state"], "iga-state");
    let code = urlencoding::decode(query["code"]).unwrap();
    let response = app.clone().oneshot(Request::builder()
        .method("POST").uri(&state.paths.token)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&client_id=iga-client&code={}&redirect_uri={}&code_verifier={verifier}",
            urlencoding::encode(&code), urlencoding::encode(REDIRECT)
        ))).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = common::json(response).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], SCOPE);
    let access_token = tokens["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(claims.audiences(), vec![AUDIENCE]);
    assert_eq!(claims.extra["scope"], SCOPE);
    assert_eq!(claims.sub.as_deref(), Some("user-1"));
    assert!(
        repo.list_iga_access_requests("test")
            .await
            .unwrap()
            .is_empty()
    );
    let response = app.oneshot(Request::builder()
        .method("POST").uri("/iga/v1/access-requests")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {access_token}"))
        .body(Body::from(serde_json::json!({
            "subject": "user-1", "entitlement": "app:erp:admin", "requested_duration_seconds": 3600
        }).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = common::json(response).await;
    assert_eq!(body["status"], "approval_required");
    let stored = repo.list_iga_access_requests("test").await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, body["id"].as_str().unwrap());
    assert_eq!(stored[0].subject, "user-1");
    assert_eq!(stored[0].approval_steps_json.as_array().unwrap().len(), 2);
    // Release the remaining file-store owners before surfacing cleanup errors.
    drop(state);
    drop(repo);
    dir.close()
        .expect("failed to clean up authorization-code fixture");
}
