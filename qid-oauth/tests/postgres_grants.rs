//! Public OAuth grant contract on the disposable CI PostgreSQL service. Never
//! point QID_TEST_POSTGRES_URL at a production database. Only an unset variable
//! skips PostgreSQL; the identical contract also runs locally on SQLite.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::OAuthResourceServerConfig,
    models::{Client, ClientType, User},
    state::SharedState,
    test_helpers, util,
};
use qid_crypto::{Audience, LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};
use qid_session::browser::SessionManager;
use qid_storage::{SqlRepository, prelude::*};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn form(app: &Router, path: &str, body: &str, proof: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("Content-Type", "application/x-www-form-urlencoded");
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn client(realm: &str, ciba: bool) -> Client {
    Client {
        id: format!("client-{}", ulid::Ulid::new()),
        realm_id: realm.into(),
        client_id: "polling-client".into(),
        client_type: if ciba {
            ClientType::Confidential
        } else {
            ClientType::Public
        },
        token_endpoint_auth_method: if ciba { "client_secret_post" } else { "none" }.into(),
        client_secret_hash: ciba.then(|| util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: vec![],
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec![],
        grant_types: vec![
            if ciba {
                "urn:openid:params:grant-type:ciba"
            } else {
                "urn:ietf:params:oauth:grant-type:device_code"
            }
            .into(),
            "refresh_token".into(),
        ],
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
    }
}

async fn grant_flow(repo: Arc<SqlRepository>, ciba: bool) {
    let realm = format!("oauth-{}", ulid::Ulid::new());
    let user = format!("user-{}", ulid::Ulid::new());
    let issuer = format!("https://id.example.com/{realm}");
    let mut config = test_helpers::test_config();
    config.realms[0].id = realm.clone();
    config.realms[0].issuer = issuer.clone();
    let oauth = &mut config.realms[0].protocols.oauth;
    oauth.device_authorization.enabled = true;
    oauth.ciba.enabled = true;
    oauth.dpop.enabled = true;
    oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://bound".into(),
        resources: vec!["https://api.example.com/bound".into()],
        scopes: vec!["read".into(), "openid".into()],
        introspection_client_ids: vec![],
        require_sender_constraint: true,
        high_risk: false,
    }];
    let mut other = oauth.resource_servers[0].clone();
    other.audience = "api://other".into();
    other.resources = vec!["https://api.example.com/other".into()];
    oauth.resource_servers.push(other);
    // All production prerequisites go through the same Repository contracts as
    // normal provisioning. Unique IDs/issuer make reruns independent of old rows.
    repo.create_realm(
        &"oauth-test-tenant".into(),
        &realm.clone().into(),
        &issuer,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.get_realm_issuer(&realm.clone().into())
            .await
            .unwrap()
            .as_deref(),
        Some(issuer.as_str())
    );
    assert_eq!(
        repo.get_realm_tenant(&realm.clone().into())
            .await
            .unwrap()
            .as_deref(),
        Some("oauth-test-tenant")
    );
    let mut client = client(&realm, ciba);
    repo.create_client(&client).await.unwrap();
    client.client_name = Some("Public polling test".into());
    repo.update_client(&client).await.unwrap();
    // More than one IN slot detects numbering/bind-order mistakes, with a
    // deliberately SQL-like value to ensure data never becomes SQL syntax.
    let matches = repo
        .find_clients_by_client_id(
            &[
                "missing'); SELECT 1; --".into(),
                realm.clone().into(),
                "missing".into(),
            ],
            &client.client_id,
        )
        .await
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, client.id);
    assert!(
        repo.find_clients_by_client_id(&[], &client.client_id)
            .await
            .unwrap()
            .is_empty()
    );
    repo.create_user(&User {
        id: user.clone(),
        realm_id: realm.clone(),
        email: Some("poller@example.com".into()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    assert_eq!(
        repo.get_user_by_id_in_realm(&realm.clone().into(), &user)
            .await
            .unwrap()
            .unwrap()
            .id,
        user
    );
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer, json!({"keys": []})).unwrap());
    let app = qid_oauth::routes(&state.paths).with_state(state.clone());
    let initiation_path = if ciba {
        &state.paths.backchannel_authentication
    } else {
        &state.paths.device_authorization
    };
    let client_form = if ciba {
        "client_id=polling-client&client_secret=secret"
    } else {
        "client_id=polling-client"
    };
    let initiation = format!("{client_form}&login_hint=poller%40example.com");
    for suffix in [
        "scope=read",
        "scope=read&resource=https://api.example.com/unknown",
        "scope=admin&resource=https://api.example.com/bound",
    ] {
        assert!(
            form(
                &app,
                initiation_path,
                &format!("{initiation}&{suffix}"),
                None
            )
            .await
            .0
            .is_client_error()
        );
    }
    let (status, authorization) = form(
        &app,
        initiation_path,
        &format!("{initiation}&scope=read%20openid&resource=https://api.example.com/bound"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{authorization}");
    let secret = authorization[if ciba { "auth_req_id" } else { "device_code" }]
        .as_str()
        .unwrap();
    let hash = util::sha256_base64url(secret);
    let poll = if ciba {
        format!("grant_type=urn:openid:params:grant-type:ciba&{client_form}&auth_req_id={secret}")
    } else {
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&{client_form}&device_code={secret}"
        )
    };
    let (pending_status, pending) = form(&app, &state.paths.token, &poll, None).await;
    assert_eq!(pending_status, StatusCode::UNAUTHORIZED);
    assert!(
        pending["error"]
            .as_str()
            .unwrap()
            .ends_with("authorization_pending")
    );
    let session = SessionManager::new(repo.clone(), 15, 1)
        .create(&realm, &user, "password", &[])
        .await
        .unwrap();
    let approval = if ciba {
        json!({"auth_req_id": secret, "user_id": user})
    } else {
        json!({"user_code": authorization["user_code"]})
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{initiation_path}/approve"))
        .header("Content-Type", "application/json")
        .header(
            "Cookie",
            format!(
                "{}={}",
                state.config.realms[0].sessions.browser.cookie_name, session.id
            ),
        )
        .body(Body::from(approval.to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let key = generate_es256("grant-test").unwrap();
    let proof = || {
        sign_es256_jwt_with_jwk_header(key.private_pem.as_bytes(), &key.public_jwk, "dpop+jwt", &json!({
        "jti": ulid::Ulid::new().to_string(), "htm": "POST",
        "htu": format!("{}{}", state.plan.public_base_url.trim_end_matches('/'), state.paths.token),
        "iat": util::now_seconds(),
    })).unwrap()
    };
    for suffix in [
        "resource=https://api.example.com/other",
        "audience=api://other",
        "scope=admin",
    ] {
        assert!(
            form(
                &app,
                &state.paths.token,
                &format!("{poll}&{suffix}"),
                Some(&proof())
            )
            .await
            .0
            .is_client_error()
        );
    }
    // Target selection is not sender proof. Missing proof must not consume.
    assert_eq!(
        form(&app, &state.paths.token, &poll, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (resource, audience, scopes, owner, approved, consumed) = if ciba {
        let grant = repo
            .get_backchannel_authentication_grant(&hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(grant.realm_id, realm);
        assert_eq!(grant.client_id, client.client_id);
        (
            grant.resource,
            grant.audience,
            grant.scopes,
            grant.user_id,
            grant.approved_at,
            grant.consumed,
        )
    } else {
        let grant = repo
            .get_device_authorization_grant(&hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(grant.realm_id, realm);
        assert_eq!(grant.client_id, client.client_id);
        (
            grant.resource,
            grant.audience,
            grant.scopes,
            grant.user_id,
            grant.approved_at,
            grant.consumed,
        )
    };
    assert_eq!(resource, ["https://api.example.com/bound"]);
    assert_eq!(audience, ["api://bound"]);
    assert_eq!(scopes, ["read", "openid"]);
    assert_eq!(owner.as_deref(), Some(user.as_str()));
    assert!(approved.is_some());
    assert!(!consumed, "refusal consumed approved grant");
    let (status, token) = form(&app, &state.paths.token, &poll, Some(&proof())).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    assert_eq!(token["token_type"], "DPoP");
    let claims = state
        .signer
        .decode_signature_only(token["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.aud, Some(Audience::Single("api://bound".into())));
    assert_eq!(
        claims.extra["resource"],
        json!(["https://api.example.com/bound"])
    );
    assert_eq!(claims.extra["scope"], "read openid");
    assert!(claims.extra["cnf"]["jkt"].is_string());
    if ciba {
        let id = state
            .signer
            .decode_signature_only(token["id_token"].as_str().unwrap())
            .unwrap()
            .claims;
        assert_eq!(id.aud, Some(Audience::Single(client.client_id.clone())));
    }
    let access = repo
        .get_access_token(claims.jti.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(access.audience, audience);
    assert_eq!(access.resource, resource);
    assert_eq!(access.scopes, scopes);
    assert_eq!(access.cnf, Some(claims.extra["cnf"].clone()));
    assert_eq!(access.sender_constraint, access.cnf);
    let family_id = access.family_id.as_deref().unwrap();
    let family = repo.get_token_family(family_id).await.unwrap().unwrap();
    assert_eq!(family.realm_id, realm);
    assert_eq!(family.user_id, user);
    assert_eq!(family.client_id, client.client_id);
    assert_eq!(family.audience, audience);
    assert_eq!(family.resource, resource);
    assert_eq!(family.scopes, scopes);
    assert_eq!(family.sender_constraint, access.cnf);
    let families = repo
        .list_token_families(&realm, Some(&user), Some(&client.client_id))
        .await
        .unwrap();
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].id, family.id);
    assert!(
        form(&app, &state.paths.token, &poll, Some(&proof()))
            .await
            .0
            .is_client_error()
    );
    let consumed = if ciba {
        repo.get_backchannel_authentication_grant(&hash)
            .await
            .unwrap()
            .unwrap()
            .consumed
    } else {
        repo.get_device_authorization_grant(&hash)
            .await
            .unwrap()
            .unwrap()
            .consumed
    };
    assert!(consumed);
    let refresh = format!(
        "grant_type=refresh_token&{client_form}&refresh_token={}",
        token["refresh_token"].as_str().unwrap()
    );
    // Public-client refresh requires its original DPoP key; confidential
    // CIBA refresh uses client authentication under the existing policy.
    if !ciba {
        assert!(
            form(&app, &state.paths.token, &refresh, None)
                .await
                .0
                .is_client_error()
        );
    }
    let (status, refreshed) = form(&app, &state.paths.token, &refresh, Some(&proof())).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let refreshed_claims = state
        .signer
        .decode_signature_only(refreshed["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(refreshed_claims.aud, claims.aud);
    for claim in ["resource", "scope", "cnf"] {
        assert_eq!(refreshed_claims.extra[claim], claims.extra[claim]);
    }
    let rotated = repo.get_token_family(family_id).await.unwrap().unwrap();
    assert_ne!(rotated.current_refresh_hash, family.current_refresh_hash);
    assert_eq!(rotated.refresh_expires_at, family.refresh_expires_at);
    assert_eq!(rotated.audience, family.audience);
    assert_eq!(rotated.resource, family.resource);
    assert_eq!(rotated.sender_constraint, family.sender_constraint);
    // A stale refresh is refused and revokes the family via the production path.
    assert!(
        form(&app, &state.paths.token, &refresh, Some(&proof()))
            .await
            .0
            .is_client_error()
    );
    assert!(
        repo.get_token_family(family_id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn postgres_public_device_and_ciba() {
    let url = match std::env::var("QID_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skipping PostgreSQL public grants: QID_TEST_POSTGRES_URL is unset");
            return;
        }
        Err(_) => panic!("QID_TEST_POSTGRES_URL must be valid Unicode"),
    };
    assert!(url.starts_with("postgres://") || url.starts_with("postgresql://"));
    let repo = Arc::new(
        SqlRepository::connect(&url)
            .await
            .expect("connect disposable PostgreSQL"),
    );
    repo.migrate().await.unwrap();
    for ciba in [false, true] {
        grant_flow(repo.clone(), ciba).await;
    }
    Arc::try_unwrap(repo).unwrap().close().await;
}

#[tokio::test]
async fn sqlite_public_device_and_ciba() {
    let path = std::env::temp_dir().join(format!("qid-public-grants-{}.db", ulid::Ulid::new()));
    let repo = Arc::new(
        SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    for ciba in [false, true] {
        grant_flow(repo.clone(), ciba).await;
    }
    Arc::try_unwrap(repo).unwrap().close().await;
    std::fs::remove_file(path).unwrap();
}
