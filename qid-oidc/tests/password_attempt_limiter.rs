#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The two password login paths share one admission limiter.
//!
//! The session API and the OIDC authorization endpoint count the password
//! logins they admit in the same limiter, so a spray of guesses spends one
//! count and not one count per path. The count is settled before the
//! credential lookup, so a refused login costs no credential verification;
//! an address that names no account still pays for the user lookup only.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use qid_core::{
    models::{Client, ClientType},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_session::PasswordAttemptLimiter;
use qid_storage::{FileRepository, prelude::*};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

struct TestFile(PathBuf);

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The realm's own limit on the failures an account may spend.
const MAX_FAILED_ATTEMPTS: u32 = 3;

/// An address that names no account, so no login of it reaches a credential.
const UNKNOWN_EMAIL: &str = "ghost@example.com";

/// The authorization request the login is posted to.
const AUTHORIZE_URI: &str = "/oauth2/authorize?client_id=par-client&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=opaque&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

/// Build the session routes and the authorization endpoint over one limiter.
async fn app() -> anyhow::Result<(TestFile, Router)> {
    let path = std::env::temp_dir().join(format!(
        "qid-oidc-password-limiter-{}.json",
        ulid::Ulid::new()
    ));
    let test_file = TestFile(path.clone());
    let repo = Arc::new(
        FileRepository::new(path.to_str().expect("test path is not UTF-8"))
            .await
            .expect("file repository creation failed"),
    );
    repo.migrate()
        .await
        .expect("file repository migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .expect("realm creation failed");
    repo.create_client(&Client {
        id: "client-id".to_string(),
        realm_id: "test".to_string(),
        client_id: "par-client".to_string(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: vec!["https://app.example.com/callback".to_string()],
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
    .expect("client creation failed");

    let mut config = test_helpers::test_config();
    config.realms[0].authentication.password.max_failed_attempts = MAX_FAILED_ATTEMPTS;
    let state = Arc::new(
        SharedState::new(
            config,
            repo,
            Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests")),
            json!({}),
        )
        .expect("shared state creation failed"),
    );

    // One limiter for both routers: the deployment's own composition.
    let limiter = Arc::new(PasswordAttemptLimiter::new());
    let router =
        qid_session::auth_routes_with_password_attempt_limiter(&state.paths, limiter.clone())
            .merge(qid_oidc::routes_with_password_attempt_limiter(
                &state.paths,
                limiter,
            ))
            .with_state(state);
    Ok((test_file, router))
}

/// Post a password login to the session API.
async fn post_password(app: Router) -> anyhow::Result<StatusCode> {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/test/auth/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": UNKNOWN_EMAIL, "password": "wrong-password"}).to_string(),
                ))?,
        )
        .await?;
    Ok(response.status())
}

/// Post a password login to the authorization endpoint.
async fn post_authorize(app: Router, email: &str) -> anyhow::Result<Response> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(AUTHORIZE_URI)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email={email}&password=wrong-password",
                    email = email.replace('@', "%40")
                )))?,
        )
        .await?)
}

#[tokio::test]
async fn the_two_password_login_paths_share_one_admission_count() -> anyhow::Result<()> {
    let (_test_file, app) = app().await?;

    // The realm admits three password logins for the address. Each of
    // them is a refusal of the password, not a limit of the route's own,
    // because no account carries the address.
    for attempt in 1..=MAX_FAILED_ATTEMPTS {
        assert_eq!(
            post_password(app.clone()).await?,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} is a refusal of the password"
        );
    }

    // The admission count is spent, so the session API refuses the login
    // before it looks a credential up.
    assert_eq!(
        post_password(app.clone()).await?,
        StatusCode::TOO_MANY_REQUESTS
    );

    // The authorization endpoint counts the same logins, so it refuses the
    // same address and issues no code.
    let response = post_authorize(app.clone(), UNKNOWN_EMAIL).await?;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .expect("the refusal is a redirect")
        .to_str()
        .expect("the location is text")
        .to_string();
    assert!(
        location.contains("error=temporarily_unavailable"),
        "the refusal is a temporary condition: {location}"
    );
    assert!(!location.contains("code="), "no code is issued: {location}");

    // Another address has its own count, so the authorization endpoint
    // reaches the credential work for it and refuses the password.
    let response = post_authorize(app, "other@example.com").await?;
    let location = response
        .headers()
        .get("location")
        .expect("the refusal is a redirect")
        .to_str()
        .expect("the location is text")
        .to_string();
    assert!(
        location.contains("error=access_denied"),
        "the password is refused: {location}"
    );
    assert!(!location.contains("code="), "no code is issued: {location}");
    Ok(())
}
