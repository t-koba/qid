//! The session API's password route enforces the realm's own attempt
//! limits. The realm states how many failures lock an account, the OIDC
//! authorization endpoint enforces the same numbers, and the route adds no
//! limit of its own.

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    config::{RealmConfig, ServerPaths},
    models::{PasswordCredential, User},
    state::SharedState,
    test_helpers,
};
use qid_crypto::{ARGON2ID_ALGORITHM, Argon2idParams, LocalSigner, hash_password_with_params};
use qid_session::auth_routes;
use qid_storage::{FileRepository, prelude::*};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

const PASSWORD: &str = "correct-password-123!";

async fn app_with_realm(configure: impl FnOnce(&mut RealmConfig)) -> anyhow::Result<Router> {
    let path = std::env::temp_dir().join(format!(
        "qid-session-password-route-{}.json",
        ulid::Ulid::new()
    ));
    let repo = Arc::new(
        FileRepository::new(path.to_str().context("test path is not UTF-8")?)
            .await
            .context("file repository creation failed")?,
    );
    repo.migrate()
        .await
        .context("file repository migration failed")?;
    repo.create_realm(
        &"tenant-1".into(),
        &"corp".into(),
        "https://login.example.com",
        Some("Corp"),
    )
    .await
    .context("realm creation failed")?;
    repo.create_user(&User {
        id: "user-1".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .context("user creation failed")?;
    repo.store_password_credential(&PasswordCredential {
        user_id: "user-1".to_string(),
        // The cheapest Argon2id cost the product accepts: the test needs the
        // route's answers, not a slow hash.
        hash: hash_password_with_params(PASSWORD, &Argon2idParams::new(8, 1, 1))
            .context("password hashing failed")?,
        algorithm: ARGON2ID_ALGORITHM.to_string(),
    })
    .await
    .context("password credential creation failed")?;

    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    configure(&mut config.realms[0]);
    let state = Arc::new(
        SharedState::new(
            config,
            repo,
            Arc::new(LocalSigner::from_secret("test", b"test-secret")),
            json!({"keys": []}),
        )
        .context("shared state creation failed")?,
    );
    Ok(auth_routes(&ServerPaths::default()).with_state(state))
}

async fn app_with_policy(max_failed_attempts: u32) -> anyhow::Result<Router> {
    app_with_realm(|realm| {
        realm.authentication.password.max_failed_attempts = max_failed_attempts;
    })
    .await
}

async fn post_password(app: Router, password: &str) -> anyhow::Result<StatusCode> {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/corp/auth/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": "alice@example.com", "password": password}).to_string(),
                ))?,
        )
        .await
        .context("password request failed")?;
    Ok(response.status())
}

#[tokio::test]
async fn the_password_route_enforces_the_realm_attempt_limit() -> anyhow::Result<()> {
    // The realm allows eight failures, so every attempt below the limit is
    // a refusal of the password rather than a limit of the route's own.
    let app = app_with_policy(8).await?;
    for attempt in 1..=8 {
        let status = post_password(app.clone(), "wrong-password").await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} is a refusal of the password"
        );
    }

    // The eighth failure locked the account, so the next attempt is
    // refused by the lockout.
    let status = post_password(app.clone(), "wrong-password").await?;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the account is locked after the realm's limit"
    );

    // The lockout refuses even the correct password.
    let status = post_password(app, PASSWORD).await?;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the lockout refuses the correct password"
    );
    Ok(())
}

#[tokio::test]
async fn the_password_route_locks_after_the_number_the_realm_states() -> anyhow::Result<()> {
    // The realm allows two failures, so the third attempt meets the lockout.
    let app = app_with_policy(2).await?;
    for _ in 0..2 {
        let status = post_password(app.clone(), "wrong-password").await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a failure below the realm's limit is a refusal of the password"
        );
    }
    let status = post_password(app, "wrong-password").await?;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the account is locked after the realm's limit"
    );
    Ok(())
}

#[tokio::test]
async fn the_password_route_refuses_a_realm_that_does_not_accept_passwords() -> anyhow::Result<()> {
    // The realm refuses password logins, so the route answers the
    // correct password with the same refusal as a wrong one.
    let app = app_with_realm(|realm| {
        realm.authentication.password.enabled = false;
    })
    .await?;
    let status = post_password(app, PASSWORD).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the realm refuses password logins"
    );
    Ok(())
}
