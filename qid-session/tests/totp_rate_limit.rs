#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The TOTP enrolment-confirmation and authentication paths share one
//! account-keyed admission budget.
//!
//! A proof for a known account spends one admission before any code
//! verification, whether the code is wrong, malformed or a replay. Only a
//! proof that verifies and wins the step claim gives its admission back. A
//! refused proof never reaches verification, the step claim, enrolment
//! activation or session creation.

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{models::User, state::SharedState, test_helpers, util::now_seconds};
use qid_crypto::totp::TotpVerifier;
use qid_session::{
    TotpAttemptLimiter, browser::SessionManager, totp_api::totp_routes_with_attempt_limiter,
};
use qid_storage::{FileRepository, prelude::*};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct TestSigner;

impl qid_core::jwt::Signer for TestSigner {
    fn sign(&self, _claims: &qid_core::jwt::JwtClaims) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn sign_with_typ(
        &self,
        _claims: &qid_core::jwt::JwtClaims,
        _typ: &str,
    ) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn decode_signature_only(
        &self,
        _token: &str,
    ) -> anyhow::Result<qid_core::jwt::TokenData<qid_core::jwt::JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn decode_with_aud(
        &self,
        _token: &str,
        _aud: &str,
    ) -> anyhow::Result<qid_core::jwt::TokenData<qid_core::jwt::JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn algorithm(&self) -> &'static str {
        "HS256"
    }
}

async fn setup(
    max_failed_attempts: u32,
) -> anyhow::Result<(Router, String, Arc<FileRepository>, Arc<TotpAttemptLimiter>)> {
    let path = std::env::temp_dir().join(format!("totp-limit-{}.json", ulid::Ulid::new()));
    let repo =
        Arc::new(FileRepository::new(path.to_str().context("store path must be UTF-8")?).await?);
    repo.migrate().await?;
    repo.create_user(&User {
        id: "totp-user".to_string(),
        realm_id: "test".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await?;
    let sessions = SessionManager::new(Arc::clone(&repo), 30, 8);
    let session = sessions.create("test", "totp-user", "phr", &[]).await?;
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.mfa.totp.enabled = true;
    config.realms[0].authentication.mfa.totp.max_failed_attempts = max_failed_attempts;
    config.realms[0]
        .authentication
        .mfa
        .totp
        .failed_attempt_window_seconds = 300;
    let state = Arc::new(SharedState::new(
        config,
        Arc::clone(&repo),
        Arc::new(TestSigner),
        json!({"keys": []}),
    )?);
    let cookie_name = state
        .realm("test")
        .context("test realm missing")?
        .browser_session
        .cookie_name
        .clone();
    let cookie = format!("{cookie_name}={}", session.id);
    let limiter = Arc::new(TotpAttemptLimiter::new());
    let paths = qid_core::config::ServerPaths::default();
    let app = totp_routes_with_attempt_limiter(&paths, limiter.clone()).with_state(state);
    Ok((app, cookie, repo, limiter))
}

async fn post(
    app: Router,
    uri: &str,
    cookie: Option<&str>,
    body: Value,
) -> anyhow::Result<(StatusCode, Value, HeaderMap)> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let response = app
        .oneshot(builder.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?, headers))
}

async fn enroll_secret(app: Router, cookie: &str) -> anyhow::Result<(Router, String)> {
    let (status, body, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/enroll",
        Some(cookie),
        json!({}),
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "enrolment must succeed");
    let secret = body["secret"]
        .as_str()
        .context("enrolment must return a secret")?
        .to_string();
    Ok((app, secret))
}

#[tokio::test]
async fn confirmation_spends_admissions_and_refuses_before_activation() -> anyhow::Result<()> {
    let (app, cookie, repo, _) = setup(2).await?;
    let (app, secret) = enroll_secret(app, &cookie).await?;

    // Two malformed proofs each spend one admission.
    for _ in 0..2 {
        let (status, _, _) = post(
            app.clone(),
            "/api/v1/test/auth/totp/verify",
            Some(&cookie),
            json!({"code": "not-a-code"}),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // A valid proof now meets a spent budget, so the route refuses it before
    // verification: the credential stays disabled and no step is consumed.
    let valid = TotpVerifier::default().generate_code(&secret, now_seconds())?;
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        Some(&cookie),
        json!({"code": valid}),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let credential = repo
        .get_totp_credential("totp-user")
        .await?
        .context("credential missing")?;
    assert!(!credential.enabled, "a refused proof must not enable");
    assert_eq!(
        credential.last_used_step, None,
        "a refused proof must not consume a step"
    );
    Ok(())
}

#[tokio::test]
async fn authentication_spends_admissions_and_refuses_before_session_creation() -> anyhow::Result<()>
{
    let (app, cookie, repo, _) = setup(2).await?;
    let (app, secret) = enroll_secret(app, &cookie).await?;
    let verifier = TotpVerifier::default();
    let now = now_seconds();
    let confirm_code = verifier.generate_code(&secret, now)?;
    let next_code = verifier.generate_code(&secret, now + 30)?;

    // The confirmation spends an admission and gives it back on success.
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        Some(&cookie),
        json!({"code": confirm_code.clone()}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let confirmed = repo
        .get_totp_credential("totp-user")
        .await?
        .context("credential missing")?;
    assert!(confirmed.enabled);

    // Replaying the confirmation step and submitting a malformed proof each
    // spend one admission; the successful confirmation gave its own back.
    for code in [confirm_code.as_str(), "not-a-code"] {
        let (status, _, _) = post(
            app.clone(),
            "/api/v1/test/auth/totp/authenticate",
            None,
            json!({"user_id": "totp-user", "code": code}),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // A valid proof now meets a spent budget: no session is created and the
    // step the proof named is not consumed.
    let step_before = repo
        .get_totp_credential("totp-user")
        .await?
        .context("credential missing")?
        .last_used_step;
    let sessions_before = repo.list_sessions("test", Some("totp-user")).await?.len();
    let (status, body, headers) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        None,
        json!({"user_id": "totp-user", "code": next_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        headers.get("set-cookie").is_none(),
        "a refused proof must not set a session cookie"
    );
    assert!(
        body.get("session_id").is_none(),
        "a refused proof must not return a session"
    );
    let step_after = repo
        .get_totp_credential("totp-user")
        .await?
        .context("credential missing")?
        .last_used_step;
    assert_eq!(
        step_before, step_after,
        "a refused proof must not consume a step"
    );
    let sessions_after = repo.list_sessions("test", Some("totp-user")).await?.len();
    assert_eq!(
        sessions_before, sessions_after,
        "a refused proof must not create a session in storage"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_confirmation_admissions_are_atomic_at_the_route() -> anyhow::Result<()> {
    let (app, cookie, repo, _) = setup(1).await?;
    let (app, _) = enroll_secret(app, &cookie).await?;
    let (left, right) = tokio::join!(
        post(
            app.clone(),
            "/api/v1/test/auth/totp/verify",
            Some(&cookie),
            json!({"code": "not-a-code"}),
        ),
        post(
            app,
            "/api/v1/test/auth/totp/verify",
            Some(&cookie),
            json!({"code": "not-a-code"}),
        ),
    );
    let left = left?;
    let right = right?;
    let statuses = [left.0, right.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::BAD_REQUEST)
            .count(),
        1,
        "exactly one concurrent route request reaches proof verification"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        1,
        "the other concurrent route request is refused at admission"
    );
    let credential = repo
        .get_totp_credential("totp-user")
        .await?
        .context("credential missing")?;
    assert!(!credential.enabled);
    assert_eq!(credential.last_used_step, None);
    Ok(())
}

#[tokio::test]
async fn confirmation_and_authentication_share_one_budget() -> anyhow::Result<()> {
    let (app, cookie, _repo, _) = setup(3).await?;
    let (app, secret) = enroll_secret(app, &cookie).await?;
    let verifier = TotpVerifier::default();
    let now = now_seconds();
    let confirm_code = verifier.generate_code(&secret, now)?;

    // One confirmation failure and one authentication failure spend the same
    // account budget: after the confirmation succeeds (giving its admission
    // back) the two failures leave one admission, and the next proof on
    // either route meets a spent budget.
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        Some(&cookie),
        json!({"code": "not-a-code"}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        Some(&cookie),
        json!({"code": confirm_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..2 {
        let (status, _, _) = post(
            app.clone(),
            "/api/v1/test/auth/totp/authenticate",
            None,
            json!({"user_id": "totp-user", "code": "not-a-code"}),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let later_code = verifier.generate_code(&secret, now + 60)?;
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        Some(&cookie),
        json!({"code": later_code}),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the confirmation path sees the admissions the authentication path spent"
    );
    Ok(())
}
