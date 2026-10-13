use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{models::User, state::SharedState, test_helpers, util::now_seconds};
use qid_crypto::totp::TotpVerifier;
use qid_mfa::verify_totp_at_with_step;
use qid_session::{browser::SessionManager, totp_api::totp_routes};
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

async fn setup() -> anyhow::Result<(Router, String)> {
    let path = std::env::temp_dir().join(format!("totp-flows-{}.json", ulid::Ulid::new()));
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
    let state = Arc::new(SharedState::new(
        test_helpers::test_config(),
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
    let paths = qid_core::config::ServerPaths::default();
    let app = totp_routes(&paths).with_state(state);
    Ok((app, cookie))
}

async fn post(
    app: Router,
    uri: &str,
    cookie: &str,
    body: Value,
) -> anyhow::Result<(StatusCode, Value)> {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
async fn totp_enroll_confirm_then_authenticate_consumes_each_code_once() -> anyhow::Result<()> {
    let (app, cookie) = setup().await?;
    let (status, body) = post(
        app.clone(),
        "/api/v1/test/auth/totp/enroll",
        &cookie,
        json!({}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let secret = body["secret"]
        .as_str()
        .context("enroll must return secret")?
        .to_string();

    // Codes for the current and next windows stay usable across a step flip
    // between generation and verification.
    let now = now_seconds();
    let verifier = TotpVerifier::default();
    let confirm_code = verifier.generate_code(&secret, now)?;
    let next_code = verifier.generate_code(&secret, now + 30)?;

    let (status, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        &cookie,
        json!({"code": confirm_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    // The confirmation code must not create a session afterwards.
    let (status, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": confirm_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A fresh code from an adjacent window still authenticates exactly once.
    let (status, body) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": next_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body["session_id"].as_str().is_some());

    let (status, _) = post(
        app,
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": next_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn totp_pending_credential_rejects_authentication_and_bad_confirmation() -> anyhow::Result<()>
{
    let (app, cookie) = setup().await?;
    let (status, body) = post(
        app.clone(),
        "/api/v1/test/auth/totp/enroll",
        &cookie,
        json!({}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let secret = body["secret"]
        .as_str()
        .context("enroll must return secret")?
        .to_string();

    // Pending credentials cannot authenticate, even with a valid code.
    let valid = TotpVerifier::default().generate_code(&secret, now_seconds())?;
    let (status, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": valid}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A non-numeric code is deterministically invalid and leaves the
    // credential disabled for the later valid confirmation.
    let (status, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        &cookie,
        json!({"code": "not-a-code"}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = post(
        app,
        "/api/v1/test/auth/totp/verify",
        &cookie,
        json!({"code": valid}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn totp_step_claim_has_a_single_winner_per_step() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let repo = FileRepository::new(
        tmp.path()
            .join("totp-race.json")
            .to_str()
            .context("race path must be UTF-8")?,
    )
    .await?;
    repo.migrate().await?;
    repo.store_totp_credential(&qid_core::models::TotpCredential {
        id: "race-1".to_string(),
        user_id: "race-user".to_string(),
        secret: TotpVerifier::generate_secret(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        enabled: true,
        last_used_step: None,
        created_at: 1,
    })
    .await?;

    // Two readers validate the same snapshot before either claims the step.
    let first = repo
        .get_totp_credential("race-user")
        .await?
        .context("credential missing")?;
    let second = repo
        .get_totp_credential("race-user")
        .await?
        .context("credential missing")?;
    let code = TotpVerifier::default().generate_code(&first.secret, 1_000_000)?;
    let step = verify_totp_at_with_step(&first, &code, 1_000_000)?.context("code must validate")?;
    assert_eq!(
        verify_totp_at_with_step(&second, &code, 1_000_000)?,
        Some(step)
    );
    let (r1, r2) = tokio::join!(
        repo.consume_totp_step(&first.id, step),
        repo.consume_totp_step(&second.id, step)
    );
    assert!(r1? ^ r2?, "exactly one claim must win");
    assert!(!repo.consume_totp_step(&first.id, step).await?);
    assert!(repo.consume_totp_step(&first.id, step + 1).await?);
    assert!(!repo.consume_totp_step("missing", 1).await?);
    Ok(())
}
