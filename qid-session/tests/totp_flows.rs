#[path = "support/admin_assurance.rs"]
mod admin_assurance;

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
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

async fn setup(totp_enabled: bool) -> anyhow::Result<(Router, String, Arc<FileRepository>)> {
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
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.mfa.totp.enabled = totp_enabled;
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
    let paths = qid_core::config::ServerPaths::default();
    let app = totp_routes(&paths).with_state(state);
    Ok((app, cookie, repo))
}

async fn post(
    app: Router,
    uri: &str,
    cookie: &str,
    body: Value,
) -> anyhow::Result<(StatusCode, Value, HeaderMap)> {
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
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?, headers))
}

#[tokio::test]
async fn totp_enroll_rejects_a_session_from_another_realm() -> anyhow::Result<()> {
    let (app, cookie, repo) = setup(true).await?;
    let cookie_name = cookie
        .split_once('=')
        .context("session cookie must contain a name and value")?
        .0;
    let foreign_session = SessionManager::new(Arc::clone(&repo), 30, 8)
        .create("other", "totp-user", "phr", &[])
        .await?;
    let foreign_cookie = format!("{cookie_name}={}", foreign_session.id);

    let (status, _, _) = post(
        app,
        "/api/v1/test/auth/totp/enroll",
        &foreign_cookie,
        json!({}),
    )
    .await?;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn totp_enroll_confirm_then_authenticate_consumes_each_code_once() -> anyhow::Result<()> {
    let (app, cookie, repo) = setup(true).await?;
    let (status, body, _) = post(
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

    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        &cookie,
        json!({"code": confirm_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    // The confirmation code must not create a session afterwards.
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": confirm_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A fresh code from an adjacent window still authenticates exactly once.
    let (status, body, headers) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": next_code}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let set_cookie = headers
        .get("set-cookie")
        .context("authentication must set a session cookie")?
        .to_str()
        .context("session cookie must be valid header text")?;
    assert!(set_cookie.contains("; HttpOnly; Secure; Path=/; SameSite=Lax"));
    // TOTP-only sessions carry their own non-phishing-resistant ACR with an
    // accurate method claim; exact-match essential-ACR enforcement elsewhere
    // then refuses phishing-resistant requests for them.
    let session_id = body["session_id"]
        .as_str()
        .context("authenticate must return session")?;
    assert!(set_cookie.starts_with(&format!("__Host-qid={session_id};")));
    let session = repo
        .get_session(session_id)
        .await?
        .context("session missing")?;
    assert_eq!(session.acr.as_deref(), Some("urn:qid:acr:totp"));
    assert_eq!(session.amr, vec!["totp".to_string()]);
    admin_assurance::assert_admin_assurance(&session, false, true);

    let (status, _, _) = post(
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
    let (app, cookie, _repo) = setup(true).await?;
    let (status, body, _) = post(
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
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/authenticate",
        &cookie,
        json!({"user_id": "totp-user", "code": valid}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A non-numeric code is deterministically invalid and leaves the
    // credential disabled for the later valid confirmation.
    let (status, _, _) = post(
        app.clone(),
        "/api/v1/test/auth/totp/verify",
        &cookie,
        json!({"code": "not-a-code"}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, _) = post(
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
async fn a_realm_without_totp_refuses_every_totp_route() -> anyhow::Result<()> {
    let (app, cookie, _repo) = setup(false).await?;
    for (uri, body) in [
        ("/api/v1/test/auth/totp/enroll", json!({})),
        ("/api/v1/test/auth/totp/verify", json!({"code": "123456"})),
        (
            "/api/v1/test/auth/totp/authenticate",
            json!({"user_id": "totp-user", "code": "123456"}),
        ),
    ] {
        let (status, _, _) = post(app.clone(), uri, &cookie, body).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "route {uri} must refuse");
    }
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
        repo.consume_totp_step(&first, step),
        repo.consume_totp_step(&second, step)
    );
    assert!(r1? ^ r2?, "exactly one claim must win");
    assert!(!repo.consume_totp_step(&first, step).await?);
    assert!(repo.consume_totp_step(&first, step + 1).await?);
    assert!(
        !repo
            .consume_totp_step(
                &qid_core::models::TotpCredential {
                    id: "missing".into(),
                    ..first.clone()
                },
                1
            )
            .await?
    );
    Ok(())
}
