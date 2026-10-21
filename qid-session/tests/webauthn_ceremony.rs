//! The discoverable WebAuthn routes need no credential: the start route
//! creates a ceremony for any caller of a realm with passkeys enabled, and
//! the finish route consumes it. A ceremony is single-use and a finish
//! without a live ceremony is refused before the realm's user table is
//! read.

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{config::ServerPaths, state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_session::auth_routes;
use qid_storage::{FileRepository, prelude::*};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn app() -> anyhow::Result<Router> {
    let path =
        std::env::temp_dir().join(format!("qid-session-webauthn-{}.json", ulid::Ulid::new()));
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

    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    config.realms[0].authentication.passkeys.enabled = true;
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

async fn post(
    app: Router,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<(StatusCode, String)> {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await
        .context("request failed")?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .context("response body read failed")?;
    Ok((status, String::from_utf8_lossy(&bytes).to_string()))
}

#[tokio::test]
async fn the_discoverable_start_route_issues_a_ceremony() -> anyhow::Result<()> {
    let app = app().await?;
    let (status, body) = post(
        app,
        "/api/v1/corp/auth/webauthn/discoverable/start",
        json!({}),
    )
    .await?;

    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value =
        serde_json::from_str(&body).context("the response is not JSON")?;
    let ceremony_id = parsed["ceremony_id"]
        .as_str()
        .context("the response carries no ceremony id")?;
    assert!(
        ceremony_id.starts_with("disc_"),
        "the ceremony id names the ceremony: {ceremony_id}"
    );
    assert!(
        parsed["challenge"]["challenge"].is_string(),
        "the response carries the challenge: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn a_finish_without_a_live_ceremony_is_refused() -> anyhow::Result<()> {
    let app = app().await?;
    let (status, body) = post(
        app,
        "/api/v1/corp/auth/webauthn/discoverable/finish",
        json!({
            "ceremony_id": "disc_0000000000000001",
            "response": {
                "id": "credential",
                "response": {
                    "clientDataJSON": "e30",
                    "authenticatorData": "e30",
                    "signature": "e30",
                    "userHandle": "AAAAAAAAAAAAAAAAAAAAAA"
                }
            }
        }),
    )
    .await?;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a finish without a live ceremony is refused before the user table is read: {body}"
    );
    Ok(())
}
