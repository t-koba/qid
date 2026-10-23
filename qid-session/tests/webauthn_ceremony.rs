//! The discoverable WebAuthn routes need no credential: the start route
//! creates a ceremony for any caller of a realm with passkeys enabled, and
//! the finish route consumes it. A ceremony is single-use and a finish
//! without a live ceremony is refused before the realm's user table is
//! read.

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value as CborValue;
use qid_core::{config::ServerPaths, models::User, state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_session::{auth_routes, browser::SessionManager};
use qid_storage::{FileRepository, prelude::*};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

struct TestApp {
    router: Router,
    repo: Arc<FileRepository>,
    cookie: String,
    _dir: tempfile::TempDir,
}

#[path = "support/trusted_packed.rs"]
mod trusted_packed;

async fn app() -> anyhow::Result<TestApp> {
    app_with_policy(None).await
}

async fn app_with_policy(
    policy: Option<qid_core::config::PackedAttestationPolicy>,
) -> anyhow::Result<TestApp> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("webauthn.json");
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
        id: "alice".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await?;
    let session = SessionManager::new(repo.clone(), 30, 8)
        .create(
            "corp",
            "alice",
            "urn:qid:acr:password",
            &["pwd".to_string()],
        )
        .await?;
    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    config.realms[0].authentication.passkeys.enabled = true;
    config.realms[0].authentication.passkeys.attestation = policy;
    let state = Arc::new(
        SharedState::new(
            config,
            repo.clone(),
            Arc::new(LocalSigner::from_secret("test", b"test-secret")),
            json!({"keys": []}),
        )
        .context("shared state creation failed")?,
    );
    Ok(TestApp {
        router: auth_routes(&ServerPaths::default()).with_state(state),
        repo,
        cookie: format!("__Host-qid={}", session.id),
        _dir: dir,
    })
}

async fn post(
    app: Router,
    path: &str,
    body: serde_json::Value,
    cookie: Option<&str>,
) -> anyhow::Result<(StatusCode, String)> {
    let (status, _, body) = post_with_headers(app, path, body, cookie).await?;
    Ok((status, body))
}

async fn post_with_headers(
    app: Router,
    path: &str,
    body: serde_json::Value,
    cookie: Option<&str>,
) -> anyhow::Result<(StatusCode, HeaderMap, String)> {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie.unwrap_or_default())
                .body(Body::from(body.to_string()))?,
        )
        .await
        .context("request failed")?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .context("response body read failed")?;
    Ok((status, headers, String::from_utf8_lossy(&bytes).to_string()))
}

#[tokio::test]
async fn the_discoverable_start_route_issues_a_ceremony() -> anyhow::Result<()> {
    let app = app().await?;
    let (status, body) = post(
        app.router.clone(),
        "/api/v1/corp/auth/webauthn/discoverable/start",
        json!({}),
        None,
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
        app.router.clone(),
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
        None,
    )
    .await?;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a finish without a live ceremony is refused before the user table is read: {body}"
    );
    Ok(())
}

fn cbor(value: CborValue) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn attestation_fields() -> anyhow::Result<Vec<(CborValue, CborValue)>> {
    // A public P-256 key; none attestation requires no signing key.
    let key = CborValue::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        (
            (-2).into(),
            CborValue::Bytes(
                URL_SAFE_NO_PAD.decode("Hv6bdBkKVfmsCu5MM6ethwZXu_MXfZ9jbGFH-WC6ymk")?,
            ),
        ),
        (
            (-3).into(),
            CborValue::Bytes(
                URL_SAFE_NO_PAD.decode("-0kZkptjI3Zjxe6hR4MOnRlF5sWJHH-mQ9RqB_1BRBE")?,
            ),
        ),
    ]);
    let mut auth_data = Sha256::digest(b"id.example.com").to_vec();
    auth_data.push(0x41); // UP + attested credential data.
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0x11; 16]); // AAGUID.
    auth_data.extend_from_slice(&4u16.to_be_bytes());
    auth_data.extend_from_slice(b"cred");
    auth_data.extend(cbor(key)?);
    Ok(vec![
        ("fmt".into(), "none".into()),
        ("authData".into(), CborValue::Bytes(auth_data)),
        ("attStmt".into(), CborValue::Map(vec![])),
    ])
}

fn registration_response(challenge: &serde_json::Value, evidence: &[u8]) -> serde_json::Value {
    json!({
        "user_id": "alice",
        "response": {
            "id": URL_SAFE_NO_PAD.encode(b"cred"),
            "rawId": URL_SAFE_NO_PAD.encode(b"cred"),
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(json!({
                    "type": "webauthn.create",
                    "challenge": challenge["challenge"]["challenge"],
                    "origin": "https://id.example.com",
                    "crossOrigin": false
                }).to_string()),
                "attestationObject": URL_SAFE_NO_PAD.encode(evidence)
            }
        }
    })
}

async fn start_registration(app: &TestApp) -> anyhow::Result<serde_json::Value> {
    start_with_attestation(app, "none").await
}

async fn start_with_attestation(
    app: &TestApp,
    attestation: &str,
) -> anyhow::Result<serde_json::Value> {
    let (status, body) = post(
        app.router.clone(),
        "/api/v1/corp/auth/webauthn/start",
        json!({"email": "alice@example.com"}),
        Some(&app.cookie),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(challenge["challenge"]["attestation"], attestation);
    Ok(challenge)
}

#[tokio::test]
async fn default_none_registration_persists_the_verified_aaguid() -> anyhow::Result<()> {
    let app = app().await?;
    let challenge = start_registration(&app).await?;
    let response = registration_response(&challenge, &cbor(CborValue::Map(attestation_fields()?))?);
    let (status, body) = post(
        app.router.clone(),
        "/api/v1/corp/auth/webauthn/finish",
        response.clone(),
        Some(&app.cookie),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let stored = app.repo.get_webauthn_credentials("alice").await?;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].credential_id, b"cred");
    assert_eq!(stored[0].aaguid, vec![0x11; 16]);
    let (status, body) = post(
        app.router.clone(),
        "/api/v1/corp/auth/webauthn/finish",
        response,
        Some(&app.cookie),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("no registration in progress"), "{body}");
    Ok(())
}

#[tokio::test]
async fn ambiguous_or_malformed_registration_is_not_stored_and_consumes_the_ceremony()
-> anyhow::Result<()> {
    let fields = attestation_fields()?;
    let valid = cbor(CborValue::Map(fields.clone()))?;
    let mut cases = Vec::new();
    for index in 0..fields.len() {
        let name = fields[index]
            .0
            .as_text()
            .context("test field name is text")?;
        let mut duplicate = fields.clone();
        let mut extra = fields[index].clone();
        if let CborValue::Bytes(auth_data) = &mut extra.1 {
            auth_data[37..53].fill(0x22); // A distinct, otherwise valid AAGUID.
        }
        duplicate.push(extra);
        cases.push((
            format!("duplicate {name}"),
            cbor(CborValue::Map(duplicate.clone()))?,
        ));
        duplicate.reverse();
        cases.push((
            format!("reversed duplicate {name}"),
            cbor(CborValue::Map(duplicate))?,
        ));
        let mut missing = fields.clone();
        missing.remove(index);
        cases.push((format!("missing {name}"), cbor(CborValue::Map(missing))?));
        let mut wrong_type = fields.clone();
        wrong_type[index].1 = CborValue::Null;
        cases.push((
            format!("wrong type {name}"),
            cbor(CborValue::Map(wrong_type))?,
        ));
    }
    for name in ["alg", "sig", "x5c", "unknown"] {
        let mut duplicate = fields.clone();
        duplicate[2].1 = CborValue::Map(vec![(name.into(), 1.into()), (name.into(), 2.into())]);
        cases.push((
            format!("duplicate statement {name}"),
            cbor(CborValue::Map(duplicate))?,
        ));
    }
    let mut nontext = fields.clone();
    nontext.push((1.into(), 1.into()));
    cases.push(("nontext object key".into(), cbor(CborValue::Map(nontext))?));
    let mut nontext = fields.clone();
    nontext[2].1 = CborValue::Map(vec![(1.into(), 1.into())]);
    cases.push((
        "nontext statement key".into(),
        cbor(CborValue::Map(nontext))?,
    ));
    let mut trailing = valid.clone();
    trailing.push(0x00);
    cases.push(("trailing CBOR".into(), trailing));
    cases.push(("nonmap object".into(), cbor(CborValue::Array(vec![]))?));
    cases.push(("malformed CBOR".into(), vec![0xff]));
    cases.push(("truncated CBOR".into(), valid[..valid.len() - 1].to_vec()));
    let mut malformed_auth = fields.clone();
    malformed_auth[1].1 = CborValue::Bytes(vec![0]);
    cases.push((
        "malformed authData".into(),
        cbor(CborValue::Map(malformed_auth))?,
    ));

    let app = app().await?;
    for (name, evidence) in cases {
        let challenge = start_registration(&app).await?;
        let (status, body) = post(
            app.router.clone(),
            "/api/v1/corp/auth/webauthn/finish",
            registration_response(&challenge, &evidence),
            Some(&app.cookie),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert!(body.contains("invalid WebAuthn"), "{name}: {body}");
        assert!(
            app.repo.get_webauthn_credentials("alice").await?.is_empty(),
            "{name}"
        );
        let (status, body) = post(
            app.router.clone(),
            "/api/v1/corp/auth/webauthn/finish",
            registration_response(&challenge, &valid),
            Some(&app.cookie),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert!(
            body.contains("no registration in progress"),
            "{name}: {body}"
        );
        assert!(
            app.repo.get_webauthn_credentials("alice").await?.is_empty(),
            "{name} retry"
        );
    }
    Ok(())
}
