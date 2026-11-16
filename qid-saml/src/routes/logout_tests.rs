//! Caller coverage; atomic owner changes remain covered by storage contracts.
use super::*;
use crate::test_support::{sign_test_document, test_sp_cert_body};
use axum::{body::Body, http::Request};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use qid_core::{config::SamlServiceProviderConfig, models::User, test_helpers::test_config};
use tower::ServiceExt;

async fn logout_app() -> (
    tempfile::TempDir,
    Arc<qid_storage::FileRepository>,
    Router,
    String,
) {
    let directory = tempfile::tempdir().unwrap();
    let repo = Arc::new(
        qid_storage::FileRepository::new(directory.path().join("store.json").to_str().unwrap())
            .await
            .unwrap(),
    );
    let mut config = test_config();
    config.realms[0].protocols.saml.enabled = true;
    config.realms[0].protocols.saml.service_providers = vec![SamlServiceProviderConfig {
        entity_id: "https://sp.example.com".into(),
        signing_certificates: vec![test_sp_cert_body()],
        ..Default::default()
    }];
    let state = Arc::new(
        SharedState::new(
            config,
            repo.clone(),
            Arc::new(super::tests::TestSigner),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let cookie_name = state
        .realm("test")
        .unwrap()
        .browser_session
        .cookie_name
        .clone();
    (
        directory,
        repo,
        saml_routes().with_state(state),
        cookie_name,
    )
}

async fn create_user(repo: &qid_storage::FileRepository, id: &str, email: &str) {
    repo.create_user(&User {
        id: id.into(),
        realm_id: "test".into(),
        email: Some(email.into()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn logout_routes_preserve_same_realm_and_ignore_foreign_or_missing_sessions() {
    let (_directory, repo, app, cookie_name) = logout_app().await;
    create_user(&repo, "user", "user@example.com").await;
    let now = qid_core::util::now_seconds();
    for (id, realm) in [
        ("sp-local", "test"),
        ("browser-local", "test"),
        ("foreign", "other"),
    ] {
        repo.create_session(&Session {
            id: id.into(),
            realm_id: realm.into(),
            user_id: "user".into(),
            auth_time: now,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: now + 600,
            absolute_expires_at: now + 600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
    }
    let foreign_before = serde_json::to_value(repo.get_session("foreign").await.unwrap()).unwrap();
    let signed = sign_test_document(
        r#"<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="2026-10-28T00:00:00Z" Destination="https://id.example.com/saml/test/slo"><s:Issuer>https://sp.example.com</s:Issuer><!--SIGNATURE--><s:NameID>user</s:NameID><p:SessionIndex>sp-local</p:SessionIndex><p:SessionIndex>foreign</p:SessionIndex><p:SessionIndex>missing</p:SessionIndex></p:LogoutRequest>"#,
        "_logout",
    );
    let encoded = STANDARD.encode(signed);
    // Repeating SP logout still reports the matched session even on Ok(false).
    for _ in 0..2 {
        let request = Request::builder()
            .method("POST")
            .uri("/saml/test/slo")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "SAMLRequest={}",
                urlencoding::encode(&encoded)
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 32_768)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"], "logout_received");
        assert_eq!(json["revoked_sessions"], serde_json::json!(["sp-local"]));
        assert!(repo.get_session("sp-local").await.unwrap().unwrap().revoked);
        assert_eq!(take_logout_revoke_scopes(), vec![Some("test".to_owned())],);
    }

    for (id, expected) in [
        ("foreign", StatusCode::UNAUTHORIZED),
        ("missing", StatusCode::UNAUTHORIZED),
        ("browser-local", StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/saml/test/slo/initiate")
                    .header(header::COOKIE, format!("{cookie_name}={id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body = axum::body::to_bytes(response.into_body(), 32_768)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if expected == StatusCode::OK {
            assert_eq!(json["result"], "logged_out");
            assert_eq!(json["session_id"], id);
            assert_eq!(json["user_id"], "user");
        } else {
            assert_eq!(json["error"], "saml_logout_required");
        }
    }
    assert!(
        repo.get_session("browser-local")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        serde_json::to_value(repo.get_session("foreign").await.unwrap()).unwrap(),
        foreign_before,
    );
    assert!(repo.get_session("missing").await.unwrap().is_none());
    assert_eq!(take_logout_revoke_scopes(), vec![Some("test".to_owned())],);
}

#[tokio::test]
async fn signed_logout_binds_every_selected_session_to_the_name_id_subject() {
    let (_directory, repo, app, _) = logout_app().await;
    create_user(&repo, "user-a", "a@example.com").await;
    create_user(&repo, "user-b", "b@example.com").await;
    let now = qid_core::util::now_seconds();
    for (id, user_id) in [("session-a", "user-a"), ("session-b", "user-b")] {
        repo.create_session(&Session {
            id: id.into(),
            realm_id: "test".into(),
            user_id: user_id.into(),
            auth_time: now,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: now + 600,
            absolute_expires_at: now + 600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
    }
    let before_a = serde_json::to_value(repo.get_session("session-a").await.unwrap()).unwrap();
    let before_b = serde_json::to_value(repo.get_session("session-b").await.unwrap()).unwrap();
    let email_a = format!(
        r#"<s:NameID Format="{}">a@example.com</s:NameID>"#,
        EMAIL_NAME_ID_FORMAT
    );
    let persistent_a = format!(
        r#"<s:NameID Format="{}">user-a</s:NameID>"#,
        crate::PERSISTENT_NAME_ID_FORMAT
    );
    for name in [
        email_a.as_str(),
        persistent_a.as_str(),
        "<s:NameID>user-a</s:NameID>",
        "", // A signed request without NameID cannot authorize revocation.
        "<s:NameID/>",
        "<s:NameID>unknown-user</s:NameID>",
    ] {
        // The matching session comes first, so incremental validation would
        // wrongly revoke A before discovering B's mismatched subject.
        let (status, body) = post_logout(&app, name, &["session-a", "session-b"]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["error"], "invalid_saml_logout_subject",
            "{name}: {body}"
        );
        assert_eq!(
            serde_json::to_value(repo.get_session("session-a").await.unwrap()).unwrap(),
            before_a,
        );
        assert_eq!(
            serde_json::to_value(repo.get_session("session-b").await.unwrap()).unwrap(),
            before_b,
        );
        assert!(take_logout_revoke_scopes().is_empty());
    }
    // Both emitted NameID formats and the existing unformatted ID lookup work;
    // repeated requests remain successful even when the session is revoked.
    for name in [
        email_a.as_str(),
        persistent_a.as_str(),
        "<s:NameID>user-a</s:NameID>",
    ] {
        for _ in 0..2 {
            let (status, body) = post_logout(&app, name, &["session-a"]).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["revoked_sessions"], serde_json::json!(["session-a"]));
            assert!(
                repo.get_session("session-a")
                    .await
                    .unwrap()
                    .unwrap()
                    .revoked
            );
            assert_eq!(
                serde_json::to_value(repo.get_session("session-b").await.unwrap()).unwrap(),
                before_b,
            );
            assert_eq!(take_logout_revoke_scopes(), vec![Some("test".to_owned())]);
        }
    }
    let persistent_b = format!(
        r#"<s:NameID Format="{}">user-b</s:NameID>"#,
        crate::PERSISTENT_NAME_ID_FORMAT
    );
    let (status, body) = post_logout(&app, &persistent_b, &["session-b"]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_sessions"], serde_json::json!(["session-b"]));
    assert!(
        repo.get_session("session-b")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(take_logout_revoke_scopes(), vec![Some("test".to_owned())]);
}

async fn post_logout(
    app: &Router,
    name_id: &str,
    session_indexes: &[&str],
) -> (StatusCode, serde_json::Value) {
    let indexes: String = session_indexes
        .iter()
        .map(|index| format!("<p:SessionIndex>{index}</p:SessionIndex>"))
        .collect();
    let signed = sign_test_document(
        &format!(
            r#"<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_subject_logout" Version="2.0" IssueInstant="2026-10-28T00:00:00Z" Destination="https://id.example.com/saml/test/slo"><s:Issuer>https://sp.example.com</s:Issuer><!--SIGNATURE-->{name_id}{indexes}</p:LogoutRequest>"#
        ),
        "_subject_logout",
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/saml/test/slo")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "SAMLRequest={}",
                    urlencoding::encode(&STANDARD.encode(signed))
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 32_768)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

thread_local! {
    static LOGOUT_REVOKE_SCOPES: std::cell::RefCell<Vec<Option<String>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn record_revoke_scope(scope: Option<&str>) {
    LOGOUT_REVOKE_SCOPES.with(|scopes| scopes.borrow_mut().push(scope.map(str::to_owned)));
}

fn take_logout_revoke_scopes() -> Vec<Option<String>> {
    LOGOUT_REVOKE_SCOPES.with(|scopes| std::mem::take(&mut *scopes.borrow_mut()))
}
