//! Caller coverage; atomic owner changes remain covered by storage contracts.
use super::*;
use crate::test_support::{TEST_SP_KEY_PEM, sign_test_document, test_sp_cert_body};
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
    logout_app_with_key(true, true).await
}

async fn logout_app_with_key(
    configure_key: bool,
    sign_assertions: bool,
) -> (
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
    let key_path = directory.path().join("idp.key");
    std::fs::write(&key_path, TEST_SP_KEY_PEM).unwrap();
    config.realms[0].protocols.saml.idp_signing_key_pem_path =
        configure_key.then(|| key_path.to_str().unwrap().into());
    config.realms[0].protocols.saml.sign_assertions = sign_assertions;
    config.realms[0].protocols.saml.service_providers =
        ["https://sp.example.com", "https://other-sp.example.com"]
            .map(|entity_id| SamlServiceProviderConfig {
                entity_id: entity_id.into(),
                acs_url: format!("{entity_id}/acs"),
                signing_certificates: vec![test_sp_cert_body()],
                ..Default::default()
            })
            .into();
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

async fn create_session(repo: &qid_storage::FileRepository, id: &str, realm: &str, user_id: &str) {
    let now = qid_core::util::now_seconds();
    repo.create_session(&Session {
        id: id.into(),
        realm_id: realm.into(),
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

#[tokio::test]
async fn sso_and_signed_slo_fail_closed_without_readable_idp_key() {
    for configure_key in [false, true] {
        let (directory, repo, app, cookie_name) = logout_app_with_key(configure_key, false).await;
        create_user(&repo, "user", "user@example.com").await;
        create_session(&repo, "session", "test", "user").await;
        // Binding needs the key even without response signing. An absent path
        // and an unreadable file both use the config-error response.
        if configure_key {
            std::fs::remove_file(directory.path().join("idp.key")).unwrap();
        }
        let before = serde_json::to_value(repo.get_session("session").await.unwrap()).unwrap();
        let (status, body) =
            post_sso(&app, &cookie_name, "session", "https://sp.example.com").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert!(body.contains("key"));
        let index = bind_session_index_to_sp(
            "session",
            "https://sp.example.com",
            TEST_SP_KEY_PEM.as_bytes(),
        )
        .unwrap();
        let (status, body) = post_logout(&app, "<s:NameID>user</s:NameID>", &[&index]).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert!(body["error"].as_str().unwrap().contains("key"));
        assert_eq!(
            serde_json::to_value(repo.get_session("session").await.unwrap()).unwrap(),
            before
        );
        assert!(take_logout_revoke_scopes().is_empty());
    }
}

#[tokio::test]
async fn logout_routes_preserve_same_realm_and_ignore_foreign_or_missing_sessions() {
    let (_directory, repo, app, cookie_name) = logout_app().await;
    create_user(&repo, "user", "user@example.com").await;
    for (id, realm) in [
        ("sp-local", "test"),
        ("browser-local", "test"),
        ("foreign", "other"),
    ] {
        create_session(&repo, id, realm, "user").await;
    }
    let foreign_before = serde_json::to_value(repo.get_session("foreign").await.unwrap()).unwrap();
    let indexes: Vec<_> = ["sp-local", "foreign", "missing"]
        .map(|id| {
            bind_session_index_to_sp(id, "https://sp.example.com", TEST_SP_KEY_PEM.as_bytes())
                .unwrap()
        })
        .into();
    let indexes: Vec<_> = indexes.iter().map(String::as_str).collect();
    // Repeating SP logout still reports the matched session even on Ok(false).
    for _ in 0..2 {
        let (status, json) = post_logout(&app, "<s:NameID>user</s:NameID>", &indexes).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["result"], "logout_received");
        assert_eq!(json["revoked_sessions"], serde_json::json!(["sp-local"]));
        assert!(repo.get_session("sp-local").await.unwrap().unwrap().revoked);
        assert_eq!(take_logout_revoke_scopes(), vec![Some("test".to_owned())]);
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
    let (_directory, repo, app, cookie_name) = logout_app().await;
    create_user(&repo, "user-a", "a@example.com").await;
    create_user(&repo, "user-b", "b@example.com").await;
    for (id, user_id) in [("session-a", "user-a"), ("session-b", "user-b")] {
        create_session(&repo, id, "test", user_id).await;
    }
    let index_a =
        sso_session_index(&app, &cookie_name, "session-a", "https://sp.example.com").await;
    let index_b = bind_session_index_to_sp(
        "session-b",
        "https://sp.example.com",
        TEST_SP_KEY_PEM.as_bytes(),
    )
    .unwrap();
    // Obtain B's index through signed SSO, rather than constructing it locally.
    let issued_to_other_sp = sso_session_index(
        &app,
        &cookie_name,
        "session-a",
        "https://other-sp.example.com",
    )
    .await;
    assert_ne!(issued_to_other_sp, "session-a");
    assert_eq!(
        resolve_session_index_for_sp(
            &issued_to_other_sp,
            "https://other-sp.example.com",
            TEST_SP_KEY_PEM.as_bytes()
        )
        .as_deref(),
        Some("session-a")
    );
    let before_a = serde_json::to_value(repo.get_session("session-a").await.unwrap()).unwrap();
    let before_b = serde_json::to_value(repo.get_session("session-b").await.unwrap()).unwrap();
    // Even a signed request for the right realm and user cannot use another
    // SP's index or a plain session ID. Put a valid index first to catch partial
    // revocation before the invalid second index is discovered.
    for invalid_index in [
        issued_to_other_sp,
        bind_session_index_to_sp(
            "session-a",
            "https://other-sp.example.com",
            TEST_SP_KEY_PEM.as_bytes(),
        )
        .unwrap(),
        bind_session_index_to_sp("session-a", "https://sp.example.com", b"attacker key").unwrap(),
        "session-a".to_owned(),
        "session-a.malformed".to_owned(),
    ] {
        let (status, body) = post_logout(
            &app,
            "<s:NameID>user-a</s:NameID>",
            &[&index_a, &invalid_index],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_saml_logout_session_index");
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
        let (status, body) = post_logout(&app, name, &[&index_a, &index_b]).await;
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
            let (status, body) = post_logout(&app, name, &[&index_a]).await;
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
    let (status, body) = post_logout(&app, &persistent_b, &[&index_b]).await;
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

async fn sso_session_index(app: &Router, cookie_name: &str, session: &str, issuer: &str) -> String {
    let (status, html) = post_sso(app, cookie_name, session, issuer).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    let response_b64 = html
        .split_once("name=\"SAMLResponse\" value=\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let xml = String::from_utf8(STANDARD.decode(response_b64).unwrap()).unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    doc.descendants()
        .find_map(|node| node.attribute("SessionIndex"))
        .unwrap()
        .to_owned()
}

async fn post_sso(
    app: &Router,
    cookie_name: &str,
    session: &str,
    issuer: &str,
) -> (StatusCode, String) {
    let signed = sign_test_document(
        &format!(
            r#"<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_authn" Version="2.0" IssueInstant="2026-10-28T00:00:00Z" Destination="https://id.example.com/saml/test/sso"><s:Issuer>{issuer}</s:Issuer><!--SIGNATURE--></p:AuthnRequest>"#
        ),
        "_authn",
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/saml/test/sso")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("{cookie_name}={session}"))
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
    (status, String::from_utf8(body.to_vec()).unwrap())
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
