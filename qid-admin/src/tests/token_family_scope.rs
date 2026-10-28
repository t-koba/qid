//! Observe the real route's storage arguments; storage tests cover atomicity.
use crate::*;
use axum::{body::Body, http::Request};
use qid_core::{models::TokenFamily, test_helpers::test_config, util::now_seconds};
use qid_crypto::LocalSigner;
use tower::ServiceExt;

thread_local! {
    static REVOKES: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(crate) struct ObservedFamilies<'a, R>(pub &'a R);
impl<R: TokenRepository> ObservedFamilies<'_, R> {
    pub async fn revoke_token_family(&self, id: &str, realm: &str) -> QidResult<()> {
        REVOKES.with(|calls| calls.borrow_mut().push((id.into(), realm.into())));
        self.0.revoke_token_family(id, realm).await
    }
}

fn take_revokes() -> Vec<(String, String)> {
    REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn request(id: &str, admin: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/admin/api/v1/target-realm/token-families/{id}/revoke"
        ))
        .header("x-qid-admin-session-id", admin)
        .header("x-qid-admin-reason", "family-scope-test")
        .body(Body::empty())
        .unwrap()
}

// A current-thread runtime isolates the observer; each test has its own file.
#[tokio::test]
async fn revoke_route_passes_validated_realm_to_storage() {
    assert!(take_revokes().is_empty());
    let file =
        TestFile(std::env::temp_dir().join(format!("qid-admin-family-scope-{}.json", Ulid::new())));
    let repo = Arc::new(
        qid_storage::FileRepository::new(file.0.to_str().unwrap())
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    for realm in ["target-realm", "foreign-realm"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let state = Arc::new(
        SharedState::new(
            test_config(),
            repo.clone(),
            Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests")),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let now = now_seconds();
    for (id, role) in [("security", "security.admin"), ("reader", "auditor")] {
        repo.upsert_admin(&Admin {
            id: id.into(),
            tenant_id: "tenant".into(),
            subject: format!("{id}@example.com"),
            roles: vec![role.into()],
            created_at: now,
        })
        .await
        .unwrap();
        repo.store_admin_elevation(&AdminElevation {
            id: id.into(),
            tenant_id: "tenant".into(),
            admin_id: id.into(),
            acr: Some("urn:qid:acr:phishing-resistant".into()),
            amr: vec!["pwd".into(), "hwk".into()],
            elevation_expires_at: now + 120,
            created_at: now,
        })
        .await
        .unwrap();
    }
    for (id, realm) in [("target", "target-realm"), ("foreign", "foreign-realm")] {
        repo.create_token_family(&TokenFamily {
            id: id.into(),
            realm_id: realm.into(),
            client_id: "client".into(),
            user_id: "user".into(),
            current_refresh_hash: "hash".into(),
            scopes: vec!["read".into()],
            auth_time: Some(now),
            acr: None,
            amr: vec!["pwd".into()],
            audience: vec!["api".into()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            refresh_expires_at: Some(now + 600),
            session_id: None,
            revoked: false,
        })
        .await
        .unwrap();
    }
    let app = admin_routes(&state.paths).with_state(state);
    let foreign = serde_json::to_value(repo.get_token_family("foreign").await.unwrap()).unwrap();
    let mut expected = repo.get_token_family("target").await.unwrap().unwrap();
    for (id, actor, status) in [
        ("target", "reader", StatusCode::UNAUTHORIZED),
        ("missing", "security", StatusCode::NOT_FOUND),
        ("foreign", "security", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(id, actor))
                .await
                .unwrap()
                .status(),
            status
        );
        assert!(take_revokes().is_empty(), "refused request must not write");
        assert_eq!(
            serde_json::to_value(repo.get_token_family("target").await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
    }
    assert!(repo.list_audit_events(None, 10).await.unwrap().is_empty());
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(request("target", "security"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
        // Exact arguments/count detect an unscoped write or a bypass of the seam.
        assert_eq!(
            take_revokes(),
            vec![("target".into(), "target-realm".into())]
        );
        expected.revoked = true;
        assert_eq!(
            serde_json::to_value(repo.get_token_family("target").await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(
            serde_json::to_value(repo.get_token_family("foreign").await.unwrap()).unwrap(),
            foreign
        );
    }
    let events = repo
        .list_audit_events(Some(&"target-realm".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| {
        event.action == "admin.token_family_revoke"
            && event.actor == "security@example.com"
            && event.reason == "family-scope-test"
            && event.metadata_json["admin_session"]["admin_session_id"] == "security"
            && event.metadata_json["operation"]["forced"] == true
    }));
}
