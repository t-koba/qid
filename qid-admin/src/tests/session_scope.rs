//! Observe actual route write arguments; backend contracts cover atomic ownership.
use crate::*;
use axum::{body::Body, http::Request};
use qid_core::{models::Session, test_helpers::test_config, util::now_seconds};
use qid_crypto::LocalSigner;
use tower::ServiceExt;

thread_local! {
    static REVOKES: std::cell::RefCell<Vec<(String, Option<String>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// Only the test build substitutes this receiver at each real handler callsite.
// Record arguments unchanged and delegate to the real FileRepository.
pub(crate) struct ObservedSessions<'a, R>(pub &'a R);
impl<R: SessionRepository> ObservedSessions<'_, R> {
    pub async fn revoke_session(&self, id: &str, scope: Option<&str>) -> QidResult<bool> {
        REVOKES.with(|calls| {
            calls
                .borrow_mut()
                .push((id.into(), scope.map(str::to_owned)))
        });
        self.0.revoke_session(id, scope).await
    }
}

fn take_revokes() -> Vec<(String, Option<String>)> {
    REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn request(path: &str, admin_session: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-qid-admin-session-id", admin_session)
        .header("x-qid-admin-reason", "scope-test")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

// Default current-thread runtimes keep the thread-local observer isolated even
// when these tests run concurrently. Each test also has its own backing file.
#[tokio::test]
async fn ordinary_revoke_route_passes_validated_realm_to_storage() {
    exercise_route(false).await;
}

#[tokio::test]
async fn breakglass_revoke_route_passes_validated_session_realm_to_storage() {
    exercise_route(true).await;
}

async fn exercise_route(breakglass: bool) {
    assert!(take_revokes().is_empty());
    let file = TestFile(
        std::env::temp_dir().join(format!("qid-admin-session-scope-{}.json", Ulid::new())),
    );
    let repo = Arc::new(
        qid_storage::FileRepository::new(file.0.to_str().unwrap())
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    for (realm, tenant) in [
        ("target-realm", "admin-tenant"),
        ("sibling-realm", "admin-tenant"),
        ("foreign-realm", "foreign-tenant"),
    ] {
        repo.create_realm(
            &tenant.into(),
            &realm.into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    let config = test_config();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap());
    let now = now_seconds();
    for (id, role) in [
        ("security", "security.admin"),
        ("emergency", "breakglass"),
        ("reader", "auditor"),
    ] {
        repo.upsert_admin(&Admin {
            id: id.into(),
            tenant_id: "admin-tenant".into(),
            subject: format!("{id}@example.com"),
            roles: vec![role.into()],
            created_at: now,
        })
        .await
        .unwrap();
        repo.store_admin_elevation(&AdminElevation {
            id: id.into(),
            tenant_id: "admin-tenant".into(),
            admin_id: id.into(),
            acr: Some("phr".into()),
            amr: vec!["webauthn".into()],
            elevation_expires_at: now + 120,
            created_at: now,
        })
        .await
        .unwrap();
    }
    for (id, realm) in [
        ("target", "target-realm"),
        ("sibling", "sibling-realm"),
        ("foreign", "foreign-realm"),
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
        state.session_cache_put(id.into(), id.as_bytes().to_vec(), 60);
    }
    let app = admin_routes(&state.paths).with_state(state.clone());
    let path = |id: &str| {
        if breakglass {
            format!("/admin/api/v1/breakglass/sessions/{id}/revoke")
        } else {
            format!("/admin/api/v1/target-realm/sessions/{id}/revoke")
        }
    };
    let body = serde_json::json!({"incident_id": " inc-1 ", "justification": " contain session "});
    let admin = if breakglass { "emergency" } else { "security" };
    let mut refusals = vec![
        ("target", "reader", body.clone(), StatusCode::UNAUTHORIZED),
        ("missing", admin, body.clone(), StatusCode::NOT_FOUND),
        (
            "foreign",
            admin,
            body.clone(),
            if breakglass {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::NOT_FOUND
            },
        ),
    ];
    if breakglass {
        refusals.push(("target", "security", body.clone(), StatusCode::UNAUTHORIZED));
        refusals.push((
            "target",
            admin,
            serde_json::json!({"incident_id": " ", "justification": "contain session"}),
            StatusCode::BAD_REQUEST,
        ));
    } else {
        refusals.push(("sibling", admin, body.clone(), StatusCode::NOT_FOUND));
    }
    for (id, actor, payload, status) in refusals {
        let response = app
            .clone()
            .oneshot(request(&path(id), actor, payload))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(take_revokes().is_empty(), "refused request must not revoke");
        for id in ["target", "sibling", "foreign"] {
            assert!(!repo.get_session(id).await.unwrap().unwrap().revoked);
            assert_eq!(state.session_cache_get(id), Some(id.as_bytes().to_vec()));
        }
    }
    let mut unchanged = Vec::new();
    for id in ["sibling", "foreign"] {
        unchanged.push((
            id,
            serde_json::to_value(repo.get_session(id).await.unwrap()).unwrap(),
        ));
    }
    let response = app
        .clone()
        .oneshot(request(&path("target"), admin, body.clone()))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        if breakglass {
            StatusCode::OK
        } else {
            StatusCode::NO_CONTENT
        }
    );
    // Exact call count and arguments catch both None scopes and bypasses of the seam.
    assert_eq!(
        take_revokes(),
        vec![("target".into(), Some("target-realm".into()))]
    );
    if breakglass {
        assert_eq!(
            response_json(response).await,
            serde_json::json!({
                "session_id": "target", "revoked": true, "incident_id": "inc-1",
                "realm_id": "target-realm", "user_id": "user",
            })
        );
    } else {
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert!(repo.get_session("target").await.unwrap().unwrap().revoked);
    assert!(state.session_cache_get("target").is_none());
    let repeat = app
        .oneshot(request(&path("target"), admin, body))
        .await
        .unwrap();
    assert_eq!(
        repeat.status(),
        if breakglass {
            StatusCode::OK
        } else {
            StatusCode::NO_CONTENT
        }
    );
    assert_eq!(
        take_revokes(),
        vec![("target".into(), Some("target-realm".into()))]
    );
    if breakglass {
        assert_eq!(
            response_json(repeat).await,
            serde_json::json!({
                "session_id": "target", "revoked": true, "incident_id": "inc-1",
                "realm_id": "target-realm", "user_id": "user",
            })
        );
    } else {
        assert!(
            axum::body::to_bytes(repeat.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert!(repo.get_session("target").await.unwrap().unwrap().revoked);
    assert!(state.session_cache_get("target").is_none());
    for (id, before) in unchanged {
        assert_eq!(
            serde_json::to_value(repo.get_session(id).await.unwrap()).unwrap(),
            before
        );
        assert_eq!(state.session_cache_get(id), Some(id.as_bytes().to_vec()));
    }
    let events = repo
        .list_audit_events(Some(&"target-realm".into()), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2, "each authorized request is audited");
    let action = if breakglass {
        "breakglass.session_revoke"
    } else {
        "admin.session_revoke"
    };
    assert!(events.iter().all(|event| {
        event.action == action
            && event.actor == format!("{admin}@example.com")
            && event.reason == "scope-test"
    }));
    let event = &events[0];
    assert_eq!(
        event.metadata_json["admin_session"]["admin_session_id"],
        admin
    );
    if breakglass {
        assert_eq!(event.metadata_json["operation"]["incident_id"], "inc-1");
        assert_eq!(
            event.metadata_json["operation"]["justification"],
            "contain session"
        );
        assert_eq!(
            event.metadata_json["operation"]["target_realm_id"],
            "target-realm"
        );
        assert_eq!(event.metadata_json["operation"]["target_user_id"], "user");
        assert_eq!(event.metadata_json["operation"]["breakglass"], true);
    } else {
        assert_eq!(event.metadata_json["operation"]["forced"], true);
    }
}
