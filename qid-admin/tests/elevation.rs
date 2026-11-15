#![cfg(test)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use qid_admin::admin_routes;
use qid_core::{
    config::QidConfig,
    models::{Admin, AdminApproval, Session, User},
    state::SharedState,
    test_helpers::test_config,
    util::now_seconds,
};
use qid_crypto::LocalSigner;
use qid_storage::{AnyRepository, prelude::*};
use serde_json::{Value, json};
use sqlx::{Connection, SqliteConnection};
use std::sync::Arc;
use tower::ServiceExt;

const SOURCE: &str = "opaque-browser-cookie-never-audit";
const EXCHANGE: &str = "/admin/api/v1/test/elevation";
const MUTATION: &str = "/admin/api/v1/test/sessions/target/revoke";

struct Fixture {
    state: Arc<SharedState<AnyRepository>>,
    dir: tempfile::TempDir,
    location: String,
    source: Session,
    admin: Admin,
}

impl Fixture {
    async fn new(sqlite: bool, config: QidConfig, binding: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(if sqlite { "repo.db" } else { "repo.json" });
        let location = if sqlite {
            format!("sqlite:{}", path.display())
        } else {
            path.to_str().unwrap().into()
        };
        let mut repo = AnyRepository::connect(&location).await.unwrap();
        for realm in ["test", "other", "unconfigured"] {
            repo.create_realm(
                &"tenant".into(),
                &realm.into(),
                &format!("https://example.com/{realm}"),
                None,
            )
            .await
            .unwrap();
        }
        for (id, realm) in [
            ("operator", "test"),
            ("ordinary", "test"),
            ("foreign", "other"),
        ] {
            repo.create_user(&User {
                id: id.into(),
                realm_id: realm.into(),
                email: None,
                email_verified: false,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
        }
        let now = now_seconds();
        let admin = Admin {
            id: "admin".into(),
            tenant_id: "tenant".into(),
            subject: "operator".into(),
            roles: vec!["security.admin".into()],
            created_at: now,
        };
        repo.upsert_admin(&admin).await.unwrap();
        let source = Session {
            id: SOURCE.into(),
            realm_id: "test".into(),
            user_id: "operator".into(),
            auth_time: now - 86400,
            acr: Some("phr".into()),
            amr: vec!["pwd".into(), "webauthn".into()],
            idle_expires_at: now + 3600,
            absolute_expires_at: now + 7200,
            revoked: false,
            created_at: now - 86400,
            cnf: None,
        };
        repo.create_session(&source).await.unwrap();
        let mut target = source.clone();
        target.id = "target".into();
        repo.create_session(&target).await.unwrap();
        // Model missing/stale stored bindings without cascading away the source.
        if binding != Some("tenant") {
            if sqlite {
                let mut conn = SqliteConnection::connect(&location).await.unwrap();
                sqlx::query("PRAGMA foreign_keys = OFF")
                    .execute(&mut conn)
                    .await
                    .unwrap();
                if let Some(tenant) = binding {
                    sqlx::query("UPDATE realms SET tenant_id = ? WHERE id = 'test'")
                        .bind(tenant)
                        .execute(&mut conn)
                        .await
                        .unwrap();
                } else {
                    sqlx::query("DELETE FROM realms WHERE id = 'test'")
                        .execute(&mut conn)
                        .await
                        .unwrap();
                }
                conn.close().await.unwrap();
            } else {
                repo.flush().await.unwrap();
                drop(repo);
                let mut data: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                if let Some(tenant) = binding {
                    data["realm_tenants"]["test"] = json!(tenant);
                } else {
                    data["realm_tenants"]
                        .as_object_mut()
                        .unwrap()
                        .remove("test");
                }
                std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
                repo = AnyRepository::connect(&location).await.unwrap();
            }
        }
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let state = Arc::new(SharedState::new(config, Arc::new(repo), signer, json!({})).unwrap());
        Self {
            state,
            dir,
            location,
            source,
            admin,
        }
    }

    fn cookie(&self, id: &str) -> String {
        format!(
            "{}={id}",
            self.state
                .require_realm("test")
                .unwrap()
                .browser_session
                .cookie_name
        )
    }

    async fn request(
        &self,
        path: &str,
        cookie: Option<&str>,
        elevation: Option<&str>,
        reason: bool,
        approval: Option<&str>,
    ) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            // None of these caller claims may establish assurance or identity.
            .header("x-qid-admin-acr", "phr")
            .header("x-qid-admin-amr", "webauthn")
            .header("x-qid-admin-roles", "breakglass");
        if let Some(value) = cookie {
            request = request.header("cookie", value);
        }
        if let Some(value) = elevation {
            request = request.header("x-qid-admin-session-id", value);
        }
        if reason {
            request = request.header("x-qid-admin-reason", " ticket-42 ");
        }
        if let Some(value) = approval {
            request = request.header("x-qid-admin-approval-id", value);
        }
        let claims = json!({
            "user_id": "operator", "roles": ["breakglass"], "acr": "phr",
            "amr": ["webauthn"], "session_id": SOURCE, "auth_time": now_seconds(),
        });
        let request = request.body(Body::from(claims.to_string())).unwrap();
        admin_routes(&self.state.paths)
            .with_state(self.state.clone())
            .oneshot(request)
            .await
            .unwrap()
    }

    async fn exchange(&self, id: &str) -> Response {
        self.request(EXCHANGE, Some(&self.cookie(id)), None, true, None)
            .await
    }

    async fn elevation_count(&self) -> usize {
        match &*self.state.repo {
            AnyRepository::Sql(_) => {
                let mut conn = SqliteConnection::connect(&self.location).await.unwrap();
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_elevations")
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
                conn.close().await.unwrap();
                count as usize
            }
            AnyRepository::File(_) => {
                self.state.repo.flush().await.unwrap();
                let data: Value =
                    serde_json::from_slice(&std::fs::read(&self.location).unwrap()).unwrap();
                data["admin_elevations"].as_object().unwrap().len()
            }
        }
    }

    async fn close(self) {
        let repo = self.state.repo.clone();
        drop(self.state);
        let Ok(repo) = Arc::try_unwrap(repo) else {
            panic!("repository still referenced")
        };
        match repo {
            AnyRepository::Sql(repo) => repo.close().await,
            AnyRepository::File(repo) => drop(repo),
        }
        self.dir.close().unwrap();
    }
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn no_store(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn exchange_stores_only_server_provenance_and_bounded_assurance() {
    for sqlite in [false, true] {
        let mut config = test_config();
        config.realms[0].sessions.browser.cookie_name = "admin-browser".into();
        config.admin.security.max_elevation_seconds = 120;
        let f = Fixture::new(sqlite, config, Some("tenant")).await;
        // Default cookie name and elevation headers alone cannot authenticate.
        assert_eq!(
            f.request(
                EXCHANGE,
                Some(&format!("__Host-qid={SOURCE}")),
                Some("forged"),
                true,
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        for (id, idle, absolute) in [
            (SOURCE, 3600, 7200),
            ("idle-bound", 60, 90),
            ("absolute-bound", 90, 60),
        ] {
            let mut session = f.source.clone();
            if id != SOURCE {
                session.id = id.into();
                session.idle_expires_at = now_seconds() + idle;
                session.absolute_expires_at = now_seconds() + absolute;
                f.state.repo.create_session(&session).await.unwrap();
            }
            let response = f.exchange(id).await;
            assert_eq!(response.status(), StatusCode::OK);
            no_store(&response);
            let json = body(response).await;
            assert_eq!(json.as_object().unwrap().len(), 2);
            let bearer = json["admin_session_id"].as_str().unwrap();
            assert_ne!(bearer, id);
            let stored = f
                .state
                .repo
                .get_admin_elevation(bearer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.source_session_id.as_deref(), Some(id));
            assert_eq!(stored.admin_id, f.admin.id);
            assert_eq!(stored.tenant_id, "tenant");
            assert_eq!(stored.acr, session.acr);
            assert_eq!(stored.amr, session.amr);
            assert_eq!(
                stored.elevation_expires_at,
                (stored.created_at + 120)
                    .min(session.idle_expires_at)
                    .min(session.absolute_expires_at)
            );
            assert_eq!(json["expires_at"], stored.elevation_expires_at);
            let events = f
                .state
                .repo
                .list_audit_events(Some(&"test".into()), 20)
                .await
                .unwrap();
            let event = events
                .iter()
                .find(|e| {
                    e.created_at == stored.created_at
                        && e.metadata_json["admin_session"]["elevation_expires_at"]
                            == stored.elevation_expires_at
                })
                .unwrap();
            assert_eq!(event.action, "admin.elevation.issue.intent");
            assert_eq!(event.actor, "operator");
            assert_eq!(event.target_type, "admin");
            assert_eq!(event.target_id, "admin");
            assert_eq!(event.reason, "ticket-42");
            assert_eq!(
                event.metadata_json["operation"]["auth_time"],
                session.auth_time
            );
            let serialized = serde_json::to_string(&events).unwrap();
            assert!(!serialized.contains(bearer));
            assert!(!serialized.contains(id));
        }
        assert_eq!(f.elevation_count().await, 3);
        f.close().await;
    }
}

#[tokio::test]
async fn exchange_rejects_invalid_sources_and_ignores_caller_claims() {
    for sqlite in [false, true] {
        let f = Fixture::new(sqlite, test_config(), Some("tenant")).await;
        for (cookie, reason, status) in [
            (None, true, StatusCode::UNAUTHORIZED),
            (Some(f.cookie("missing")), true, StatusCode::UNAUTHORIZED),
            (Some(f.cookie(SOURCE)), false, StatusCode::BAD_REQUEST),
        ] {
            let response = f
                .request(EXCHANGE, cookie.as_deref(), None, reason, None)
                .await;
            assert_eq!(response.status(), status);
            no_store(&response);
        }
        for variant in [
            "expired-idle",
            "expired-absolute",
            "revoked",
            "no-lifetime",
            "wrong-realm",
            "wrong-user",
            "user-realm",
            "weak-acr",
            "weak-amr",
            "no-acr",
        ] {
            let mut session = f.source.clone();
            session.id = variant.into();
            match variant {
                "expired-idle" => session.idle_expires_at = now_seconds() - 1,
                "expired-absolute" => session.absolute_expires_at = now_seconds() - 1,
                "revoked" => session.revoked = true,
                "no-lifetime" => session.idle_expires_at = now_seconds(),
                "wrong-realm" => session.realm_id = "other".into(),
                "wrong-user" => session.user_id = "ordinary".into(),
                "user-realm" => session.user_id = "foreign".into(),
                "weak-acr" => session.acr = Some("pwd".into()),
                "weak-amr" => session.amr = vec!["pwd".into()],
                "no-acr" => session.acr = None,
                _ => unreachable!(),
            }
            // A real Admin for the foreign user isolates user-realm validation.
            if variant == "user-realm" {
                let mut admin = f.admin.clone();
                admin.id = "foreign-admin".into();
                admin.subject = "foreign".into();
                f.state.repo.upsert_admin(&admin).await.unwrap();
            }
            f.state.repo.create_session(&session).await.unwrap();
            let response = f.exchange(variant).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{variant} sqlite={sqlite}"
            );
            no_store(&response);
        }
        // Even a stored realm and valid source do not enable an unconfigured path.
        let mut session = f.source.clone();
        session.id = "unconfigured-source".into();
        session.realm_id = "unconfigured".into();
        f.state.repo.create_session(&session).await.unwrap();
        assert_eq!(
            f.request(
                "/admin/api/v1/unconfigured/elevation",
                Some(&f.cookie(&session.id)),
                None,
                true,
                None
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(f.elevation_count().await, 0);
        assert!(
            f.state
                .repo
                .list_audit_events(None, 20)
                .await
                .unwrap()
                .is_empty()
        );
        f.close().await;
    }
}

#[tokio::test]
async fn exchange_requires_stored_tenant_and_admin_binding_not_config_fallback() {
    for sqlite in [false, true] {
        for binding in [None, Some("foreign-tenant")] {
            let mut config = test_config();
            config.realms[0].tenant_id = Some("tenant".into());
            let f = Fixture::new(sqlite, config, binding).await;
            assert_eq!(f.exchange(SOURCE).await.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(f.elevation_count().await, 0);
            f.close().await;
        }
    }
}

#[tokio::test]
async fn exchange_keeps_current_roles_and_mutation_approval_policy() {
    for sqlite in [false, true] {
        let mut config = test_config();
        config.admin.security.require_approval = true;
        let f = Fixture::new(sqlite, config, Some("tenant")).await;
        let approval = AdminApproval {
            id: "approval".into(),
            tenant_id: "tenant".into(),
            approver_admin_id: f.admin.id.clone(),
            target_admin_id: f.admin.id.clone(),
            reason: Some("ticket-42".into()),
            approved_at: now_seconds(),
            expires_at: now_seconds() + 600,
            consumed: false,
        };
        f.state.repo.store_admin_approval(&approval).await.unwrap();
        let response = f
            .request(
                EXCHANGE,
                Some(&f.cookie(SOURCE)),
                None,
                true,
                Some(&approval.id),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body(response).await;
        let bearer = json["admin_session_id"].as_str().unwrap();
        assert!(
            !f.state
                .repo
                .get_admin_approval(&approval.id)
                .await
                .unwrap()
                .unwrap()
                .consumed
        );
        assert_eq!(
            f.request(MUTATION, None, Some(bearer), true, None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            !f.state
                .repo
                .get_session("target")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        // Remove the role after issuance: a valid elevation and approval are insufficient.
        let mut admin = f.admin.clone();
        admin.roles.clear();
        f.state.repo.upsert_admin(&admin).await.unwrap();
        assert_eq!(
            f.request(MUTATION, None, Some(bearer), true, Some(&approval.id))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            !f.state
                .repo
                .get_admin_approval(&approval.id)
                .await
                .unwrap()
                .unwrap()
                .consumed
        );
        assert!(
            !f.state
                .repo
                .get_session("target")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        f.state.repo.upsert_admin(&f.admin).await.unwrap();
        assert_eq!(
            f.request(MUTATION, None, Some(bearer), true, Some(&approval.id))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(
            f.state
                .repo
                .get_admin_approval(&approval.id)
                .await
                .unwrap()
                .unwrap()
                .consumed
        );
        f.close().await;
    }
}

#[tokio::test]
async fn exchange_and_authorization_share_configured_assurance() {
    for sqlite in [false, true] {
        for require_step_up in [true, false] {
            let mut config = test_config();
            config.admin.security.require_step_up = require_step_up;
            config.admin.security.required_acr = "custom-strong".into();
            config.admin.security.required_amr = vec!["custom-method".into()];
            let f = Fixture::new(sqlite, config, Some("tenant")).await;
            if require_step_up {
                assert_eq!(f.exchange(SOURCE).await.status(), StatusCode::UNAUTHORIZED);
            }
            let mut session = f.source.clone();
            session.id = "custom-source".into();
            session.acr = if require_step_up {
                Some("custom-strong".into())
            } else {
                None
            };
            session.amr = if require_step_up {
                vec!["custom-method".into()]
            } else {
                vec!["pwd".into()]
            };
            f.state.repo.create_session(&session).await.unwrap();
            let response = f.exchange(&session.id).await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            let bearer = json["admin_session_id"].as_str().unwrap();
            assert_eq!(
                f.request(MUTATION, None, Some(bearer), true, None)
                    .await
                    .status(),
                StatusCode::NO_CONTENT
            );
            f.close().await;
        }
    }
}

#[tokio::test]
async fn fail_closed_audit_failure_precedes_elevation_persistence() {
    let mut config = test_config();
    config.admin.audit_fail_closed = true;
    let f = Fixture::new(true, config, Some("tenant")).await;
    let mut conn = SqliteConnection::connect(&f.location).await.unwrap();
    sqlx::query("CREATE TRIGGER reject_elevation_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, 'deterministic audit failure'); END").execute(&mut conn).await.unwrap();
    let response = f.exchange(SOURCE).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    no_store(&response);
    assert_eq!(f.elevation_count().await, 0);
    assert!(
        f.state
            .repo
            .list_audit_events(None, 20)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("DROP TRIGGER reject_elevation_audit")
        .execute(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    assert_eq!(f.exchange(SOURCE).await.status(), StatusCode::OK);
    assert_eq!(f.elevation_count().await, 1);
    f.close().await;
}
