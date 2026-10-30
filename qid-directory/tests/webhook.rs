use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{DirectoryProviderConfig, DirectoryWebhookConfig},
    models::{Admin, AdminElevation, ScimUser},
    state::SharedState,
    test_helpers,
    util::now_seconds,
};
use qid_storage::{AnyRepository, prelude::*};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use tower::ServiceExt;

struct Fixture {
    app: Router,
    state: Arc<SharedState<AnyRepository>>,
    session: String,
    dir: PathBuf,
}
impl Fixture {
    async fn new(sql: bool, configure: impl FnOnce(&mut qid_core::config::QidConfig)) -> Self {
        let dir = std::env::temp_dir().join(format!("qid-hr-route-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store");
        let url = if sql {
            format!("sqlite:{}", path.display())
        } else {
            path.to_str().unwrap().into()
        };
        let repo = Arc::new(AnyRepository::connect(&url).await.unwrap());
        repo.create_realm(
            &"tenant".into(),
            &"test".into(),
            "https://id.example.com/test",
            None,
        )
        .await
        .unwrap();
        let mut config = test_helpers::test_config();
        let realm = &mut config.realms[0];
        realm.tenant_id = Some("tenant".into());
        realm.protocols.directory.enabled = true;
        realm.protocols.directory.providers = vec![DirectoryProviderConfig {
            id: "hr".into(),
            provider_type: "webhook".into(),
            enabled: true,
            connection: Default::default(),
            sync: Default::default(),
            attribute_mapping: Default::default(),
            webhook: Some(DirectoryWebhookConfig {
                max_request_bytes: 2048,
                max_records: 2,
            }),
        }];
        configure(&mut config);
        let state = Arc::new(
            SharedState::new(
                config,
                repo,
                Arc::new(qid_core::jwt::NoSigningKey),
                json!({}),
            )
            .unwrap(),
        );
        let now = now_seconds();
        state
            .repo
            .upsert_admin(&Admin {
                id: "admin".into(),
                tenant_id: "tenant".into(),
                subject: "admin".into(),
                roles: vec!["directory.admin".into()],
                created_at: now,
            })
            .await
            .unwrap();
        let elevation = AdminElevation {
            id: "elevated".into(),
            tenant_id: "tenant".into(),
            admin_id: "admin".into(),
            acr: Some("phr".into()),
            amr: vec!["webauthn".into()],
            elevation_expires_at: now + 300,
            created_at: now,
        };
        state.repo.store_admin_elevation(&elevation).await.unwrap();
        let app = qid_directory::directory_routes().with_state(state.clone());
        Self {
            app,
            state,
            session: elevation.id,
            dir,
        }
    }
    async fn call(
        &self,
        uri: &str,
        body: impl Into<Body>,
        session: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::post(uri).header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("x-qid-admin-session-id", session);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(body.into()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }
    async fn post(&self, body: &str) -> (StatusCode, Value) {
        self.call(
            "/directory/v1/providers/hr/hr?realm=test",
            body.to_owned(),
            Some(&self.session),
        )
        .await
    }
    async fn post_as(&self, body: &str, content_type: &str) -> (StatusCode, Value) {
        let request = Request::post("/directory/v1/providers/hr/hr?realm=test")
            .header("content-type", content_type)
            .header("x-qid-admin-session-id", &self.session)
            .body(body.to_owned())
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }
    async fn assert_empty(&self) {
        assert!(
            self.state
                .repo
                .list_scim_users(&"test".into())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            self.state
                .repo
                .get_hr_receipt("test", "hr")
                .await
                .unwrap()
                .is_none()
        );
    }
    async fn close(self) {
        let Self {
            app,
            state,
            session: _,
            dir,
        } = self;
        drop(app);
        let repo = state.repo.clone();
        drop(state);
        match Arc::try_unwrap(repo).unwrap_or_else(|_| panic!("repository reference leaked")) {
            AnyRepository::Sql(r) => r.close().await,
            AnyRepository::File(r) => drop(r),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
fn record(key: &str, event: &str) -> Value {
    json!({"external_id":key,"user_name":key,"event":event})
}
fn body(sequence: u64, records: Vec<Value>) -> String {
    json!({"sequence":sequence,"records":records}).to_string()
}

#[tokio::test]
async fn hr_route_orders_retries_and_never_reactivates_a_stale_joiner_on_both_backends() {
    for sql in [false, true] {
        let f = Fixture::new(sql, |_| {}).await;
        let response = f
            .app
            .clone()
            .oneshot(
                Request::get("/directory/v1/providers/hr?realm=test")
                    .header("x-qid-admin-session-id", &f.session)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let detail: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(detail["syncable"], false);
        assert_eq!(detail["webhook"]["max_records"], 2);
        assert!(detail.get("deactivate_missing").is_none());
        let (status, sync_error) = f
            .call(
                "/directory/v1/providers/hr/sync?realm=test",
                Body::empty(),
                Some(&f.session),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(
            sync_error["detail"]
                .as_str()
                .unwrap()
                .contains("inbound webhook")
        );
        assert!(
            !sync_error["detail"]
                .as_str()
                .unwrap()
                .contains("qid-worker")
        );
        let response = f
            .app
            .clone()
            .oneshot(
                Request::get("/directory/v1/providers/hr/sync/status?realm=test")
                    .header("x-qid-admin-session-id", &f.session)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let status_error: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(
            status_error["detail"]
                .as_str()
                .unwrap()
                .contains("inbound webhook")
        );
        let joiner = body(1, vec![record("employee", "joiner")]);
        let (status, result) = f.post(&joiner).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result,
            json!({"sequence":1,"created":1,"updated":0,"deprovisioned":0,"replayed":false})
        );
        let (_, replay) = f.post(&joiner).await;
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["created"], 1);
        assert_eq!(
            f.post(&format!("{joiner} ")).await.0,
            StatusCode::CONFLICT,
            "digest covers exact bytes"
        );
        assert_eq!(f.post(&body(3, vec![])).await.0, StatusCode::CONFLICT);
        assert_eq!(f.post(&body(0, vec![])).await.0, StatusCode::CONFLICT);
        let leaver = body(2, vec![record("employee", "leaver")]);
        assert_eq!(f.post(&leaver).await.0, StatusCode::OK);
        assert_eq!(f.post(&joiner).await.0, StatusCode::CONFLICT);
        let users = f.state.repo.list_scim_users(&"test".into()).await.unwrap();
        assert_eq!(users.len(), 1);
        assert!(!users[0].active);
        assert!(users[0].deprovisioned_at.is_some());
        let receipt = f
            .state
            .repo
            .get_hr_receipt("test", "hr")
            .await
            .unwrap()
            .unwrap();
        let encoded = serde_json::to_string(&receipt).unwrap();
        assert!(!encoded.contains("employee"));
        assert_eq!(
            receipt.digest,
            qid_core::util::sha256_hex(leaver.as_bytes())
        );
        f.close().await;
    }
}

#[tokio::test]
async fn hr_route_preflights_the_whole_batch_without_effects_on_both_backends() {
    for sql in [false, true] {
        let f = Fixture::new(sql, |_| {}).await;
        for records in [
            vec![record("prefix", "joiner"), record("missing", "leaver")],
            vec![record("duplicate", "joiner"), record("duplicate", "mover")],
            vec![
                record("prefix", "joiner"),
                json!({"external_id":"another","user_name":"prefix","event":"joiner"}),
            ],
        ] {
            assert_eq!(f.post(&body(1, records)).await.0, StatusCode::CONFLICT);
            f.assert_empty().await;
        }
        for id in ["a", "b"] {
            f.state
                .repo
                .create_scim_user(&ScimUser {
                    id: id.into(),
                    realm_id: "test".into(),
                    external_id: Some("ambiguous".into()),
                    user_name: id.into(),
                    name_json: json!({}),
                    emails_json: json!([]),
                    enterprise_json: json!({}),
                    directory_provider_id: None,
                    deprovisioned_at: None,
                    active: true,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            f.post(&body(
                1,
                vec![record("prefix", "joiner"), record("ambiguous", "mover")]
            ))
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            f.state
                .repo
                .list_scim_users(&"test".into())
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(
            f.state
                .repo
                .get_hr_receipt("test", "hr")
                .await
                .unwrap()
                .is_none()
        );
        f.close().await;
    }
}

#[tokio::test]
async fn hr_route_rejects_unknown_authority_fields_and_bounds_before_preflight() {
    let f = Fixture::new(false, |_| {}).await;
    assert_eq!(
        f.post_as(&body(1, vec![]), "text/plain").await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    for raw in [
        body(
            1,
            vec![json!({"external_id":" ","user_name":"worker","event":"joiner"})],
        ),
        body(
            1,
            vec![json!({"external_id":"employee","user_name":"  ","event":"joiner"})],
        ),
        r#"{"sequence":1,"records":[],"realm_id":"forged"}"#.to_string(),
        r#"{"sequence":1,"records":[],"provider_id":"forged"}"#.to_string(),
        body(
            1,
            vec![json!({"external_id":"x","user_name":"x","event":"joiner","tenant_id":"forged"})],
        ),
        body(
            1,
            vec![
                json!({"external_id":"x","user_name":"x","event":"joiner","directory_provider_id":"forged"}),
            ],
        ),
        r#"{"sequence":1,"sequence":1,"records":[]}"#.to_string(),
        r#"{"sequence":1.5,"records":[]}"#.to_string(),
        "not json".to_string(),
        "[1,[]]".to_string(),
        r#"{"sequence":1,"records":[["x","x",null,null,null,null,"joiner"]]}"#.to_string(),
    ] {
        assert_eq!(f.post(&raw).await.0, StatusCode::BAD_REQUEST);
        f.assert_empty().await;
    }
    assert_eq!(
        f.post(&body(
            1,
            vec![
                record("a", "joiner"),
                record("b", "joiner"),
                record("c", "joiner")
            ]
        ))
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        f.post(&"x".repeat(2049)).await.0,
        StatusCode::PAYLOAD_TOO_LARGE,
        "byte bound precedes JSON parsing"
    );
    f.assert_empty().await;
    // Exactly the byte and record limits are accepted.
    let mut exact = body(1, vec![record("a", "joiner"), record("b", "joiner")]);
    exact.push_str(&" ".repeat(2048 - exact.len()));
    assert_eq!(f.post(&exact).await.0, StatusCode::OK);
    f.close().await;
    // No accidental Axum 2 MiB extractor limit when a provider allows more.
    let f = Fixture::new(false, |c| {
        c.realms[0].protocols.directory.providers[0].webhook = None
    })
    .await;
    let mut raw = body(1, vec![]);
    raw.push_str(&" ".repeat(2 * 1024 * 1024));
    assert_eq!(f.post(&raw).await.0, StatusCode::OK);
    f.close().await;
}

#[tokio::test]
async fn hr_route_requires_session_stepup_roles_and_tenant_bound_configured_provider() {
    let f = Fixture::new(false, |c| {
        let mut other = c.realms[0].clone();
        other.id = "other".into();
        other.issuer = "https://id.example.com/other".into();
        other.tenant_id = Some("another-tenant".into());
        c.realms.push(other);
    })
    .await;
    let raw = body(1, vec![]);
    for session in [None, Some("invalid")] {
        assert_eq!(
            f.call(
                "/directory/v1/providers/hr/hr?realm=test",
                raw.clone(),
                session
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.call(
            "/directory/v1/providers/hr/hr",
            raw.clone(),
            Some(&f.session)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "multi-realm request must select realm"
    );
    assert_eq!(
        f.call(
            "/directory/v1/providers/hr/hr?realm=other",
            raw.clone(),
            Some(&f.session)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "path provider does not authorize another tenant"
    );
    assert_eq!(
        f.call(
            "/directory/v1/providers/absent/hr?realm=test",
            raw.clone(),
            Some(&f.session)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.call(
            "/directory/v1/providers/hr/hr?realm=absent",
            raw.clone(),
            Some(&f.session)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let mut elevation = f
        .state
        .repo
        .get_admin_elevation(&f.session)
        .await
        .unwrap()
        .unwrap();
    elevation.id = "expired".into();
    elevation.elevation_expires_at = 1;
    f.state
        .repo
        .store_admin_elevation(&elevation)
        .await
        .unwrap();
    assert_eq!(
        f.call(
            "/directory/v1/providers/hr/hr?realm=test",
            raw.clone(),
            Some("expired")
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    elevation.id = "weak".into();
    elevation.elevation_expires_at = now_seconds() + 300;
    elevation.acr = None;
    elevation.amr = vec!["pwd".into()];
    f.state
        .repo
        .store_admin_elevation(&elevation)
        .await
        .unwrap();
    assert_eq!(
        f.call(
            "/directory/v1/providers/hr/hr?realm=test",
            raw,
            Some("weak")
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut admin = f
        .state
        .repo
        .get_admin_by_id("admin")
        .await
        .unwrap()
        .unwrap();
    admin.roles = vec![];
    f.state.repo.upsert_admin(&admin).await.unwrap();
    assert_eq!(f.post(&body(1, vec![])).await.0, StatusCode::UNAUTHORIZED);
    f.assert_empty().await;
    f.close().await;
    for mode in 0..4 {
        let f = Fixture::new(false, |c| match mode {
            0 => c.realms[0].protocols.directory.enabled = false,
            1 => c.realms[0].protocols.directory.providers[0].enabled = false,
            2 => c.realms[0].protocols.directory.providers[0].provider_type = "ldap".into(),
            _ => c.realms[0].tenant_id = None,
        })
        .await;
        let status = f.post(&body(1, vec![])).await.0;
        assert_eq!(
            status,
            if mode == 3 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            }
        );
        f.assert_empty().await;
        f.close().await;
    }
}
