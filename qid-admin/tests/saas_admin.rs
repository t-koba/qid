use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{SamlProtocolConfig, SamlServiceProviderConfig},
    models::{
        Admin, AdminApproval, AdminElevation, AuditEvent, Client, ClientType, PolicyBundle,
        Session, User, default_client_jwks, default_token_endpoint_auth_method,
    },
    state::SharedState,
    tenant::{RealmId, TenantId},
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_admin_saas");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

async fn setup() -> (Router, Arc<SharedState<SqlRepository>>) {
    let config = test_helpers::test_config();
    setup_with_config(config).await
}

async fn setup_with_config(
    config: qid_core::config::QidConfig,
) -> (Router, Arc<SharedState<SqlRepository>>) {
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    seed_base_admin(&state).await;
    let app = qid_admin::admin_routes(&state.paths).with_state(state.clone());
    (app, state)
}

async fn seed_saas_realm_client(state: &SharedState<SqlRepository>) {
    state
        .repo
        .create_realm(
            &TenantId::from("tenant-saas"),
            &RealmId::from("realm-saas"),
            "https://login.customer.example.com",
            Some("SaaS tenant realm"),
        )
        .await
        .expect("create SaaS realm failed");
    state
        .repo
        .create_client(&Client {
            id: "client-saas".to_string(),
            realm_id: "realm-saas".to_string(),
            client_id: "crm-client".to_string(),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: default_token_endpoint_auth_method(),
            client_secret_hash: Some("hash".to_string()),
            mtls_certificate_thumbprints: Vec::new(),
            jwks: default_client_jwks(),
            redirect_uris: vec!["https://crm.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            default_max_age: None,
            require_auth_time: false,
            sector_identifier_uri: None,
            subject_type: None,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            backchannel_client_notification_endpoint: None,
        })
        .await
        .expect("create SaaS client failed");
}

fn json_request(method: Method, uri: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "admin-session-1")
        .body(Body::from(body))
        .unwrap()
}

fn approval_json_request(method: Method, uri: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "admin-session-1")
        .header("x-qid-admin-approval-id", "approval-123")
        .header("x-qid-admin-approver", "approver@example.com")
        .header(
            "x-qid-admin-approved-at",
            (qid_core::util::now_seconds() - 30).to_string(),
        )
        .body(Body::from(body))
        .unwrap()
}

fn admin_get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "admin-session-1")
        .body(Body::empty())
        .unwrap()
}

fn platform_admin_get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "platform.admin")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "admin-session-1")
        .body(Body::empty())
        .unwrap()
}

fn security_admin_json_request(method: Method, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "security-ticket-123")
        .header("x-qid-admin-actor", "security-admin@example.com")
        .header("x-qid-admin-roles", "security.admin")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "security-admin-session-1")
        .body(Body::from(body))
        .unwrap()
}

fn breakglass_request(uri: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "emergency-session-containment")
        .header("x-qid-admin-actor", "breakglass@example.com")
        .header("x-qid-admin-roles", "breakglass")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-session-id", "breakglass-admin-session")
        .body(Body::from(body))
        .unwrap()
}

async fn seed_base_admin(state: &SharedState<SqlRepository>) {
    let now = qid_core::util::now_seconds();
    let mut admin_map = std::collections::HashMap::new();
    for (subject, roles, session_id, acr, amr) in [
        (
            "admin@example.com",
            vec!["tenant.owner".to_string(), "platform.admin".to_string()],
            "admin-session-1",
            Some("urn:qid:acr:phishing-resistant"),
            vec!["pwd".to_string(), "hwk".to_string()],
        ),
        (
            "security-admin@example.com",
            vec!["security.admin".to_string()],
            "security-admin-session-1",
            Some("urn:qid:acr:phishing-resistant"),
            vec!["pwd".to_string(), "hwk".to_string()],
        ),
        (
            "breakglass@example.com",
            vec!["breakglass".to_string()],
            "breakglass-admin-session",
            Some("urn:qid:acr:phishing-resistant"),
            vec!["pwd".to_string(), "hwk".to_string()],
        ),
        (
            "approver@example.com",
            vec!["tenant.owner".to_string()],
            "approver-session",
            Some("urn:qid:acr:phishing-resistant"),
            vec!["pwd".to_string(), "hwk".to_string()],
        ),
    ] {
        let admin = Admin {
            id: format!("admin-{subject}"),
            tenant_id: "tenant-saas".to_string(),
            subject: subject.to_string(),
            roles,
            created_at: now,
        };
        state.repo.upsert_admin(&admin).await.unwrap();
        admin_map.insert(subject.to_string(), admin.id.clone());
        let elevation = AdminElevation {
            id: session_id.to_string(),
            tenant_id: "tenant-saas".to_string(),
            admin_id: admin.id.clone(),
            acr: acr.map(ToString::to_string),
            amr,
            elevation_expires_at: now + 120,
            created_at: now,
        };
        state.repo.store_admin_elevation(&elevation).await.unwrap();
    }

    // Pre-seed approval record for tests that use approval_json_request.
    if let (Some(target_id), Some(approver_id)) = (
        admin_map.get("admin@example.com"),
        admin_map.get("approver@example.com"),
    ) {
        state
            .repo
            .store_admin_approval(&AdminApproval {
                id: "approval-123".to_string(),
                tenant_id: "tenant-saas".to_string(),
                approver_admin_id: approver_id.clone(),
                target_admin_id: target_id.clone(),
                reason: None,
                approved_at: now - 30,
                expires_at: now + 90,
                consumed: false,
            })
            .await
            .unwrap();
    }
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn breakglass_session_revoke_requires_breakglass_role_and_audits_incident() {
    let (app, state) = setup().await;
    let now = qid_core::util::now_seconds();
    state
        .repo
        .create_realm(
            &"tenant-saas".into(),
            &"realm-bg".into(),
            "https://id.example.com/realms/bg",
            None,
        )
        .await
        .unwrap();
    state
        .repo
        .create_user(&User {
            id: "user-bg".to_string(),
            realm_id: "realm-bg".to_string(),
            email: Some("breakglass-target@example.com".to_string()),
            email_verified: true,
            display_name: Some("Breakglass Target".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    state
        .repo
        .create_session(&Session {
            id: "session-bg".to_string(),
            realm_id: "realm-bg".to_string(),
            user_id: "user-bg".to_string(),
            auth_time: now,
            acr: Some("urn:qid:acr:phishing-resistant".to_string()),
            amr: vec!["pwd".to_string(), "hwk".to_string()],
            idle_expires_at: now + 600,
            absolute_expires_at: now + 3600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();

    let owner_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/breakglass/sessions/session-bg/revoke",
            r#"{"incident_id":"inc-1","justification":"suspected account takeover"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(owner_response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        !state
            .repo
            .get_session("session-bg")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );

    let breakglass_response = app
        .clone()
        .oneshot(breakglass_request(
            "/admin/api/v1/breakglass/sessions/session-bg/revoke",
            r#"{"incident_id":"inc-1","justification":"suspected account takeover"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(breakglass_response.status(), StatusCode::OK);
    let body = response_json(breakglass_response).await;
    assert_eq!(body["session_id"], "session-bg");
    assert_eq!(body["revoked"], true);
    assert_eq!(body["incident_id"], "inc-1");

    assert!(
        state
            .repo
            .get_session("session-bg")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    let events = state
        .repo
        .list_audit_events(Some(&"realm-bg".into()), 10)
        .await
        .unwrap();
    let event = events
        .iter()
        .find(|event| event.action == "breakglass.session_revoke")
        .expect("break-glass audit event not found");
    assert_eq!(event.actor, "breakglass@example.com");
    assert_eq!(event.reason, "emergency-session-containment");
    assert_eq!(event.metadata_json["operation"]["breakglass"], true);
    assert_eq!(event.metadata_json["operation"]["incident_id"], "inc-1");
    assert_eq!(
        event.metadata_json["admin_session"]["admin_session_id"],
        "breakglass-admin-session"
    );
}

#[tokio::test]
async fn key_rotation_plan_route_requires_security_admin_and_audits_plan() {
    let (app, state) = setup().await;
    state
        .repo
        .create_realm(
            &"tenant-security".into(),
            &"corp".into(),
            "https://id.example.com/realms/corp",
            Some("Corp"),
        )
        .await
        .unwrap();
    let body = serde_json::json!({
        "inventory": [
            {
                "realm_id": "corp",
                "keyring_name": "corp-shared",
                "kid": "shared-1",
                "purpose": "pep_assertion",
                "signer_type": "local",
                "created_at_epoch": 100,
                "not_before_epoch": 100,
                "retire_after_epoch": 10000,
                "revoked": false
            },
            {
                "realm_id": "corp",
                "keyring_name": "corp-shared",
                "kid": "shared-2",
                "purpose": "oidc_token",
                "signer_type": "local",
                "created_at_epoch": 100,
                "not_before_epoch": 100,
                "retire_after_epoch": 10000,
                "revoked": false
            }
        ],
        "requirements": [
            {
                "realm_id": "corp",
                "purpose": "pep_assertion",
                "max_age_days": 90,
                "overlap_days": 14,
                "require_remote_signer": true,
                "require_dedicated_keyring": true
            }
        ],
        "now_epoch": 1000
    });

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/api/v1/key-rotation/plan")
                .header("Content-Type", "application/json")
                .header("x-qid-admin-reason", "security-ticket-123")
                .header("x-qid-admin-actor", "admin@example.com")
                .header("x-qid-admin-roles", "tenant.owner")
                .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
                .header("x-qid-admin-amr", "pwd,hwk")
                .header(
                    "x-qid-admin-elevation-expires-at",
                    (qid_core::util::now_seconds() + 60).to_string(),
                )
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(security_admin_json_request(
            Method::POST,
            "/admin/api/v1/key-rotation/plan",
            body.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["status"], "rejected");
    assert_eq!(json["rejected_count"], 1);
    assert_eq!(
        json["plans"][0]["reasons"][0],
        "dedicated_keyring_required:corp-shared"
    );

    let events = state
        .repo
        .list_audit_events(Some(&"corp".into()), 10)
        .await
        .unwrap();
    let event = events
        .iter()
        .find(|event| event.action == "key_rotation.plan")
        .expect("key rotation audit event not found");
    assert_eq!(event.actor, "security-admin@example.com");
    assert_eq!(event.reason, "security-ticket-123");
    assert_eq!(event.metadata_json["operation"]["rejected_count"], 1);
}

#[tokio::test]
async fn policy_simulator_uses_active_bundle_and_records_audit() {
    let (app, state) = setup().await;
    state
        .repo
        .create_realm(
            &TenantId::from("tenant-saas"),
            &RealmId::from("test"),
            "https://id.example.com",
            Some("Test Realm"),
        )
        .await
        .unwrap();
    state
        .repo
        .create_policy_bundle(&PolicyBundle {
            id: "policy-sim".to_string(),
            realm_id: "test".to_string(),
            name: "sim-bundle".to_string(),
            source_hash: "sha256:sim".to_string(),
            compiled_json: serde_json::json!({
                "version": "1",
                "default_decision": "deny",
                "rules": [
                    {
                        "name": "allow-finance-read",
                        "type": "allow",
                        "action": "document.read",
                        "resource_host": "finance.example.com",
                        "conditions": [
                            {"field": "group", "op": "contains", "value": "finance"}
                        ]
                    }
                ]
            }),
            version: 1,
            active: true,
        })
        .await
        .unwrap();

    let response = app
        .oneshot(security_admin_json_request(
            Method::POST,
            "/admin/api/v1/test/policy/simulate",
            serde_json::json!({
                "subject": "alice@example.com",
                "groups": ["finance"],
                "action": "document.read",
                "resource_host": "finance.example.com",
                "risk_score": 10
            })
            .to_string(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["active_bundle"], "sim-bundle");
    assert_eq!(body["decision"]["decision"], "allow");
    assert_eq!(body["decision"]["policy_id"], "allow-finance-read");
    assert_eq!(body["decision"]["matched_rules"][0], "allow-finance-read");

    let events = state
        .repo
        .list_audit_events(Some(&RealmId::from("test".to_string())), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "policy.simulate");
    assert_eq!(events[0].target_id, "sim-bundle");
    assert_eq!(events[0].metadata_json["operation"]["dry_run"], true);
}

#[tokio::test]
async fn admin_ui_shell_and_dashboard_report_operational_status() {
    let (app, state) = setup().await;
    state
        .repo
        .create_realm(
            &"tenant-ui".into(),
            &"realm-ui".into(),
            "https://id.example.com/realms/ui",
            Some("UI Realm"),
        )
        .await
        .unwrap();
    state
        .repo
        .create_user(&User {
            id: "user-ui".to_string(),
            realm_id: "realm-ui".to_string(),
            email: Some("ui@example.com".to_string()),
            email_verified: true,
            display_name: Some("UI User".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    state
        .repo
        .create_client(&Client {
            id: "client-ui".to_string(),
            realm_id: "realm-ui".to_string(),
            client_id: "ui-client".to_string(),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: default_token_endpoint_auth_method(),
            client_secret_hash: Some("hash".to_string()),
            mtls_certificate_thumbprints: Vec::new(),
            jwks: default_client_jwks(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            default_max_age: None,
            require_auth_time: false,
            sector_identifier_uri: None,
            subject_type: None,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            backchannel_client_notification_endpoint: None,
        })
        .await
        .unwrap();
    state
        .repo
        .create_policy_bundle(&PolicyBundle {
            id: "policy-ui".to_string(),
            realm_id: "realm-ui".to_string(),
            name: "default".to_string(),
            source_hash: "hash".to_string(),
            compiled_json: serde_json::json!({"version": 1, "rules": []}),
            version: 1,
            active: true,
        })
        .await
        .unwrap();
    state
        .repo
        .append_audit_event(&AuditEvent {
            id: "audit-ui".to_string(),
            realm_id: Some("realm-ui".to_string()),
            actor: "admin@example.com".to_string(),
            action: "dashboard.seed".to_string(),
            target_type: "dashboard".to_string(),
            target_id: "admin-ui".to_string(),
            reason: "test".to_string(),
            metadata_json: serde_json::json!({}),
            created_at: qid_core::util::now_seconds(),
            previous_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();

    let shell_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/admin/ui")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shell_response.status(), StatusCode::OK);
    let content_type = shell_response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/html"));
    let shell = String::from_utf8(
        shell_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(shell.contains("qid admin"));
    assert!(shell.contains("/admin/api/v1/ui/dashboard"));

    let dashboard_response = app
        .clone()
        .oneshot(platform_admin_get_request("/admin/api/v1/ui/dashboard"))
        .await
        .unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = response_json(dashboard_response).await;
    assert_eq!(dashboard["realm_count"], 1);
    assert_eq!(dashboard["user_count"], 1);
    assert_eq!(dashboard["client_count"], 1);
    assert_eq!(dashboard["policy_bundle_count"], 1);
    assert_eq!(dashboard["audit_event_count"], 1);
    assert_eq!(dashboard["breakglass_enabled"], true);
    assert_eq!(dashboard["realms"][0]["id"], "realm-ui");
    assert_eq!(dashboard["realms"][0]["user_count"], 1);
    assert!(
        dashboard["views"]
            .as_array()
            .unwrap()
            .iter()
            .any(|view| view["label"] == "Audit search")
    );
    assert!(
        dashboard["conformance"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == "OAuth/OIDC" && item["status"] == "ready")
    );
}

#[tokio::test]
async fn saas_admin_routes_create_list_delete_and_audit() {
    let (app, state) = setup().await;
    seed_saas_realm_client(&state).await;

    let domain_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/custom-domains",
            r#"{
                "id":"domain-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "hostname":"login.customer.example.com",
                "certificate_ref":"",
                "verified":false,
                "verification_status":"pending",
                "dns_challenge_name":"_qid.login.customer.example.com",
                "dns_challenge_value":"qid-domain-proof",
                "certificate_expires_at":null,
                "certificate_renew_after":null,
                "last_verified_at":null
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(domain_response.status(), StatusCode::CREATED);
    let domain = response_json(domain_response).await;
    assert_eq!(domain["hostname"], "login.customer.example.com");
    assert_eq!(domain["verification_status"], "pending");

    let activate_domain_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/custom-domains/domain-1/activate",
            r#"{
                "dns_challenge_value":"qid-domain-proof",
                "certificate_ref":"kms://certificates/customer-login",
                "certificate_expires_at":1900000000,
                "certificate_renew_after":1880000000,
                "verified_at":1800000000
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(activate_domain_response.status(), StatusCode::OK);
    let activated_domain = response_json(activate_domain_response).await;
    assert_eq!(activated_domain["verification_status"], "active");
    assert_eq!(activated_domain["verified"], true);

    let renew_domain_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/custom-domains/domain-1/renew-certificate",
            r#"{
                "certificate_ref":"kms://certificates/customer-login-v2",
                "certificate_expires_at":1960000000,
                "certificate_renew_after":1940000000
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(renew_domain_response.status(), StatusCode::OK);
    let renewed_domain = response_json(renew_domain_response).await;
    assert_eq!(
        renewed_domain["certificate_ref"],
        "kms://certificates/customer-login-v2"
    );

    let brand_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/ciam-brands",
            r##"{
                "id":"brand-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Customer Blue",
                "primary_color":"#2f6fed",
                "logo_uri":"https://cdn.example.com/logo.svg",
                "privacy_policy_uri":"https://www.example.com/privacy",
                "support_uri":"https://support.example.com",
                "terms_version":"2026-06",
                "active":true
            }"##,
        ))
        .await
        .unwrap();
    assert_eq!(brand_response.status(), StatusCode::CREATED);

    let brand_list_response = app
        .clone()
        .oneshot(admin_get_request(
            "/admin/api/v1/tenants/tenant-saas/ciam-brands",
        ))
        .await
        .unwrap();
    assert_eq!(brand_list_response.status(), StatusCode::OK);
    let brands = response_json(brand_list_response).await;
    assert_eq!(brands[0]["display_name"], "Customer Blue");

    let connector_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/marketplace-connectors",
            r#"{
                "id":"connector-1",
                "tenant_id":"tenant-saas",
                "provider":"example-crm",
                "connector_type":"scim",
                "config_json":{
                    "base_url":"https://crm.example.com/scim/v2",
                    "token_ref":"kms://secrets/crm-scim-token"
                },
                "enabled":true
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(connector_response.status(), StatusCode::CREATED);

    let app_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            r#"{
                "id":"app-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Customer CRM",
                "category":"sales",
                "oidc_client_id":"crm-client",
                "saml_entity_id":null,
                "scim_enabled":true,
                "marketplace_connector_id":"connector-1"
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(app_response.status(), StatusCode::CREATED);

    let usage_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/usage-billing-events",
            r#"{
                "id":"usage-1",
                "tenant_id":"tenant-saas",
                "meter":"active_users",
                "quantity":42,
                "occurred_at":1700000000,
                "idempotency_key":"tenant-saas:usage-1",
                "dimensions":{"realm":"realm-saas"}
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(usage_response.status(), StatusCode::CREATED);

    let evidence_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/compliance-evidence-packs",
            r#"{
                "id":"evidence-1",
                "tenant_id":"tenant-saas",
                "period_start":1700000000,
                "period_end":1702592000,
                "controls":["SOC2-CC6.1","ISO27001-A.5.15"],
                "object_uri":"s3://qid-evidence/tenant-saas/2026-01.jsonl",
                "sha256_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "generated_at":1702592100
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(evidence_response.status(), StatusCode::CREATED);

    let delegated_admin_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/delegated-admins",
            r#"{
                "id":"delegated-admin-1",
                "tenant_id":"tenant-saas",
                "subject":"delegated@example.com",
                "roles":["app.admin","auditor"],
                "allowed_realm_ids":["realm-saas"],
                "granted_by":"admin@example.com",
                "granted_at":1800000000,
                "expires_at":1860000000,
                "revoked":false
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(delegated_admin_response.status(), StatusCode::CREATED);

    let delegated_admin_list_response = app
        .clone()
        .oneshot(admin_get_request(
            "/admin/api/v1/tenants/tenant-saas/delegated-admins",
        ))
        .await
        .unwrap();
    assert_eq!(delegated_admin_list_response.status(), StatusCode::OK);
    let delegated_admins = response_json(delegated_admin_list_response).await;
    assert_eq!(delegated_admins[0]["subject"], "delegated@example.com");
    assert_eq!(
        delegated_admins[0]["roles"],
        serde_json::json!(["app.admin", "auditor"])
    );

    let revoke_delegated_admin_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/delegated-admins/delegated-admin-1/revoke",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(
        revoke_delegated_admin_response.status(),
        StatusCode::NO_CONTENT
    );

    let list_response = app
        .clone()
        .oneshot(admin_get_request(
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
        ))
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let entries = response_json(list_response).await;
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["display_name"], "Customer CRM");

    let delete_response = app
        .clone()
        .oneshot(json_request(
            Method::DELETE,
            "/admin/api/v1/tenants/tenant-saas/custom-domains/domain-1",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let delete_brand_response = app
        .clone()
        .oneshot(json_request(
            Method::DELETE,
            "/admin/api/v1/tenants/tenant-saas/ciam-brands/brand-1",
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(delete_brand_response.status(), StatusCode::NO_CONTENT);

    let audit = state.repo.list_audit_events(None, 20).await.unwrap();
    let actions: Vec<_> = audit.iter().map(|event| event.action.as_str()).collect();
    assert!(actions.contains(&"custom_domain.create"));
    assert!(actions.contains(&"custom_domain.activate"));
    assert!(actions.contains(&"custom_domain.certificate_renew"));
    assert!(actions.contains(&"ciam_brand.create"));
    assert!(actions.contains(&"marketplace_connector.create"));
    assert!(actions.contains(&"app_catalog_entry.create"));
    assert!(actions.contains(&"usage_billing_event.create"));
    assert!(actions.contains(&"compliance_evidence_pack.create"));
    assert!(actions.contains(&"delegated_tenant_admin.create"));
    assert!(actions.contains(&"delegated_tenant_admin.revoke"));
    assert!(actions.contains(&"custom_domain.delete"));
    assert!(actions.contains(&"ciam_brand.delete"));
    assert!(
        audit
            .iter()
            .all(|event| event.actor == "admin@example.com" && event.reason == "ticket-123")
    );
    assert!(audit.iter().any(|event| {
        event.metadata_json["admin_session"]["admin_session_id"] == "admin-session-1"
            && event.metadata_json["admin_session"]["roles"][0] == "tenant.owner"
            && event.metadata_json["operation"]["tenant_id"] == "tenant-saas"
    }));
}

#[tokio::test]
async fn saas_admin_routes_validate_saml_app_catalog_reference() {
    let mut config = test_helpers::test_config();
    config.realms[0].id = "realm-saas".to_string();
    config.realms[0].issuer = "https://login.customer.example.com".to_string();
    config.realms[0].protocols.saml = SamlProtocolConfig {
        enabled: true,
        sign_assertions: false,
        encrypt_assertions: None,
        max_clock_skew_seconds: 60,
        sign_metadata: false,
        idp_signing_key_pem_path: None,
        idp_encryption_key_pem_path: None,
        service_providers: vec![SamlServiceProviderConfig {
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            slo_url: None,
            name_id_formats: Vec::new(),
            attribute_release_policy: Vec::new(),
            signing_certificates: Vec::new(),
            encryption_certificates: Vec::new(),
            want_assertions_signed: false,
        }],
    };
    let (app, state) = setup_with_config(config).await;
    seed_saas_realm_client(&state).await;

    let unregistered_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            r#"{
                "id":"app-saml-unregistered",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Unregistered SAML",
                "category":"sales",
                "oidc_client_id":null,
                "saml_entity_id":"https://unregistered.example.com/metadata",
                "scim_enabled":false,
                "marketplace_connector_id":null
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(unregistered_response.status(), StatusCode::BAD_REQUEST);

    let registered_response = app
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            r#"{
                "id":"app-saml-registered",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Registered SAML",
                "category":"sales",
                "oidc_client_id":null,
                "saml_entity_id":"https://sp.example.com/metadata",
                "scim_enabled":false,
                "marketplace_connector_id":null
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(registered_response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn saas_admin_routes_reject_missing_reason_and_tenant_mismatch() {
    let (app, _) = setup().await;

    let now = qid_core::util::now_seconds();
    let missing_reason = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/custom-domains")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header("x-qid-admin-elevation-expires-at", (now + 60).to_string())
        .header("x-qid-admin-session-id", "admin-session-1")
        .body(Body::from(
            r#"{
                "id":"domain-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "hostname":"login.customer.example.com",
                "certificate_ref":"kms://certificates/customer-login",
                "verified":true
            }"#,
        ))
        .unwrap();
    let missing_reason_response = app.clone().oneshot(missing_reason).await.unwrap();
    assert_eq!(missing_reason_response.status(), StatusCode::BAD_REQUEST);

    let tenant_mismatch_response = app
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/custom-domains",
            r#"{
                "id":"domain-1",
                "tenant_id":"tenant-b",
                "realm_id":"realm-saas",
                "hostname":"login.customer.example.com",
                "certificate_ref":"kms://certificates/customer-login",
                "verified":true
            }"#,
        ))
        .await
        .unwrap();
    assert_eq!(tenant_mismatch_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn saas_admin_routes_reject_missing_step_up_and_wrong_role() {
    let (app, _) = setup().await;

    let missing_step_up = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "app.admin")
        .body(Body::from(
            r#"{
                "id":"app-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Customer CRM",
                "category":"sales",
                "oidc_client_id":"crm-client",
                "saml_entity_id":null,
                "scim_enabled":true,
                "marketplace_connector_id":null
            }"#,
        ))
        .unwrap();
    let missing_step_up_response = app.clone().oneshot(missing_step_up).await.unwrap();
    assert_eq!(missing_step_up_response.status(), StatusCode::UNAUTHORIZED);

    let wrong_role = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "auditor")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .body(Body::from(
            r#"{
                "id":"app-1",
                "tenant_id":"tenant-saas",
                "realm_id":"realm-saas",
                "display_name":"Customer CRM",
                "category":"sales",
                "oidc_client_id":"crm-client",
                "saml_entity_id":null,
                "scim_enabled":true,
                "marketplace_connector_id":null
            }"#,
        ))
        .unwrap();
    let wrong_role_response = app.oneshot(wrong_role).await.unwrap();
    assert_eq!(wrong_role_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn saas_admin_routes_reject_expired_or_overlong_elevation() {
    let (app, _) = setup().await;
    let body = r#"{
        "id":"app-1",
        "tenant_id":"tenant-saas",
        "realm_id":"realm-saas",
        "display_name":"Customer CRM",
        "category":"sales",
        "oidc_client_id":"crm-client",
        "saml_entity_id":null,
        "scim_enabled":false,
        "marketplace_connector_id":null
    }"#;

    let expired = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "app.admin")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() - 1).to_string(),
        )
        .body(Body::from(body))
        .unwrap();
    let expired_response = app.clone().oneshot(expired).await.unwrap();
    assert_eq!(expired_response.status(), StatusCode::UNAUTHORIZED);

    let overlong = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "app.admin")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 3600).to_string(),
        )
        .body(Body::from(body))
        .unwrap();
    let overlong_response = app.oneshot(overlong).await.unwrap();
    assert_eq!(overlong_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn saas_admin_routes_enforce_approval_when_configured() {
    let mut config = test_helpers::test_config();
    config.admin.security.require_approval = true;
    config.admin.security.max_approval_age_seconds = 120;
    let (app, state) = setup_with_config(config).await;
    seed_saas_realm_client(&state).await;
    let body = r#"{
        "id":"app-approval",
        "tenant_id":"tenant-saas",
        "realm_id":"realm-saas",
        "display_name":"Approved CRM",
        "category":"sales",
        "oidc_client_id":"crm-client",
        "saml_entity_id":null,
        "scim_enabled":false,
        "marketplace_connector_id":null
    }"#;

    let missing_approval_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            body,
        ))
        .await
        .unwrap();
    assert_eq!(missing_approval_response.status(), StatusCode::UNAUTHORIZED);

    let approved_response = app
        .clone()
        .oneshot(approval_json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            body,
        ))
        .await
        .unwrap();
    assert_eq!(approved_response.status(), StatusCode::CREATED);
    assert!(
        state
            .repo
            .get_admin_approval("approval-123")
            .await
            .unwrap()
            .unwrap()
            .consumed
    );

    let second_body = r#"{
        "id":"app-approval-reuse",
        "tenant_id":"tenant-saas",
        "realm_id":"realm-saas",
        "display_name":"Approval Reuse",
        "category":"sales",
        "oidc_client_id":"crm-client",
        "saml_entity_id":null,
        "scim_enabled":false,
        "marketplace_connector_id":null
    }"#;
    let reused_approval_response = app
        .clone()
        .oneshot(approval_json_request(
            Method::POST,
            "/admin/api/v1/tenants/tenant-saas/app-catalog",
            second_body,
        ))
        .await
        .unwrap();
    assert_eq!(reused_approval_response.status(), StatusCode::UNAUTHORIZED);

    let audit = state.repo.list_audit_events(None, 10).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|event| { event.metadata_json["operation"]["display_name"] == "Approved CRM" })
    );
}

#[tokio::test]
async fn saas_admin_routes_reject_self_or_stale_approval() {
    let mut config = test_helpers::test_config();
    config.admin.security.require_approval = true;
    config.admin.security.max_approval_age_seconds = 60;
    let (app, _) = setup_with_config(config).await;
    let body = r#"{
        "id":"app-approval",
        "tenant_id":"tenant-saas",
        "realm_id":"realm-saas",
        "display_name":"Approved CRM",
        "category":"sales",
        "oidc_client_id":"crm-client",
        "saml_entity_id":null,
        "scim_enabled":true,
        "marketplace_connector_id":null
    }"#;

    let self_approval = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-approval-id", "approval-self")
        .header("x-qid-admin-approver", "admin@example.com")
        .header(
            "x-qid-admin-approved-at",
            (qid_core::util::now_seconds() - 30).to_string(),
        )
        .body(Body::from(body))
        .unwrap();
    let self_approval_response = app.clone().oneshot(self_approval).await.unwrap();
    assert_eq!(self_approval_response.status(), StatusCode::UNAUTHORIZED);

    let stale_approval = Request::builder()
        .method(Method::POST)
        .uri("/admin/api/v1/tenants/tenant-saas/app-catalog")
        .header("Content-Type", "application/json")
        .header("x-qid-admin-reason", "ticket-123")
        .header("x-qid-admin-actor", "admin@example.com")
        .header("x-qid-admin-roles", "tenant.owner")
        .header("x-qid-admin-acr", "urn:qid:acr:phishing-resistant")
        .header("x-qid-admin-amr", "pwd,hwk")
        .header(
            "x-qid-admin-elevation-expires-at",
            (qid_core::util::now_seconds() + 60).to_string(),
        )
        .header("x-qid-admin-approval-id", "approval-stale")
        .header("x-qid-admin-approver", "approver@example.com")
        .header(
            "x-qid-admin-approved-at",
            (qid_core::util::now_seconds() - 120).to_string(),
        )
        .body(Body::from(body))
        .unwrap();
    let stale_approval_response = app.oneshot(stale_approval).await.unwrap();
    assert_eq!(stale_approval_response.status(), StatusCode::UNAUTHORIZED);
}
