use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    config::{PepCapabilityConfig, PepRegistrationConfig, ServerPaths},
    jwt::{Audience, JwtClaims, Signer},
    models::Session,
    state::SharedState,
    util::now_seconds,
};
use qid_proxy::{
    capport_routes_enabled,
    captive_portal::{get_binding, remove_binding},
    captive_portal_routes,
};
use qid_storage::{FileRepository, SessionRepository};
use std::sync::Arc;
use tower::ServiceExt;

fn config_with_capport(realms: &[(&str, bool)]) -> qid_core::config::QidConfig {
    let mut config = qid_core::test_helpers::test_config();
    let template = config.realms[0].clone();
    config.realms = realms
        .iter()
        .map(|(id, capport)| {
            let mut realm = template.clone();
            realm.id = (*id).to_string();
            realm.issuer = format!(
                "{}/realms/{}",
                config.server.public_base_url.trim_end_matches('/'),
                realm.id
            );
            realm.protocols.network_aaa.capport = *capport;
            realm
        })
        .collect();
    config
}

#[test]
fn capport_routes_stay_off_by_default() {
    let config = qid_core::test_helpers::test_config();
    assert!(!config.realms[0].protocols.network_aaa.capport);
    assert!(!capport_routes_enabled(&config));
}

#[test]
fn capport_routes_enable_when_any_realm_opts_in() {
    let off = config_with_capport(&[("a", false), ("b", false)]);
    assert!(!capport_routes_enabled(&off));

    let one_on = config_with_capport(&[("a", false), ("b", true)]);
    assert!(capport_routes_enabled(&one_on));

    let all_on = config_with_capport(&[("a", true)]);
    assert!(capport_routes_enabled(&all_on));
}

#[test]
fn captive_portal_routes_accept_default_and_custom_details_paths() {
    let default_paths = ServerPaths::default();
    assert_eq!(
        default_paths.capport_details,
        "/api/v1/:realm/captive-portal/api/v1/details"
    );
    let _default_router = captive_portal_routes::<FileRepository>(&default_paths);

    let custom_paths = ServerPaths {
        capport_details: "/capport/:realm/status".to_string(),
        ..ServerPaths::default()
    };
    let _custom_router = captive_portal_routes::<FileRepository>(&custom_paths);
}

#[tokio::test]
async fn capport_details_rejects_disabled_realms_on_default_and_custom_paths() {
    for route in [
        "/api/v1/:realm/captive-portal/api/v1/details",
        "/capport/:realm/status",
    ] {
        let mut config = config_with_capport(&[("disabled", false), ("enabled", true)]);
        config.server.paths.capport_details = route.to_string();
        config.validate().expect("valid CAPPORT test config");

        let path =
            std::env::temp_dir().join(format!("qid-capport-isolation-{}.json", ulid::Ulid::new()));
        let repo = Arc::new(
            FileRepository::new(path.to_str().expect("valid temp path"))
                .await
                .expect("file repository"),
        );
        repo.migrate().await.expect("file repository migration");
        let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
            "capport-test",
            b"capport realm isolation test key",
        ));
        let state = Arc::new(
            SharedState::new(
                config.clone(),
                Arc::clone(&repo),
                signer,
                serde_json::json!({}),
            )
            .expect("shared state"),
        );
        let app = captive_portal_routes::<FileRepository>(&config.server.paths)
            .with_state(Arc::clone(&state));

        for (realm, expected) in [
            ("disabled", StatusCode::NOT_FOUND),
            ("enabled", StatusCode::OK),
        ] {
            let uri = route.replace(":realm", realm);
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("GET request"),
                )
                .await
                .expect("CAPPORT response");
            assert_eq!(response.status(), expected, "realm {realm} at {route}");
        }

        drop(app);
        drop(state);
        drop(repo);
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn capport_deployment_docs_disclose_process_local_bindings() {
    for document in [
        include_str!("../../docs/operations.md"),
        include_str!("../../docs/http-api.md"),
        include_str!("../../config/usecases/09-network-access/captive-portal-oidc-bridge.yaml"),
    ] {
        let normalized = document.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains("process-local"));
        assert!(normalized.contains("not shared across qidd instances"));
    }
}

// Keep process-local bindings and repository files isolated, including on assertion failure.
struct CapportBindCleanup {
    path: std::path::PathBuf,
    realm: String,
    src_ips: Vec<String>,
}

impl Drop for CapportBindCleanup {
    fn drop(&mut self) {
        for src_ip in &self.src_ips {
            remove_binding(&self.realm, src_ip);
        }
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("tmp"));
    }
}

fn capport_session(realm: &str, now: u64) -> Session {
    Session {
        id: ulid::Ulid::new().to_string(),
        realm_id: realm.to_string(),
        user_id: ulid::Ulid::new().to_string(),
        auth_time: now,
        acr: None,
        amr: Vec::new(),
        idle_expires_at: now + 600,
        absolute_expires_at: now + 1200,
        revoked: false,
        created_at: now,
        cnf: None,
    }
}

#[allow(clippy::expect_used)] // Request construction or service failure must fail the test.
async fn bind_capport_session(
    app: &axum::Router,
    token: &str,
    realm: &str,
    src_ip: &str,
    session: &Session,
) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/{realm}/captive-portal/bind"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "src_ip": src_ip,
                        "session_id": session.id,
                        "ttl_seconds": 300,
                    })
                    .to_string(),
                ))
                .expect("bind request"),
        )
        .await
        .expect("bind response")
        .status()
}

#[tokio::test]
async fn capport_bind_validates_sessions_before_creating_or_replacing_bindings() {
    const AUDIENCE: &str = "urn:qid:test:capport";
    let unique = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let realm = format!("capport-{unique}");
    let other_realm = format!("other-{unique}");
    let cleanup = CapportBindCleanup {
        path: std::env::temp_dir().join(format!("qid-capport-bind-{unique}.json")),
        realm: realm.clone(),
        src_ips: [1, 2, 10, 11, 12, 13, 20, 21]
            .map(|last| format!("198.51.100.{last}"))
            .to_vec(),
    };
    let mut config = config_with_capport(&[(&realm, true), (&other_realm, true)]);
    for realm_config in &mut config.realms {
        realm_config.pep_registrations.enabled = true;
        realm_config.pep_registrations.registrations = vec![PepRegistrationConfig {
            name: "capport-pep".to_string(),
            audience: Some(format!("{AUDIENCE}:{}", realm_config.id)),
            capabilities: vec![PepCapabilityConfig {
                effect: "captive_portal".to_string(),
            }],
            assertion: Default::default(),
            decision: Default::default(),
            auth: Default::default(),
        }];
    }
    config.validate().expect("valid CAPPORT bind config");
    let repo = Arc::new(
        FileRepository::new(cleanup.path.to_str().expect("valid temp path"))
            .await
            .expect("file repository"),
    );
    repo.migrate().await.expect("file repository migration");
    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "capport-bind-test",
        b"capport bind regression test key",
    ));
    let now = now_seconds();
    let token = signer
        .sign(&JwtClaims {
            iss: None,
            sub: Some("capport-pep".to_string()),
            aud: Some(Audience::single(format!("{AUDIENCE}:{realm}"))),
            exp: Some((now + 300) as usize),
            nbf: None,
            iat: Some(now as usize),
            jti: None,
            extra: [("realm_id".to_string(), serde_json::json!(realm))].into(),
        })
        .expect("adapter token");
    let state = Arc::new(
        SharedState::new(
            config.clone(),
            Arc::clone(&repo),
            signer,
            serde_json::json!({}),
        )
        .expect("shared state"),
    );
    let app = captive_portal_routes::<FileRepository>(&config.server.paths)
        .with_state(Arc::clone(&state));
    let active = capport_session(&realm, now);
    repo.create_session(&active).await.expect("active session");

    // The first request exercises the repository path; the second uses its cached result.
    assert!(state.session_cache_get(&active.id).is_none());
    for src_ip in ["198.51.100.1", "198.51.100.2"] {
        assert!(get_binding(&realm, src_ip).is_none());
        assert_eq!(
            bind_capport_session(&app, &token, &realm, src_ip, &active).await,
            StatusCode::OK
        );
        let binding = get_binding(&realm, src_ip).expect("same-realm binding");
        assert_eq!(binding.session_id, active.id);
        assert_eq!(binding.user_id, active.user_id);
        assert!(state.session_cache_get(&active.id).is_some());
    }

    let foreign = capport_session(&other_realm, now);
    let mut revoked = capport_session(&realm, now);
    revoked.revoked = true;
    let mut idle_expired = capport_session(&realm, now);
    idle_expired.idle_expires_at = now - 60;
    let mut absolute_expired = capport_session(&realm, now);
    absolute_expired.absolute_expires_at = now - 60;
    for (label, session, src_ip) in [
        ("foreign realm", foreign, "198.51.100.10"),
        ("revoked", revoked, "198.51.100.11"),
        ("idle expired", idle_expired, "198.51.100.12"),
        ("absolute expired", absolute_expired, "198.51.100.13"),
    ] {
        repo.create_session(&session)
            .await
            .expect("invalid session");
        assert!(state.session_cache_get(&session.id).is_none(), "{label}");
        assert!(get_binding(&realm, src_ip).is_none(), "{label}");
        assert!(
            !bind_capport_session(&app, &token, &realm, src_ip, &session)
                .await
                .is_success(),
            "{label} must not create a binding"
        );
        assert!(get_binding(&realm, src_ip).is_none(), "{label}");

        // Active foreign sessions are cached by the repo path even though binding is denied.
        // Exercise that warm-cache rejection too; inactive sessions remain cold.
        assert_eq!(
            state.session_cache_get(&session.id).is_some(),
            label == "foreign realm"
        );
        assert!(
            !bind_capport_session(&app, &token, &realm, "198.51.100.1", &session)
                .await
                .is_success(),
            "{label} must not replace a binding"
        );
        let binding = get_binding(&realm, "198.51.100.1").expect("original binding preserved");
        assert_eq!(binding.session_id, active.id, "{label}");
        assert_eq!(binding.user_id, active.user_id, "{label}");
    }

    // Revoke a previously cached active session through the production route, not a
    // repository-only mutation: revocation must evict the cache before the next bind.
    let warmed = capport_session(&realm, now);
    repo.create_session(&warmed)
        .await
        .expect("session to revoke");
    assert!(state.session_cache_get(&warmed.id).is_none());
    assert_eq!(
        bind_capport_session(&app, &token, &realm, "198.51.100.20", &warmed).await,
        StatusCode::OK
    );
    assert!(state.session_cache_get(&warmed.id).is_some());
    let revoke_app = qid_session::api::auth_routes::<FileRepository>(&config.server.paths)
        .with_state(Arc::clone(&state));
    let response = revoke_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(
                    config
                        .server
                        .paths
                        .auth_session_revoke
                        .replace(":realm", &realm),
                )
                .header(
                    "cookie",
                    format!(
                        "{}={}",
                        config.realms[0].sessions.browser.cookie_name, warmed.id
                    ),
                )
                .body(Body::empty())
                .expect("revoke request"),
        )
        .await
        .expect("revoke response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(repo.get_session(&warmed.id).await.unwrap().unwrap().revoked);
    assert!(state.session_cache_get(&warmed.id).is_none());
    assert!(get_binding(&realm, "198.51.100.21").is_none());
    for src_ip in ["198.51.100.21", "198.51.100.1"] {
        assert!(
            !bind_capport_session(&app, &token, &realm, src_ip, &warmed)
                .await
                .is_success()
        );
    }
    assert!(get_binding(&realm, "198.51.100.21").is_none());
    let binding = get_binding(&realm, "198.51.100.1").expect("original binding after revocation");
    assert_eq!(binding.session_id, active.id);
    assert_eq!(binding.user_id, active.user_id);
}
