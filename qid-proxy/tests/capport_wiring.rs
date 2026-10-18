use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{config::ServerPaths, state::SharedState};
use qid_proxy::{capport_routes_enabled, captive_portal_routes};
use qid_storage::FileRepository;
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
