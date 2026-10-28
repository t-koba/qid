//! Route contract for realm-bound SCIM auxiliary deletes.
//!
//! The handlers pass the authenticated `ScimRequestContext` realm into
//! storage and map a missing or wrong-owner delete to 404.

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use qid_core::{state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

fn scim_test_config() -> qid_core::config::QidConfig {
    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    config.realms[0].protocols.scim.cursor_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    config.realms[0].protocols.scim.event_callback_allowed_hosts =
        vec!["events.example.com".into()];
    let mut other = config.realms[0].clone();
    other.id = "other".into();
    config.realms.push(other);
    config
}

fn test_app(repo: Arc<FileRepository>) -> Router {
    let config = scim_test_config();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    qid_scim::scim_routes().with_state(state)
}

async fn delete_request(app: &Router, path: &str, realm: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method(Method::DELETE).uri(path);
    if let Some(realm) = realm {
        builder = builder.extension(qid_scim::ScimRequestContext {
            realm_id: realm.into(),
        });
    }
    let request = builder.body(Body::empty()).unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

fn device(id: &str, realm: &str) -> ScimDeviceRecord {
    ScimDeviceRecord {
        id: id.into(),
        realm_id: realm.into(),
        display_name: Some("phone".into()),
        manufacturer: None,
        model: None,
        os: None,
        os_version: None,
        last_seen: None,
    }
}

fn subscription(id: &str, realm: &str) -> ScimEventSubscriptionRecord {
    ScimEventSubscriptionRecord {
        id: id.into(),
        realm_id: realm.into(),
        callback_url: "https://events.example.com/hook".into(),
        event_types: vec!["user.created".into()],
        enabled: true,
        created_at: 1_000,
    }
}

#[tokio::test]
async fn scim_aux_deletes_enforce_realm() {
    let dir = std::env::temp_dir().join(format!("qid-scim-aux-{}", ulid::Ulid::new()));
    let path = dir.join("store.json");
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let app = test_app(repo.clone());

    // Devices: wrong realm is 404 and preserves, correct realm is 204.
    repo.upsert_scim_device(&device("route-device", "corp"))
        .await
        .unwrap();
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/route-device", Some("other")).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        repo.get_scim_device("route-device")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/route-device", Some("corp")).await,
        StatusCode::NO_CONTENT
    );
    assert!(
        repo.get_scim_device("route-device")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/route-device", Some("corp")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/missing", Some("corp")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/missing", None).await,
        StatusCode::NOT_FOUND
    );
    repo.upsert_scim_device(&device("route-device-open", "other"))
        .await
        .unwrap();
    assert_eq!(
        delete_request(&app, "/scim/v2/Devices/route-device-open", None).await,
        StatusCode::NO_CONTENT
    );

    // Subscriptions: same 404/204 semantics.
    repo.upsert_scim_event_subscription(&subscription("route-sub", "corp"))
        .await
        .unwrap();
    assert_eq!(
        delete_request(&app, "/scim/v2/EventSubscriptions/route-sub", Some("other")).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        repo.get_scim_event_subscription("route-sub")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/EventSubscriptions/route-sub", Some("corp")).await,
        StatusCode::NO_CONTENT
    );
    assert!(
        repo.get_scim_event_subscription("route-sub")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/EventSubscriptions/route-sub", Some("corp")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete_request(&app, "/scim/v2/EventSubscriptions/missing", Some("corp")).await,
        StatusCode::NOT_FOUND
    );
    repo.upsert_scim_event_subscription(&subscription("route-sub-open", "other"))
        .await
        .unwrap();
    assert_eq!(
        delete_request(&app, "/scim/v2/EventSubscriptions/route-sub-open", None).await,
        StatusCode::NO_CONTENT
    );

    drop(app);
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
