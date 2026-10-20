use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{ETAG, IF_MATCH},
    },
};
use http_body_util::BodyExt;
use qid_core::models::{AccessToken, Session, User};
use qid_core::{state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::prelude::*;
use qid_storage::{FileRepository, SqlRepository};
use std::sync::Arc;
use tower::ServiceExt;

const ENTERPRISE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const CORE_DEVICE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Device";
const DEVICE_EXTENSION_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:device:2.0:Device";
const EVENT_SUBSCRIPTION_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:EventSubscription";

async fn setup() -> Router {
    setup_with_store().await.0
}

async fn setup_with_store() -> (Router, Arc<FileRepository>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("qid-scim-{}", ulid::Ulid::new()));
    let path = dir.join("store.json");
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    (test_app(repo.clone()), repo, path)
}

fn custom_schema(
    id: &str,
    name: &str,
    attribute: &str,
) -> qid_core::config::CustomScimSchemaConfig {
    qid_core::config::CustomScimSchemaConfig {
        id: id.to_string(),
        name: name.to_string(),
        description: format!("{name} description"),
        attributes: vec![qid_core::config::CustomScimAttributeConfig {
            name: attribute.to_string(),
            r#type: "string".to_string(),
            multi_valued: false,
            required: false,
            case_exact: false,
            mutability: "readWrite".to_string(),
            returned: "default".to_string(),
        }],
    }
}

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

fn scim_test_state<R: Repository>(repo: Arc<R>) -> Arc<SharedState<R>> {
    let config = scim_test_config();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap())
}

fn test_app<R: Repository>(repo: Arc<R>) -> Router {
    qid_scim::scim_routes().with_state(scim_test_state(repo))
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn scim_user_can_be_created_read_patched_and_deleted() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-1","userName":"alice@example.com","name":{"givenName":"Alice"},"emails":[{"value":"alice@example.com"}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Engineering","employeeNumber":"E123"},"active":true}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap();
    let created_version = created["meta"]["version"].as_str().unwrap().to_string();
    assert!(
        created["schemas"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String(
                ENTERPRISE_USER_SCHEMA.to_string()
            ))
    );
    assert_eq!(created[ENTERPRISE_USER_SCHEMA]["department"], "Engineering");

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_etag = get_response.headers().get(ETAG).unwrap().to_str().unwrap();
    assert_eq!(get_etag, created_version);

    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, created_version.as_str())
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"userName","value":"alice2@example.com"},{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Platform"}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched["userName"], "alice2@example.com");
    assert_eq!(patched["active"], false);
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["employeeNumber"], "E123");
    let patched_version = patched["meta"]["version"].as_str().unwrap();
    assert_ne!(patched_version, created_version);

    let stale_patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, created_version)
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"active","value":true}]}"#,
        ))
        .unwrap();
    let stale_patch_response = app.clone().oneshot(stale_patch_request).await.unwrap();
    assert_eq!(
        stale_patch_response.status(),
        StatusCode::PRECONDITION_FAILED
    );

    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/scim/v2/Users/{id}"))
        .header(IF_MATCH, patched_version)
        .body(Body::empty())
        .unwrap();
    let delete_response = app.clone().oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let soft_deleted_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let soft_deleted_response = app.clone().oneshot(soft_deleted_request).await.unwrap();
    assert_eq!(soft_deleted_response.status(), StatusCode::OK);
    let soft_deleted = response_json(soft_deleted_response).await;
    assert_eq!(soft_deleted["active"], false);
    let soft_deleted_version = soft_deleted["meta"]["version"].as_str().unwrap();

    let hard_delete_request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/scim/v2/Users/{id}?hard_delete=true"))
        .header(IF_MATCH, soft_deleted_version)
        .body(Body::empty())
        .unwrap();
    let hard_delete_response = app.clone().oneshot(hard_delete_request).await.unwrap();
    assert_eq!(hard_delete_response.status(), StatusCode::NO_CONTENT);

    let missing_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let missing_response = app.oneshot(missing_request).await.unwrap();
    assert_eq!(missing_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scim_users_support_external_id_filter_and_pagination() {
    let app = setup().await;
    for i in 0..3 {
        let create_request = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/Users")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"realm":"corp","externalId":"hr-{i}","userName":"user{i}@example.com","active":{},"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{{"department":"{}","employeeNumber":"E{i}"}}}}"#,
                if i == 2 { "false" } else { "true" },
                if i == 1 { "Engineering" } else { "Operations" }
            )))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
    }

    let filter_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=externalId%20eq%20%22hr-1%22")
        .body(Body::empty())
        .unwrap();
    let filter_response = app.clone().oneshot(filter_request).await.unwrap();
    assert_eq!(filter_response.status(), StatusCode::OK);
    let filtered = response_json(filter_response).await;
    assert_eq!(filtered["totalResults"], 1);
    assert_eq!(filtered["Resources"][0]["externalId"], "hr-1");

    let user_name_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=userName%20eq%20%22user0%40example.com%22")
        .body(Body::empty())
        .unwrap();
    let user_name_response = app.clone().oneshot(user_name_request).await.unwrap();
    assert_eq!(user_name_response.status(), StatusCode::OK);
    let user_name_filtered = response_json(user_name_response).await;
    assert_eq!(user_name_filtered["totalResults"], 1);
    assert_eq!(
        user_name_filtered["Resources"][0]["userName"],
        "user0@example.com"
    );

    let active_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=active%20eq%20false")
        .body(Body::empty())
        .unwrap();
    let active_response = app.clone().oneshot(active_request).await.unwrap();
    assert_eq!(active_response.status(), StatusCode::OK);
    let active_filtered = response_json(active_response).await;
    assert_eq!(active_filtered["totalResults"], 1);
    assert_eq!(active_filtered["Resources"][0]["active"], false);
    assert_eq!(active_filtered["Resources"][0]["externalId"], "hr-2");

    let enterprise_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Aextension%3Aenterprise%3A2.0%3AUser%3Adepartment%20eq%20%22Engineering%22")
        .body(Body::empty())
        .unwrap();
    let enterprise_response = app.clone().oneshot(enterprise_request).await.unwrap();
    assert_eq!(enterprise_response.status(), StatusCode::OK);
    let enterprise_filtered = response_json(enterprise_response).await;
    assert_eq!(enterprise_filtered["totalResults"], 1);
    assert_eq!(enterprise_filtered["Resources"][0]["externalId"], "hr-1");

    let short_enterprise_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=enterprise.department%20eq%20%22Operations%22")
        .body(Body::empty())
        .unwrap();
    let short_enterprise_response = app.clone().oneshot(short_enterprise_request).await.unwrap();
    assert_eq!(short_enterprise_response.status(), StatusCode::OK);
    let short_enterprise_filtered = response_json(short_enterprise_response).await;
    assert_eq!(short_enterprise_filtered["totalResults"], 2);

    let page_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&start_index=2&count=1")
        .body(Body::empty())
        .unwrap();
    let page_response = app.clone().oneshot(page_request).await.unwrap();
    assert_eq!(page_response.status(), StatusCode::OK);
    let page = response_json(page_response).await;
    assert_eq!(page["totalResults"], 3);
    assert_eq!(page["startIndex"], 2);
    assert_eq!(page["itemsPerPage"], 1);
    assert_eq!(page["Resources"].as_array().unwrap().len(), 1);

    let unsupported_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=title%20eq%20%22Manager%22")
        .body(Body::empty())
        .unwrap();
    let unsupported_response = app.oneshot(unsupported_request).await.unwrap();
    assert_eq!(unsupported_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn scim_pagination_extreme_start_index_is_safe_for_users_and_groups() {
    let app = setup().await;
    for resource in ["Users", "Groups"] {
        let uri = format!(
            "/scim/v2/{resource}?realm=corp&start_index={}&count=200",
            usize::MAX
        );
        let page = get_json(&app, &uri, None).await;
        assert_eq!(page["startIndex"], serde_json::json!(usize::MAX));
        assert_eq!(page["itemsPerPage"], 0);
        assert!(page.get("nextCursor").is_none());
    }
}

#[tokio::test]
async fn scim_group_can_be_created_patched_filtered_and_deleted() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Groups")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","displayName":"engineering","members":[{"value":"user-1"}]}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap();
    let created_version = created["meta"]["version"].as_str().unwrap().to_string();

    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Groups/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, created_version.as_str())
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"displayName","value":"platform"},{"op":"replace","path":"members","value":[{"value":"user-2"}]}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched["displayName"], "platform");
    assert_eq!(patched["members"][0]["value"], "user-2");
    assert_ne!(patched["meta"]["version"], created_version);

    let list_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Groups?realm=corp&filter=displayName%20eq%20%22platform%22")
        .body(Body::empty())
        .unwrap();
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let listed = response_json(list_response).await;
    assert_eq!(listed["totalResults"], 1);

    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/scim/v2/Groups/{id}"))
        .body(Body::empty())
        .unwrap();
    let delete_response = app.oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn scim_group_patch_add_members_appends_instead_of_replacing() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Groups")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","displayName":"append-group","members":[{"value":"user-1"}]}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap();
    let version = created["meta"]["version"].as_str().unwrap();

    // Direct PATCH add must keep the existing member.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Groups/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, version)
        .body(Body::from(
            r#"{"Operations":[{"op":"add","path":"members","value":[{"value":"user-2"}]}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    let members: Vec<&str> = patched["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["value"].as_str().unwrap())
        .collect();
    assert_eq!(members, vec!["user-1", "user-2"]);

    // Bulk PATCH shares the helper and must append as well.
    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"PATCH","path":"/Groups/{id}","data":{{"Operations":[{{"op":"add","path":"members","value":[{{"value":"user-3"}}]}}]}}}}]}}"#
        )))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "200");
    let members: Vec<&str> = bulk["Operations"][0]["response"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["value"].as_str().unwrap())
        .collect();
    assert_eq!(members, vec!["user-1", "user-2", "user-3"]);
}

#[tokio::test]
async fn scim_bulk_dispatches_create_and_delete_operations() {
    let app = setup().await;
    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"failOnErrors":1,"Operations":[{"method":"POST","path":"/Users","bulkId":"u1","data":{"realm":"corp","userName":"bulk@example.com"}},{"method":"POST","path":"/Groups","bulkId":"g1","data":{"realm":"corp","displayName":"bulk-group"}}]}"#,
        ))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "201");
    assert_eq!(bulk["Operations"][1]["status"], "201");

    let group_location = bulk["Operations"][1]["location"].as_str().unwrap();
    let delete_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"DELETE","path":"{}"}}]}}"#,
            group_location.trim_start_matches("/scim/v2")
        )))
        .unwrap();
    let delete_response = app.oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
    let deleted = response_json(delete_response).await;
    assert_eq!(deleted["Operations"][0]["status"], "204");
}

#[tokio::test]
async fn scim_bulk_stops_after_server_error_at_threshold() {
    let (app, _repo, store_path) = setup_with_store().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Groups")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","displayName":"fail-stop-group"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Inject a repository failure: replace the store file with a directory so
    // the atomic temp-to-store rename on the next persisted write fails with
    // a server error on every platform.
    std::fs::remove_file(&store_path).unwrap();
    std::fs::create_dir(&store_path).unwrap();

    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"failOnErrors":1,"Operations":[{{"method":"PATCH","path":"/Groups/{id}","data":{{"Operations":[{{"op":"replace","path":"displayName","value":"mutated"}}]}}}},{{"method":"POST","path":"/Groups","data":{{"realm":"corp","displayName":"must-not-run"}}}}]}}"#
        )))
        .unwrap();
    let bulk_response = app.oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "500");
    // The server failure counts toward failOnErrors, so the later mutation
    // must not run.
    assert_eq!(bulk["Operations"].as_array().unwrap().len(), 1);

    std::fs::remove_dir(&store_path).unwrap();
    let _ = std::fs::remove_file(store_path.with_extension("tmp"));
}

#[tokio::test]
async fn scim_lifecycle_mutations_do_not_touch_login_records() {
    let (app, repo, _store_path) = setup_with_store().await;
    // A SCIM-provisioned user and a login identity sharing the same name.
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"leaver@example.com"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let scim_id = created["id"].as_str().unwrap().to_string();

    repo.create_user(&User {
        id: "login-user-1".to_string(),
        realm_id: "corp".to_string(),
        email: Some("leaver@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    repo.create_session(&Session {
        id: "session-1".to_string(),
        realm_id: "corp".to_string(),
        user_id: "login-user-1".to_string(),
        auth_time: 1_700_000_000,
        acr: None,
        amr: vec![],
        idle_expires_at: 1_800_000_000,
        absolute_expires_at: 1_800_000_000,
        revoked: false,
        created_at: 1_700_000_000,
        cnf: None,
    })
    .await
    .unwrap();
    repo.create_access_token(&AccessToken {
        jti: "token-1".to_string(),
        family_id: None,
        user_id: "login-user-1".to_string(),
        client_id: "client-1".to_string(),
        realm_id: "corp".to_string(),
        scopes: vec!["openid".to_string()],
        audience: vec![],
        resource: vec![],
        authorization_details: None,
        cnf: None,
        auth_time: None,
        acr: None,
        amr: vec![],
        nonce: None,
        sender_constraint: None,
        token_format: Default::default(),
        expires_at: 1_800_000_000,
        revoked: false,
        issued_at: 1_700_000_000,
    })
    .await
    .unwrap();

    // Deactivate via SCIM PATCH, then delete the SCIM user.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{scim_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"active","value":false}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/scim/v2/Users/{scim_id}"))
        .body(Body::empty())
        .unwrap();
    let delete_response = app.clone().oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    // The SCIM registry reflects the lifecycle change (DELETE is a soft
    // delete that deactivates but retains the record) ...
    let scim_user = repo.get_scim_user(&scim_id).await.unwrap().unwrap();
    assert!(!scim_user.active);
    // ... while the login identity, session, and token are untouched:
    // inbound SCIM is an isolated provisioning registry with no login
    // binding, not an implicit session/token revocation authority.
    assert!(repo.get_user_by_id("login-user-1").await.unwrap().is_some());
    let session = repo.get_session("session-1").await.unwrap().unwrap();
    assert!(!session.revoked);
    let token = repo.get_access_token("token-1").await.unwrap().unwrap();
    assert!(!token.revoked);
}

#[tokio::test]
async fn scim_bulk_supports_patch_soft_delete_and_unlimited_failures() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"method":"POST","path":"/Users","bulkId":"u1","data":{"realm":"corp","externalId":"bulk-soft","userName":"bulk-soft@example.com","active":true}},{"method":"POST","path":"/Groups","bulkId":"g1","data":{"realm":"corp","displayName":"bulk-soft-group","members":[]}}]}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let created = response_json(create_response).await;
    let user_location = created["Operations"][0]["location"].as_str().unwrap();
    let group_location = created["Operations"][1]["location"].as_str().unwrap();
    let user_id = user_location.trim_start_matches("/scim/v2/Users/");
    let group_id = group_location.trim_start_matches("/scim/v2/Groups/");

    let patch_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"failOnErrors":0,"Operations":[{{"method":"PATCH","path":"/Users/{user_id}","data":{{"Operations":[{{"op":"replace","path":"userName","value":"patched@example.com"}},{{"op":"replace","path":"active","value":false}}]}}}},{{"method":"PATCH","path":"/Groups/{group_id}","data":{{"Operations":[{{"op":"replace","path":"displayName","value":"patched-group"}}]}}}},{{"method":"PATCH","path":"/Users/missing","bulkId":"missing","data":{{"Operations":[{{"op":"replace","path":"active","value":false}}]}}}},{{"method":"POST","path":"/Groups","bulkId":"after-failure","data":{{"realm":"corp","displayName":"after-failure"}}}}]}}"#
        )))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched["Operations"].as_array().unwrap().len(), 4);
    assert_eq!(patched["Operations"][0]["status"], "200");
    assert_eq!(
        patched["Operations"][0]["response"]["userName"],
        "patched@example.com"
    );
    assert_eq!(patched["Operations"][0]["response"]["active"], false);
    assert_eq!(
        patched["Operations"][1]["response"]["displayName"],
        "patched-group"
    );
    assert_eq!(patched["Operations"][2]["status"], "404");
    assert_eq!(patched["Operations"][3]["status"], "201");

    let delete_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"DELETE","path":"/Users/{user_id}"}}]}}"#
        )))
        .unwrap();
    let delete_response = app.clone().oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);

    let get_soft_deleted_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{user_id}"))
        .body(Body::empty())
        .unwrap();
    let get_soft_deleted_response = app.clone().oneshot(get_soft_deleted_request).await.unwrap();
    assert_eq!(get_soft_deleted_response.status(), StatusCode::OK);
    let soft_deleted = response_json(get_soft_deleted_response).await;
    assert_eq!(soft_deleted["active"], false);

    let hard_delete_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"DELETE","path":"/scim/v2/Users/{user_id}?hard_delete=true"}}]}}"#
        )))
        .unwrap();
    let hard_delete_response = app.clone().oneshot(hard_delete_request).await.unwrap();
    assert_eq!(hard_delete_response.status(), StatusCode::OK);

    let get_hard_deleted_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{user_id}"))
        .body(Body::empty())
        .unwrap();
    let get_hard_deleted_response = app.oneshot(get_hard_deleted_request).await.unwrap();
    assert_eq!(get_hard_deleted_response.status(), StatusCode::NOT_FOUND);
}

async fn realm_request(
    app: &Router,
    method: Method,
    path: &str,
    realm: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("/scim/v2/{path}"))
                .header("Content-Type", "application/json")
                // This is the context installed by the authenticated SCIM boundary.
                .extension(qid_scim::ScimRequestContext {
                    realm_id: realm.into(),
                })
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// The advertised wire payload for a stored device or subscription record.
/// The fixture keeps the stored-record shape, so the request body is derived
/// from the names the schema discovery advertises.
fn advertised_body(resource: &str, stored: &serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({"id": stored["id"], "realm": stored["realm_id"]});
    if resource == "Devices" {
        body["displayName"] = stored["display_name"].clone();
        body[DEVICE_EXTENSION_SCHEMA] = serde_json::json!({
            "manufacturer": stored["manufacturer"],
            "model": stored["model"],
            "os": stored["os"],
            "osVersion": stored["os_version"],
            "lastSeen": stored["last_seen"],
        });
    } else {
        body["callback"] = stored["callback_url"].clone();
        body["eventTypes"] = stored["event_types"].clone();
        body["enabled"] = stored["enabled"].clone();
    }
    body
}

async fn stored_resource<R: Repository>(repo: &R, resource: &str) -> serde_json::Value {
    if resource == "Devices" {
        serde_json::to_value(repo.get_scim_device("shared-id").await.unwrap().unwrap()).unwrap()
    } else {
        serde_json::to_value(
            repo.get_scim_event_subscription("shared-id")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
}

async fn assert_realm_upsert_contract<R: Repository>(repo: Arc<R>) {
    for realm in ["corp", "other"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://{realm}.example.com"),
            None,
        )
        .await
        .unwrap();
    }
    let app = test_app(repo.clone());
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/upserts.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let resource = case["resource"].as_str().unwrap();
        let initial = advertised_body(resource, &case["initial"]);
        let mut changed = advertised_body(resource, &case["changed"]);
        let response = realm_request(&app, Method::POST, resource, "corp", initial).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let incumbent = stored_resource(repo.as_ref(), resource).await;
        assert_eq!(incumbent["realm_id"], "corp");
        // A body claiming the incumbent realm must not override the other context.
        changed["realm"] = "corp".into();
        let response = realm_request(&app, Method::POST, resource, "other", changed.clone()).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            response_json(response).await["error"]
                .as_str()
                .unwrap()
                .starts_with("conflict:")
        );
        assert_eq!(stored_resource(repo.as_ref(), resource).await, incumbent);
        let path = format!("{resource}/shared-id");
        let response =
            realm_request(&app, Method::GET, &path, "other", serde_json::Value::Null).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response =
            realm_request(&app, Method::GET, &path, "corp", serde_json::Value::Null).await;
        assert_eq!(response.status(), StatusCode::OK);
        // Same-realm POST remains an intentional update, even with a spoofed body realm.
        changed["realm"] = "other".into();
        let response = realm_request(&app, Method::POST, resource, "corp", changed.clone()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let updated = stored_resource(repo.as_ref(), resource).await;
        assert_ne!(updated, incumbent);
        for (key, value) in case["changed"].as_object().unwrap() {
            if key != "created_at" {
                assert_eq!(&updated[key], value, "{resource}.{key}");
            }
        }
        // An identical same-realm upsert is still successful (not a no-op conflict).
        let response = realm_request(&app, Method::POST, resource, "corp", changed).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
}

#[tokio::test]
async fn file_scim_upserts_preserve_realm_ownership() {
    let (_, repo, path) = setup_with_store().await;
    assert_realm_upsert_contract(repo).await;
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn sql_scim_upserts_preserve_realm_ownership() {
    let path = std::env::temp_dir().join(format!("qid-scim-{}.db", ulid::Ulid::new()));
    let repo = Arc::new(
        SqlRepository::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    assert_realm_upsert_contract(repo).await;
}

async fn get_json(app: &Router, uri: &str, realm: Option<&str>) -> serde_json::Value {
    let response = match realm {
        Some(realm) => {
            realm_request(
                app,
                Method::GET,
                uri.strip_prefix("/scim/v2/").unwrap(),
                realm,
                serde_json::json!({}),
            )
            .await
        }
        None => app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap(),
    };
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

#[tokio::test]
async fn scim_schema_discovery_advertises_only_supported_schemas() {
    let app = setup().await;
    for realm in [Some("corp"), Some("other"), None, Some("unknown")] {
        let schemas = get_json(&app, "/scim/v2/Schemas", realm).await;
        assert_eq!(schemas["totalResults"], 6);
        let ids: Vec<&str> = schemas["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:User"));
        assert!(ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:Group"));
        assert!(ids.contains(&ENTERPRISE_USER_SCHEMA));
        assert!(ids.contains(&CORE_DEVICE_SCHEMA));
        assert!(ids.contains(&DEVICE_EXTENSION_SCHEMA));
        assert!(ids.contains(&EVENT_SUBSCRIPTION_SCHEMA));
        assert!(
            !schemas.to_string().contains("example:"),
            "no custom extension is advertised"
        );
        let types = get_json(&app, "/scim/v2/ResourceTypes", realm).await;
        assert!(types.to_string().contains(ENTERPRISE_USER_SCHEMA));
        assert!(
            !types.to_string().contains("example:"),
            "no custom extension is advertised"
        );
        assert_eq!(
            types["Resources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == "User")
                .unwrap()["schemaExtensions"],
            serde_json::json!([{"schema": ENTERPRISE_USER_SCHEMA, "required": false}])
        );
    }
    let schemas = get_json(&app, "/scim/v2/Schemas", None).await;
    assert!(
        schemas["Resources"].as_array().unwrap().iter().any(|r| {
            r["id"] == ENTERPRISE_USER_SCHEMA
                && r["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["name"] == "department")
        }),
        "built-in enterprise extension stays advertised"
    );
}

#[tokio::test]
async fn scim_resource_types_resolve_in_schemas_with_scoped_subset() {
    let app = setup().await;
    let schemas = get_json(&app, "/scim/v2/Schemas", None).await;
    let by_id = |id: &str| {
        schemas["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("{id} is advertised"))
            .clone()
    };
    let names = |schema: &serde_json::Value| {
        let mut names: Vec<String> = schema["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_string())
            .collect();
        names.sort_unstable();
        names
    };
    let types = get_json(&app, "/scim/v2/ResourceTypes", None).await;
    let resources = types["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 4);
    for resource in resources {
        let schema = resource["schema"].as_str().unwrap();
        assert!(
            by_id(schema)["id"] == schema,
            "ResourceTypes schema {schema} resolves in /Schemas"
        );
        for extension in resource
            .get("schemaExtensions")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let schema = extension["schema"].as_str().unwrap();
            assert!(
                by_id(schema)["id"] == schema,
                "ResourceTypes extension {schema} resolves in /Schemas"
            );
        }
    }
    let device = resources
        .iter()
        .find(|r| r["id"] == "Device")
        .expect("Device resource type is advertised");
    assert_eq!(device["schema"], CORE_DEVICE_SCHEMA);
    assert_eq!(
        device["schemaExtensions"],
        serde_json::json!([{"schema": DEVICE_EXTENSION_SCHEMA, "required": false}])
    );
    let subscription = resources
        .iter()
        .find(|r| r["id"] == "EventSubscription")
        .expect("EventSubscription resource type is advertised");
    assert_eq!(subscription["schema"], EVENT_SUBSCRIPTION_SCHEMA);
    assert!(subscription.get("schemaExtensions").is_none());
    let core_device = by_id(CORE_DEVICE_SCHEMA);
    assert_eq!(names(&core_device), ["displayName".to_string()]);
    assert!(
        core_device["description"]
            .as_str()
            .unwrap()
            .contains("implemented subset"),
        "scoped Device description must not claim full conformance"
    );
    let extension = by_id(DEVICE_EXTENSION_SCHEMA);
    assert_eq!(
        names(&extension),
        [
            "lastSeen".to_string(),
            "manufacturer".to_string(),
            "model".to_string(),
            "os".to_string(),
            "osVersion".to_string()
        ]
    );
    assert!(
        extension["description"]
            .as_str()
            .unwrap()
            .contains("implemented subset"),
        "scoped device extension must not claim full conformance"
    );
    let subscription_schema = by_id(EVENT_SUBSCRIPTION_SCHEMA);
    assert_eq!(
        names(&subscription_schema),
        [
            "callback".to_string(),
            "createdAt".to_string(),
            "enabled".to_string(),
            "eventTypes".to_string()
        ]
    );
    assert!(
        subscription_schema["description"]
            .as_str()
            .unwrap()
            .contains("implemented subset"),
        "scoped subscription description must not claim full conformance"
    );
}

#[tokio::test]
async fn scim_user_schema_discovery_matches_created_and_returned_name_and_emails() {
    let app = setup().await;
    let schemas = get_json(&app, "/scim/v2/Schemas", None).await;
    let user_schema = schemas["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["id"] == CORE_USER_SCHEMA)
        .expect("core User schema is advertised");
    let user_attributes = user_schema["attributes"].as_array().unwrap();
    let discovered = |name: &str| {
        user_attributes
            .iter()
            .find(|attribute| attribute["name"] == name)
            .unwrap_or_else(|| panic!("{name} is advertised"))
    };

    assert_eq!(
        discovered("name"),
        &serde_json::json!({
            "name": "name",
            "type": "complex",
            "multiValued": false,
            "required": false,
            "subAttributes": [
                {"name": "formatted", "type": "string", "multiValued": false, "required": false},
                {"name": "familyName", "type": "string", "multiValued": false, "required": false},
                {"name": "givenName", "type": "string", "multiValued": false, "required": false},
                {"name": "middleName", "type": "string", "multiValued": false, "required": false},
                {"name": "honorificPrefix", "type": "string", "multiValued": false, "required": false},
                {"name": "honorificSuffix", "type": "string", "multiValued": false, "required": false}
            ]
        })
    );
    assert_eq!(
        discovered("emails"),
        &serde_json::json!({
            "name": "emails",
            "type": "complex",
            "multiValued": true,
            "required": false,
            "subAttributes": [
                {"name": "value", "type": "string", "multiValued": false, "required": false},
                {"name": "display", "type": "string", "multiValued": false, "required": false},
                {"name": "type", "type": "string", "multiValued": false, "required": false},
                {"name": "primary", "type": "boolean", "multiValued": false, "required": false}
            ]
        })
    );

    let request = serde_json::json!({
        "realm": "corp",
        "schemas": [CORE_USER_SCHEMA],
        "userName": "schema-discovery@example.com",
        "name": {
            "formatted": "Dr. Ada Lovelace",
            "familyName": "Lovelace",
            "givenName": "Ada",
            "middleName": "Byron",
            "honorificPrefix": "Dr.",
            "honorificSuffix": "III"
        },
        "emails": [
            {"value": "ada@example.com", "display": "Work", "type": "work", "primary": true},
            {"value": "ada.home@example.com", "display": "Home", "type": "home", "primary": false}
        ]
    });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scim/v2/Users")
                .header("Content-Type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    assert_eq!(created["name"], request["name"]);
    assert_eq!(created["emails"], request["emails"]);
}

#[tokio::test]
async fn scim_owned_external_id_is_immutable_and_reconciles_with_directory_sync() {
    let (app, repo, _store_path) = setup_with_store().await;
    const DN: &str = "uid=alice,ou=people,dc=example,dc=com";
    const OWNER: &str = "provider-a";

    // Create an unowned user, then mark it provider-owned like directory sync would.
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"realm":"corp","externalId":"{DN}","userName":"alice@example.com"}}"#,
        )))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert!(created.get("directory_provider_id").is_none());
    assert!(created.get("directoryProviderId").is_none());

    let mut owned = repo.get_scim_user(&id).await.unwrap().unwrap();
    owned.directory_provider_id = Some(OWNER.to_string());
    repo.update_scim_user(&owned).await.unwrap();

    // PUT with a different externalId must fail closed with 409 and change nothing.
    let put_changed = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"uid=eve,ou=people,dc=example,dc=com","userName":"alice@example.com"}"#,
        ))
        .unwrap();
    let put_changed_response = app.clone().oneshot(put_changed).await.unwrap();
    assert_eq!(put_changed_response.status(), StatusCode::CONFLICT);
    let put_changed_body = response_json(put_changed_response).await;
    assert!(
        put_changed_body["error"]
            .as_str()
            .unwrap()
            .starts_with("conflict:"),
        "unexpected error body: {put_changed_body}"
    );
    assert!(
        !put_changed_body["error"].as_str().unwrap().contains(OWNER),
        "internal provider ownership must not be disclosed: {put_changed_body}"
    );

    // PATCH replace/add with a different externalId must fail closed.
    for op in ["add", "replace"] {
        let patch_changed = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/scim/v2/Users/{id}"))
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"Operations":[{{"op":"{op}","path":"externalId","value":"uid=eve,ou=people,dc=example,dc=com"}}]}}"#,
            )))
            .unwrap();
        let patch_response = app.clone().oneshot(patch_changed).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::CONFLICT, "op {op}");
        let patch_body = response_json(patch_response).await;
        assert!(
            patch_body["error"]
                .as_str()
                .unwrap()
                .starts_with("conflict:"),
            "unexpected error body for {op}: {patch_body}"
        );
        assert!(
            !patch_body["error"].as_str().unwrap().contains(OWNER),
            "internal provider ownership must not be disclosed: {patch_body}"
        );
    }

    // PATCH remove must fail closed.
    let patch_remove = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"remove","path":"externalId"}]}"#,
        ))
        .unwrap();
    let patch_remove_response = app.clone().oneshot(patch_remove).await.unwrap();
    assert_eq!(patch_remove_response.status(), StatusCode::CONFLICT);
    let patch_remove_body = response_json(patch_remove_response).await;
    assert!(
        patch_remove_body["error"]
            .as_str()
            .unwrap()
            .starts_with("conflict:")
    );
    assert!(
        !patch_remove_body["error"].as_str().unwrap().contains(OWNER),
        "internal provider ownership must not be disclosed: {patch_remove_body}"
    );

    // Rejections must not mutate the stored row.
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.external_id.as_deref(), Some(DN));
    assert_eq!(stored.directory_provider_id.as_deref(), Some(OWNER));
    assert_eq!(stored.user_name, "alice@example.com");

    // Identical round-trips are allowed and keep the stored DN.
    let put_equal = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"realm":"corp","externalId":"{DN}","userName":"alice@example.com"}}"#,
        )))
        .unwrap();
    let put_equal_response = app.clone().oneshot(put_equal).await.unwrap();
    assert_eq!(put_equal_response.status(), StatusCode::OK);
    let put_equal_body = response_json(put_equal_response).await;
    assert_eq!(put_equal_body["externalId"], DN);
    assert!(put_equal_body.get("directory_provider_id").is_none());
    assert!(put_equal_body.get("directoryProviderId").is_none());

    for op in ["add", "replace"] {
        let patch_equal = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/scim/v2/Users/{id}"))
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"Operations":[{{"op":"{op}","path":"externalId","value":"{DN}"}}]}}"#,
            )))
            .unwrap();
        let patch_equal_response = app.clone().oneshot(patch_equal).await.unwrap();
        assert_eq!(patch_equal_response.status(), StatusCode::OK, "op {op}");
        let patch_equal_body = response_json(patch_equal_response).await;
        assert_eq!(patch_equal_body["externalId"], DN);
    }

    // PUT with omitted externalId preserves the owned DN and still allows
    // unrelated attribute updates.
    let put_omitted = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"alice-new@example.com"}"#,
        ))
        .unwrap();
    let put_omitted_response = app.clone().oneshot(put_omitted).await.unwrap();
    assert_eq!(put_omitted_response.status(), StatusCode::OK);
    let put_omitted_body = response_json(put_omitted_response).await;
    assert_eq!(put_omitted_body["externalId"], DN);
    assert_eq!(put_omitted_body["userName"], "alice-new@example.com");
    assert!(put_omitted_body.get("directory_provider_id").is_none());
    assert!(put_omitted_body.get("directoryProviderId").is_none());

    // Restore the original userName so the reconciliation check below sees the
    // owned sync key only.
    let put_restore = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"alice@example.com"}"#,
        ))
        .unwrap();
    let put_restore_response = app.clone().oneshot(put_restore).await.unwrap();
    assert_eq!(put_restore_response.status(), StatusCode::OK);

    // An owned row with a missing stored external_id must also fail closed:
    // SCIM cannot supply the missing raw DN.
    let missing_create = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"nodn@example.com"}"#,
        ))
        .unwrap();
    let missing_response = app.clone().oneshot(missing_create).await.unwrap();
    assert_eq!(missing_response.status(), StatusCode::CREATED);
    let missing_created = response_json(missing_response).await;
    let missing_id = missing_created["id"].as_str().unwrap().to_string();
    let mut missing_owned = repo.get_scim_user(&missing_id).await.unwrap().unwrap();
    missing_owned.directory_provider_id = Some(OWNER.to_string());
    repo.update_scim_user(&missing_owned).await.unwrap();
    let missing_patch = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{missing_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"op":"replace","path":"externalId","value":"{DN}"}}]}}"#,
        )))
        .unwrap();
    let missing_patch_response = app.clone().oneshot(missing_patch).await.unwrap();
    assert_eq!(missing_patch_response.status(), StatusCode::CONFLICT);
    let missing_put = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{missing_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"realm":"corp","externalId":"{DN}","userName":"nodn@example.com"}}"#,
        )))
        .unwrap();
    let missing_put_response = app.clone().oneshot(missing_put).await.unwrap();
    assert_eq!(missing_put_response.status(), StatusCode::CONFLICT);
    let missing_stored = repo.get_scim_user(&missing_id).await.unwrap().unwrap();
    assert_eq!(missing_stored.external_id, None);
    assert_eq!(missing_stored.directory_provider_id.as_deref(), Some(OWNER));
    repo.delete_scim_user(&missing_id).await.unwrap();

    // Provider reconciliation still resolves the same owned row: run the real
    // directory sync after the rejected SCIM mutations and the allowed
    // unchanged/equal round trips.
    let sync_state = scim_test_state(repo.clone());
    let sync_result = qid_directory::sync_ldap_entries(
        &sync_state,
        "corp",
        OWNER,
        &[qid_directory::LdapDirectoryEntry {
            dn: DN.to_string(),
            uid: "alice@example.com".to_string(),
            mail: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            department: Some("Platform".to_string()),
            manager_dn: None,
            enabled: true,
        }],
        qid_directory::LdapSyncOptions {
            deactivate_missing: false,
            synced_at: 2_000,
        },
    )
    .await
    .unwrap();
    assert!(sync_result.created_user_ids.is_empty());
    assert_eq!(sync_result.updated_user_ids, vec![id.clone()]);
    assert!(sync_result.unchanged_user_ids.is_empty());
    let reconciled = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(reconciled.external_id.as_deref(), Some(DN));
    assert_eq!(reconciled.directory_provider_id.as_deref(), Some(OWNER));
    assert_eq!(reconciled.user_name, "alice@example.com");
    let users = repo.list_scim_users(&"corp".into()).await.unwrap();
    let owned_matches: Vec<_> = users
        .iter()
        .filter(|user| user.directory_provider_id.as_deref() == Some(OWNER))
        .filter(|user| user.external_id.as_deref() == Some(DN))
        .collect();
    assert_eq!(owned_matches.len(), 1);
    assert_eq!(owned_matches[0].id, id);
    assert_eq!(users.len(), 1);
}

#[tokio::test]
async fn scim_unowned_external_id_remains_mutable() {
    let (app, repo, _store_path) = setup_with_store().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-1","userName":"bob@example.com"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Unowned PUT may change externalId (existing merge behavior).
    let put_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-2","userName":"bob@example.com"}"#,
        ))
        .unwrap();
    let put_response = app.clone().oneshot(put_request).await.unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);
    assert_eq!(response_json(put_response).await["externalId"], "hr-2");

    // Unowned PATCH may change and then clear externalId.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"externalId","value":"hr-3"}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    assert_eq!(response_json(patch_response).await["externalId"], "hr-3");

    let remove_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"remove","path":"externalId"}]}"#,
        ))
        .unwrap();
    let remove_response = app.clone().oneshot(remove_request).await.unwrap();
    assert_eq!(remove_response.status(), StatusCode::OK);

    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.external_id, None);
    assert_eq!(stored.directory_provider_id, None);
}

#[tokio::test]
async fn scim_enterprise_deprovisioned_at_is_server_owned() {
    let (app, repo, _store_path) = setup_with_store().await;

    // Create with a forged enterprise marker: storage and response must drop it.
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-forge","userName":"forge@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Engineering","deprovisioned_at":1050}}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created[ENTERPRISE_USER_SCHEMA]["department"], "Engineering");
    assert!(
        created[ENTERPRISE_USER_SCHEMA]
            .get("deprovisioned_at")
            .is_none()
    );
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.deprovisioned_at, None);
    assert!(stored.enterprise_json.get("deprovisioned_at").is_none());
    assert_eq!(stored.enterprise_json["department"], "Engineering");

    // Seed a trusted timestamp like directory sync would, with a stale forged
    // enterprise value alongside it.
    let mut trusted = stored;
    trusted.deprovisioned_at = Some(1_050);
    trusted.enterprise_json =
        serde_json::json!({"department": "Engineering", "deprovisioned_at": 9_999});
    repo.update_scim_user(&trusted).await.unwrap();

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched = response_json(get_response).await;
    assert_eq!(fetched[ENTERPRISE_USER_SCHEMA]["department"], "Engineering");
    assert_eq!(fetched[ENTERPRISE_USER_SCHEMA]["deprovisioned_at"], 1_050);
    let version_before = fetched["meta"]["version"].as_str().unwrap().to_string();

    // PUT with a different forged marker must preserve the trusted timestamp
    // while still applying unrelated enterprise attributes.
    let put_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-forge","userName":"forge@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Platform","deprovisioned_at":9999}}"#,
        ))
        .unwrap();
    let put_response = app.clone().oneshot(put_request).await.unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);
    let put_body = response_json(put_response).await;
    assert_eq!(put_body[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    assert_eq!(put_body[ENTERPRISE_USER_SCHEMA]["deprovisioned_at"], 1_050);
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.deprovisioned_at, Some(1_050));
    assert!(stored.enterprise_json.get("deprovisioned_at").is_none());
    assert_eq!(stored.enterprise_json["department"], "Platform");

    // PATCH replace of the timestamp must not change the authority.
    let patch_forge = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            "{{\"Operations\":[{{\"op\":\"replace\",\"path\":\"{ENTERPRISE_USER_SCHEMA}:deprovisioned_at\",\"value\":7777}},{{\"op\":\"replace\",\"path\":\"{ENTERPRISE_USER_SCHEMA}:department\",\"value\":\"Research\"}}]}}"
        )))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_forge).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["department"], "Research");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["deprovisioned_at"], 1_050);
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.deprovisioned_at, Some(1_050));
    assert!(stored.enterprise_json.get("deprovisioned_at").is_none());

    // PATCH remove of the timestamp must not clear the authority.
    let patch_remove = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            "{{\"Operations\":[{{\"op\":\"remove\",\"path\":\"{ENTERPRISE_USER_SCHEMA}:deprovisioned_at\"}}]}}"
        )))
        .unwrap();
    let patch_remove_response = app.clone().oneshot(patch_remove).await.unwrap();
    assert_eq!(patch_remove_response.status(), StatusCode::OK);
    let removed = response_json(patch_remove_response).await;
    assert_eq!(removed[ENTERPRISE_USER_SCHEMA]["deprovisioned_at"], 1_050);
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.deprovisioned_at, Some(1_050));

    // PUT without an enterprise body preserves the timestamp.
    let put_omit = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, version_before.as_str())
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-forge","userName":"forge2@example.com"}"#,
        ))
        .unwrap();
    // Version changed since creation, so a stale If-Match must fail; retry
    // without it to prove the merge path still preserves the timestamp.
    let stale = app.clone().oneshot(put_omit).await.unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    let put_retry = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","externalId":"hr-forge","userName":"forge2@example.com"}"#,
        ))
        .unwrap();
    let put_retry_response = app.clone().oneshot(put_retry).await.unwrap();
    assert_eq!(put_retry_response.status(), StatusCode::OK);
    let retried = response_json(put_retry_response).await;
    assert_eq!(retried[ENTERPRISE_USER_SCHEMA]["deprovisioned_at"], 1_050);
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.deprovisioned_at, Some(1_050));
}

const CUSTOM_URN: &str = "urn:example:Custom";
const UNSUPPORTED_ERROR: &str = "unsupported SCIM schema extension";

async fn post_user(app: &Router, body: &str) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let json = response_json(response).await;
    (status, json)
}

#[test]
fn scim_custom_schemas_are_rejected_by_config_validation() {
    fn single_realm_config() -> qid_core::config::QidConfig {
        let mut config = test_helpers::test_config();
        config.realms[0].id = "corp".to_string();
        config.realms[0].issuer = "https://id.example.com/realms/corp".to_string();
        config.realms.truncate(1);
        config
    }
    let mut enabled = single_realm_config();
    enabled.realms[0].protocols.scim.enabled = true;
    enabled.realms[0].protocols.scim.custom_schemas =
        vec![custom_schema(CUSTOM_URN, "Custom", "customAttr")];
    let err = enabled.validate().unwrap_err().to_string();
    assert!(
        err.contains("custom_schemas are unsupported"),
        "unexpected error: {err}"
    );

    let mut disabled = single_realm_config();
    disabled.realms[0].protocols.scim.enabled = false;
    disabled.realms[0].protocols.scim.custom_schemas =
        vec![custom_schema(CUSTOM_URN, "Custom", "customAttr")];
    let err = disabled.validate().unwrap_err().to_string();
    assert!(
        err.contains("custom_schemas are unsupported"),
        "disabled realms must also fail: {err}"
    );
    assert!(
        !err.contains(CUSTOM_URN),
        "config error must not echo values: {err}"
    );

    single_realm_config()
        .validate()
        .expect("empty custom_schemas stays valid");
}

#[tokio::test]
async fn scim_rejects_unsupported_user_extensions_on_post() {
    let (app, repo, _path) = setup_with_store().await;
    let before = repo.list_scim_users(&"corp".into()).await.unwrap().len();
    for body in [
        format!(
            r#"{{"realm":"corp","userName":"custom@example.com","{CUSTOM_URN}":{{"customAttr":"x"}}}}"#
        ),
        format!(
            r#"{{"realm":"corp","userName":"custom@example.com","schemas":["urn:ietf:params:scim:schemas:core:2.0:User","{CUSTOM_URN}"]}}"#
        ),
    ] {
        let (status, json) = post_user(&app, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], format!("bad request: {UNSUPPORTED_ERROR}"));
        assert!(
            !json.to_string().contains(CUSTOM_URN),
            "error must not echo values: {json}"
        );
    }
    assert_eq!(
        repo.list_scim_users(&"corp".into()).await.unwrap().len(),
        before,
        "rejected POST must persist nothing"
    );

    let (status, created) = post_user(
        &app,
        r#"{"realm":"corp","userName":"supported@example.com","schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Engineering"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created[ENTERPRISE_USER_SCHEMA]["department"], "Engineering");
}

#[tokio::test]
async fn scim_rejects_unsupported_user_extensions_on_put() {
    let (app, repo, _path) = setup_with_store().await;
    let (_, created) = post_user(&app, r#"{"realm":"corp","userName":"put@example.com"}"#).await;
    let id = created["id"].as_str().unwrap().to_string();
    let version = created["meta"]["version"].as_str().unwrap().to_string();
    for body in [
        format!(
            r#"{{"realm":"corp","userName":"put@example.com","{CUSTOM_URN}":{{"customAttr":"x"}}}}"#
        ),
        format!(
            r#"{{"realm":"corp","userName":"put@example.com","schemas":["urn:ietf:params:scim:schemas:core:2.0:User","{CUSTOM_URN}"]}}"#
        ),
    ] {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/scim/v2/Users/{id}"))
            .header("Content-Type", "application/json")
            .header(IF_MATCH, &version)
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], format!("bad request: {UNSUPPORTED_ERROR}"));
        assert!(!json.to_string().contains(CUSTOM_URN));
    }
    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.user_name, "put@example.com");
    let get = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(
        get_response.headers().get(ETAG).unwrap().to_str().unwrap(),
        version,
        "rejected PUT must not change the version"
    );
}

#[tokio::test]
async fn scim_bulk_rejects_unsupported_user_extensions() {
    let (app, repo, _path) = setup_with_store().await;
    let before = repo.list_scim_users(&"corp".into()).await.unwrap().len();
    let bulk = format!(
        r#"{{"failOnErrors":0,"Operations":[{{"method":"POST","path":"/Users","bulkId":"bad","data":{{"realm":"corp","userName":"bulk-custom@example.com","{CUSTOM_URN}":{{"customAttr":"x"}}}}}},{{"method":"POST","path":"/Users","bulkId":"good","data":{{"realm":"corp","userName":"bulk-ok@example.com"}}}}]}}"#
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(bulk))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["Operations"][0]["status"], "400");
    assert_eq!(
        json["Operations"][0]["response"]["detail"],
        format!("bad request: {UNSUPPORTED_ERROR}")
    );
    assert!(!json.to_string().contains(CUSTOM_URN));
    assert_eq!(json["Operations"][1]["status"], "201");
    let users = repo.list_scim_users(&"corp".into()).await.unwrap();
    assert_eq!(users.len(), before + 1);
    assert!(users.iter().any(|u| u.user_name == "bulk-ok@example.com"));
    assert!(
        users
            .iter()
            .all(|u| u.user_name != "bulk-custom@example.com"),
        "rejected Bulk user must persist nothing"
    );
}

#[tokio::test]
async fn scim_patch_rejects_custom_extension_without_partial_mutation() {
    let (app, repo, _path) = setup_with_store().await;
    let (_, created) = post_user(&app, r#"{"realm":"corp","userName":"patch@example.com"}"#).await;
    let id = created["id"].as_str().unwrap().to_string();
    let version = created["meta"]["version"].as_str().unwrap().to_string();

    let custom_path = format!(
        r#"{{"Operations":[{{"op":"replace","path":"userName","value":"changed@example.com"}},{{"op":"replace","path":"{CUSTOM_URN}:customAttr","value":"x"}}]}}"#
    );
    let request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, &version)
        .body(Body::from(custom_path))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response_json(response).await;
    assert_eq!(json["error"], format!("bad request: {UNSUPPORTED_ERROR}"));
    assert!(!json.to_string().contains(CUSTOM_URN));

    let pathless = format!(
        r#"{{"Operations":[{{"op":"replace","path":"userName","value":"changed@example.com"}},{{"op":"add","value":{{"{CUSTOM_URN}":{{"customAttr":"x"}}}}}}]}}"#
    );
    let request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .header(IF_MATCH, &version)
        .body(Body::from(pathless))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response_json(response).await;
    assert!(!json.to_string().contains(CUSTOM_URN));

    let stored = repo.get_scim_user(&id).await.unwrap().unwrap();
    assert_eq!(stored.user_name, "patch@example.com");
    let get = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.oneshot(get).await.unwrap();
    assert_eq!(
        get_response.headers().get(ETAG).unwrap().to_str().unwrap(),
        version,
        "rejected PATCH must not change the version"
    );
}

async fn version_test_bulk(app: &Router, body: serde_json::Value) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scim/v2/Bulk")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

async fn version_test_get(app: &Router, path: &str) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

#[tokio::test]
async fn scim_bulk_checks_user_and_group_versions_before_mutating() {
    assert_conditional_user_and_group_routes(setup().await).await;
}

#[tokio::test]
async fn sql_scim_checks_user_and_group_versions_before_mutating() {
    let dir = std::env::temp_dir().join(format!("qid-scim-versions-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = Arc::new(
        SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    repo.create_realm(
        &"tenant".into(),
        &"corp".into(),
        "https://corp.example.com",
        None,
    )
    .await
    .unwrap();
    assert_conditional_user_and_group_routes(test_app(repo.clone())).await;
    Arc::try_unwrap(repo).ok().unwrap().close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

async fn assert_conditional_user_and_group_routes(app: Router) {
    for (resource, attribute) in [("Users", "userName"), ("Groups", "displayName")] {
        let created = version_test_bulk(
            &app,
            serde_json::json!({"Operations": [{
                "method": "POST", "path": format!("/{resource}"),
                "data": {"realm": "corp", attribute: "initial", "active": true}
            }]}),
        )
        .await;
        assert_eq!(created["Operations"][0]["status"], "201");
        let path = created["Operations"][0]["location"].as_str().unwrap();
        let original_version = &created["Operations"][0]["response"]["meta"]["version"];
        // A successful conditional PUT makes the creation version genuinely stale,
        // without depending on clock resolution for the version to change.
        let seeded = version_test_bulk(
            &app,
            serde_json::json!({"Operations": [{
                "method": "PUT", "path": path, "version": original_version,
                "data": {"realm": "corp", attribute: "seeded", "active": true}
            }]}),
        )
        .await;
        assert_eq!(seeded["Operations"][0]["status"], "200");
        assert_ne!(
            seeded["Operations"][0]["response"]["meta"]["version"],
            *original_version
        );

        for method in ["PUT", "PATCH", "DELETE"] {
            let before = version_test_get(&app, path).await;
            let data = if method == "PATCH" {
                serde_json::json!({"Operations": [{
                    "op": "replace", "path": attribute, "value": "patched"
                }]})
            } else {
                serde_json::json!({"realm": "corp", attribute: "replaced", "active": true})
            };
            let mut operation = serde_json::json!({
                "method": method, "path": path, "bulkId": "conditional",
                "version": original_version, "data": data
            });
            let direct = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("Content-Type", "application/json")
                        .header(IF_MATCH, original_version.as_str().unwrap())
                        .body(Body::from(operation["data"].to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                direct.status(),
                StatusCode::PRECONDITION_FAILED,
                "direct {resource} {method}"
            );
            assert_eq!(response_json(direct).await["status"], "412");
            let stale = version_test_bulk(
                &app,
                serde_json::json!({
                    "Operations": [operation.clone()]
                }),
            )
            .await;
            assert_eq!(
                stale["Operations"][0]["status"], "412",
                "{resource} {method}"
            );
            assert_eq!(stale["Operations"][0]["bulkId"], "conditional");
            assert_eq!(stale["Operations"][0]["response"]["status"], "412");
            assert_eq!(
                version_test_get(&app, path).await,
                before,
                "stale {resource} {method} mutated state"
            );

            // PATCH also exercises the individual-route comma-list and whitespace
            // matching rules; PUT and DELETE use the exact current version.
            operation["version"] = if method == "PATCH" {
                serde_json::json!(format!(
                    " \"not-current\", {} ",
                    before["meta"]["version"].as_str().unwrap()
                ))
            } else {
                before["meta"]["version"].clone()
            };
            let current =
                version_test_bulk(&app, serde_json::json!({"Operations": [operation]})).await;
            assert_eq!(
                current["Operations"][0]["status"],
                if method == "DELETE" { "204" } else { "200" },
                "{resource} {method}"
            );
            if method != "DELETE" {
                let after = version_test_get(&app, path).await;
                assert_eq!(
                    after[attribute],
                    if method == "PUT" {
                        "replaced"
                    } else {
                        "patched"
                    }
                );
                assert_eq!(current["Operations"][0]["response"], after);
                assert_ne!(after["meta"]["version"], before["meta"]["version"]);
            }
        }
        if resource == "Users" {
            let soft_deleted = version_test_get(&app, path).await;
            assert_eq!(soft_deleted["active"], false);
            // A stale conditional hard delete must not remove the soft-deleted row.
            let hard_path = format!("{path}?hard_delete=true");
            let stale = version_test_bulk(
                &app,
                serde_json::json!({"Operations": [{
                    "method": "DELETE", "path": hard_path, "version": original_version
                }]}),
            )
            .await;
            assert_eq!(stale["Operations"][0]["status"], "412");
            assert_eq!(version_test_get(&app, path).await, soft_deleted);
            let deleted = version_test_bulk(
                &app,
                serde_json::json!({"Operations": [{
                    "method": "DELETE", "path": hard_path, "version": " * "
                }]}),
            )
            .await;
            assert_eq!(deleted["Operations"][0]["status"], "204");
        }
        let missing = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn scim_bulk_version_failure_counts_toward_fail_on_errors() {
    let app = setup().await;
    let created = version_test_bulk(
        &app,
        serde_json::json!({"Operations": [{
            "method": "POST", "path": "/Users", "data": {"realm": "corp", "userName": "unchanged"}
        }]}),
    )
    .await;
    let path = created["Operations"][0]["location"].as_str().unwrap();
    let before = version_test_get(&app, path).await;
    let result = version_test_bulk(&app, serde_json::json!({"failOnErrors": 1, "Operations": [
        {"method": "PATCH", "path": path, "version": "\"stale\"", "data": {
            "Operations": [{"op": "replace", "path": "userName", "value": "must-not-change"}]
        }},
        {"method": "POST", "path": "/Groups", "data": {"realm": "corp", "displayName": "must-not-run"}}
    ]})).await;
    assert_eq!(result["Operations"].as_array().unwrap().len(), 1);
    assert_eq!(result["Operations"][0]["status"], "412");
    assert_eq!(version_test_get(&app, path).await, before);
    assert_eq!(
        version_test_get(&app, "/scim/v2/Groups?realm=corp").await["totalResults"],
        0
    );
}

#[tokio::test]
async fn scim_bulk_rejects_versions_on_create_without_creating_records() {
    let app = setup().await;
    for (resource, attribute) in [("Users", "userName"), ("Groups", "displayName")] {
        let result = version_test_bulk(&app, serde_json::json!({"failOnErrors": 0, "Operations": [
            {"method": "POST", "path": format!("/{resource}"), "version": "*", "bulkId": "rejected",
             "data": {"realm": "corp", attribute: "must-not-exist"}},
            {"method": "POST", "path": format!("/{resource}"),
             "data": {"realm": "corp", attribute: "unversioned"}}
        ]})).await;
        assert_eq!(result["Operations"][0]["status"], "400");
        assert_eq!(result["Operations"][0]["bulkId"], "rejected");
        assert_eq!(result["Operations"][1]["status"], "201");
        let listed = version_test_get(&app, &format!("/scim/v2/{resource}?realm=corp")).await;
        assert_eq!(listed["totalResults"], 1);
        assert_eq!(listed["Resources"][0][attribute], "unversioned");
    }
}

#[tokio::test]
async fn scim_bulk_version_checks_preserve_realm_isolation_and_missing_status() {
    let app = setup().await;
    let scoped = app
        .clone()
        .layer(axum::Extension(qid_scim::ScimRequestContext {
            realm_id: "other".into(),
        }));
    for (resource, attribute) in [("Users", "userName"), ("Groups", "displayName")] {
        let created = version_test_bulk(
            &app,
            serde_json::json!({"Operations": [{
                "method": "POST", "path": format!("/{resource}"),
                "data": {"realm": "corp", attribute: "private"}
            }]}),
        )
        .await;
        let path = created["Operations"][0]["location"].as_str().unwrap();
        let before = version_test_get(&app, path).await;
        for method in ["PUT", "PATCH", "DELETE"] {
            for version in [
                before["meta"]["version"].as_str().unwrap(),
                "\"stale\"",
                "*",
            ] {
                let result = version_test_bulk(
                    &scoped,
                    serde_json::json!({"Operations": [{
                        "method": method, "path": path, "version": version,
                        "data": {"realm": "other", attribute: "must-not-change", "Operations": []}
                    }]}),
                )
                .await;
                assert_eq!(
                    result["Operations"][0]["status"], "404",
                    "{resource} {method}"
                );
            }
            let missing = version_test_bulk(&app, serde_json::json!({"Operations": [{
                "method": method, "path": format!("/{resource}/missing"), "version": "*", "data": {}
            }]})).await;
            assert_eq!(missing["Operations"][0]["status"], "404");
        }
        assert_eq!(version_test_get(&app, path).await, before);
    }
}

#[tokio::test]
async fn scim_user_patch_add_merges_complex_attributes() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"merge@example.com","name":{"givenName":"Ada","familyName":"Lovelace"},"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Eng","employeeNumber":"E1"}}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Direct `add` on `name` merges: overlapping keys replace, the rest survive.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"add","path":"name","value":{"givenName":"Grace","middleName":"M"}}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched["name"]["givenName"], "Grace");
    assert_eq!(patched["name"]["middleName"], "M");
    assert_eq!(patched["name"]["familyName"], "Lovelace");

    // Direct `add` on the short enterprise alias merges as well.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"add","path":"enterprise","value":{"department":"Platform","costCenter":"RND"}}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["costCenter"], "RND");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["employeeNumber"], "E1");

    // The full enterprise URN alias merges through the same path.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"op":"add","path":"{ENTERPRISE_USER_SCHEMA}","value":{{"organization":"Example"}}}}]}}"#
        )))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["organization"], "Example");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    assert_eq!(patched[ENTERPRISE_USER_SCHEMA]["employeeNumber"], "E1");
    assert_eq!(patched["name"]["familyName"], "Lovelace");

    // Bulk PATCH shares the helper and must merge too.
    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"PATCH","path":"/Users/{id}","data":{{"Operations":[{{"op":"add","path":"name","value":{{"nickName":"G"}}}}]}}}}]}}"#
        )))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "200");
    assert_eq!(bulk["Operations"][0]["response"]["name"]["nickName"], "G");
    assert_eq!(
        bulk["Operations"][0]["response"]["name"]["familyName"],
        "Lovelace"
    );

    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"PATCH","path":"/Users/{id}","data":{{"Operations":[{{"op":"add","path":"{ENTERPRISE_USER_SCHEMA}","value":{{"division":"Research"}}}}]}}}}]}}"#
        )))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "200");
    assert_eq!(
        bulk["Operations"][0]["response"][ENTERPRISE_USER_SCHEMA]["division"],
        "Research"
    );
    assert_eq!(
        bulk["Operations"][0]["response"][ENTERPRISE_USER_SCHEMA]["employeeNumber"],
        "E1"
    );

    // Explicit `replace` still replaces the whole object.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"name","value":{"givenName":"Solo"}}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(patched["name"], serde_json::json!({"givenName": "Solo"}));

    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"op":"replace","path":"{ENTERPRISE_USER_SCHEMA}","value":{{"department":"Solo"}}}}]}}"#
        )))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(
        patched[ENTERPRISE_USER_SCHEMA],
        serde_json::json!({"department": "Solo"})
    );

    // Malformed `add` values fail closed and keep stored fields.
    let before_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let before_response = app.clone().oneshot(before_request).await.unwrap();
    assert_eq!(before_response.status(), StatusCode::OK);
    let before = response_json(before_response).await;
    let before_version = before["meta"]["version"].as_str().unwrap().to_string();

    for body in [
        r#"{"Operations":[{"op":"add","path":"name","value":"oops"}]}"#.to_string(),
        format!(
            r#"{{"Operations":[{{"op":"add","path":"{ENTERPRISE_USER_SCHEMA}","value":["oops"]}}]}}"#
        ),
        r#"{"Operations":[{"op":"add","path":"enterprise"}]}"#.to_string(),
    ] {
        let patch_request = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/scim/v2/Users/{id}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let patch_response = app.clone().oneshot(patch_request).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);
    }

    let after_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let after_response = app.oneshot(after_request).await.unwrap();
    assert_eq!(after_response.status(), StatusCode::OK);
    let after = response_json(after_response).await;
    assert_eq!(after["name"], before["name"]);
    assert_eq!(
        after[ENTERPRISE_USER_SCHEMA],
        before[ENTERPRISE_USER_SCHEMA]
    );
    assert_eq!(after["meta"]["version"], before_version);
}

#[tokio::test]
async fn scim_user_patch_add_appends_emails() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"append@example.com","emails":[{"value":"a@example.com","primary":true}]}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();

    fn email_values(user: &serde_json::Value) -> Vec<&str> {
        user["emails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["value"].as_str().unwrap())
            .collect()
    }

    // Direct `add` appends without dropping the stored entry.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"add","path":"emails","value":[{"value":"b@example.com"}]}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(
        email_values(&patched),
        vec!["a@example.com", "b@example.com"]
    );
    assert_eq!(patched["emails"][0]["primary"], true);

    // Bulk PATCH shares the helper and must append as well.
    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{"Operations":[{{"method":"PATCH","path":"/Users/{id}","data":{{"Operations":[{{"op":"add","path":"emails","value":[{{"value":"c@example.com"}}]}}]}}}}]}}"#
        )))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "200");
    assert_eq!(
        email_values(&bulk["Operations"][0]["response"]),
        vec!["a@example.com", "b@example.com", "c@example.com"]
    );

    // Explicit `replace` stays whole-array replacement.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"emails","value":[{"value":"solo@example.com"}]}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched = response_json(patch_response).await;
    assert_eq!(
        patched["emails"],
        serde_json::json!([{"value": "solo@example.com"}])
    );

    // Malformed `add` values fail closed and keep stored entries.
    let before_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let before_response = app.clone().oneshot(before_request).await.unwrap();
    assert_eq!(before_response.status(), StatusCode::OK);
    let before = response_json(before_response).await;
    let before_version = before["meta"]["version"].as_str().unwrap().to_string();

    for body in [
        r#"{"Operations":[{"op":"add","path":"emails"}]}"#.to_string(),
        r#"{"Operations":[{"op":"add","path":"emails","value":"oops"}]}"#.to_string(),
        r#"{"Operations":[{"op":"add","path":"emails","value":{"value":"oops"}}]}"#.to_string(),
    ] {
        let patch_request = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/scim/v2/Users/{id}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let patch_response = app.clone().oneshot(patch_request).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);
    }

    let after_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let after_response = app.clone().oneshot(after_request).await.unwrap();
    assert_eq!(after_response.status(), StatusCode::OK);
    let after = response_json(after_response).await;
    assert_eq!(after["emails"], before["emails"]);
    assert_eq!(after["meta"]["version"], before_version);

    // A malformed `replace` is a client error too, and the record is unchanged.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"emails","value":{"value":"stored"}}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);

    let after_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let after_response = app.clone().oneshot(after_request).await.unwrap();
    assert_eq!(after_response.status(), StatusCode::OK);
    let after = response_json(after_response).await;
    assert_eq!(after["emails"], before["emails"]);
    assert_eq!(after["meta"]["version"], before_version);
}

#[tokio::test]
async fn scim_device_create_accepts_the_advertised_attribute_names() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Devices")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","displayName":"Lab device","urn:ietf:params:scim:schemas:extension:device:2.0:Device":{"manufacturer":"acme","model":"m1","os":"linux","osVersion":"13","lastSeen":1700000000}}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert!(
        !id.is_empty(),
        "the server assigns an id when none is supplied"
    );
    assert_eq!(created["displayName"], "Lab device");
    assert_eq!(created[DEVICE_EXTENSION_SCHEMA]["manufacturer"], "acme");
    assert_eq!(created[DEVICE_EXTENSION_SCHEMA]["model"], "m1");
    assert_eq!(created[DEVICE_EXTENSION_SCHEMA]["os"], "linux");
    assert_eq!(created[DEVICE_EXTENSION_SCHEMA]["osVersion"], "13");
    assert_eq!(created[DEVICE_EXTENSION_SCHEMA]["lastSeen"], 1700000000);
    assert!(
        created.get("realm").is_none(),
        "the response carries no unadvertised realm attribute"
    );

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Devices/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched = response_json(get_response).await;
    assert_eq!(fetched["displayName"], "Lab device");
    assert_eq!(fetched[DEVICE_EXTENSION_SCHEMA]["osVersion"], "13");
    assert_eq!(fetched[DEVICE_EXTENSION_SCHEMA]["lastSeen"], 1700000000);
}

#[tokio::test]
async fn scim_device_create_uses_a_supplied_id() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Devices")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","id":"device-1","displayName":"Lab"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    assert_eq!(created["id"], "device-1");
}

#[tokio::test]
async fn scim_device_create_rejects_unknown_attribute_names() {
    let app = setup().await;
    for body in [
        r#"{"realm":"corp","displayname":"Lab device"}"#,
        r#"{"realm":"corp","realm_id":"corp"}"#,
        r#"{"realm":"corp","urn:ietf:params:scim:schemas:extension:device:2.0:Device":{"osversion":"13"}}"#,
        r#"{"realm":"corp","schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}"#,
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/Devices")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "body must be rejected: {body}"
        );
    }

    let list_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Devices")
        .body(Body::empty())
        .unwrap();
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let listed = response_json(list_response).await;
    assert_eq!(listed["totalResults"], 0, "a rejected write stores nothing");
}

#[tokio::test]
async fn scim_event_subscription_create_accepts_the_advertised_attribute_names() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/EventSubscriptions")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","callback":"https://events.example.com/hook","eventTypes":["user.created"],"enabled":true}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert!(
        !id.is_empty(),
        "the server assigns an id when none is supplied"
    );
    assert_eq!(created["callback"], "https://events.example.com/hook");
    assert_eq!(created["eventTypes"][0], "user.created");
    assert_eq!(created["enabled"], true);
    assert!(created["createdAt"].as_u64().unwrap() > 0);
    assert!(
        created.get("realm").is_none(),
        "the response carries no unadvertised realm attribute"
    );

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/EventSubscriptions/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched = response_json(get_response).await;
    assert_eq!(fetched["callback"], "https://events.example.com/hook");
    assert_eq!(fetched["eventTypes"][0], "user.created");
}

#[tokio::test]
async fn scim_event_subscription_created_at_is_server_owned() {
    let app = setup().await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/EventSubscriptions")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","callback":"https://events.example.com/hook","eventTypes":["user.created"],"createdAt":1}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    assert_ne!(
        created["createdAt"], 1,
        "a supplied createdAt is ignored in favour of the server time"
    );
}

#[tokio::test]
async fn scim_event_subscription_create_rejects_invalid_payloads() {
    let app = setup().await;
    for body in [
        r#"{"realm":"corp","eventTypes":["user.created"]}"#,
        r#"{"realm":"corp","callback":"https://events.example.com/hook"}"#,
        r#"{"realm":"corp","callback":"https://events.example.com/hook","eventTypes":["user.created"],"callBack":"https://events.example.com/other"}"#,
        r#"{"realm":"corp","callback":"https://events.example.com/hook","eventTypes":"user.created"}"#,
        r#"{"realm":"corp","callback":"https://events.example.com/hook","eventTypes":["user.created"],"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}"#,
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/EventSubscriptions")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "body must be rejected: {body}"
        );
    }

    let list_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/EventSubscriptions")
        .body(Body::empty())
        .unwrap();
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let listed = response_json(list_response).await;
    assert_eq!(listed["totalResults"], 0, "a rejected write stores nothing");
}

#[tokio::test]
async fn scim_complex_containers_are_validated_before_storage() {
    let app = setup().await;

    // A User create with a malformed container is a client error and stores nothing.
    for body in [
        r#"{"realm":"corp","userName":"a@example.com","name":"Alice"}"#,
        r#"{"realm":"corp","userName":"a@example.com","name":{"givenName":42}}"#,
        r#"{"realm":"corp","userName":"a@example.com","emails":"a@example.com"}"#,
        r#"{"realm":"corp","userName":"a@example.com","emails":[{"value":"a@example.com","primary":"yes"}]}"#,
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/Users")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "body must be rejected: {body}"
        );
    }

    // The valid shape still round-trips.
    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"a@example.com","name":{"givenName":"Alice"},"emails":[{"value":"a@example.com","primary":true}]}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = response_json(create_response).await;
    let id = created["id"].as_str().unwrap().to_string();
    let version = created["meta"]["version"].as_str().unwrap().to_string();

    // A malformed replace keeps the stored record.
    let replace_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","userName":"a@example.com","emails":{"value":"a@example.com"}}"#,
        ))
        .unwrap();
    let replace_response = app.clone().oneshot(replace_request).await.unwrap();
    assert_eq!(replace_response.status(), StatusCode::BAD_REQUEST);

    // A malformed patch keeps the stored record.
    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Users/{id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"replace","path":"name","value":["Alice"]}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Users/{id}"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched = response_json(get_response).await;
    assert_eq!(fetched["name"]["givenName"], "Alice");
    assert_eq!(fetched["emails"][0]["value"], "a@example.com");
    assert_eq!(fetched["meta"]["version"], version);

    // Bulk shares the validation and creates nothing for a malformed body.
    let bulk_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"failOnErrors":0,"Operations":[{"method":"POST","path":"/Users","data":{"realm":"corp","userName":"b@example.com","emails":"b@example.com"}}]}"#,
        ))
        .unwrap();
    let bulk_response = app.clone().oneshot(bulk_request).await.unwrap();
    assert_eq!(bulk_response.status(), StatusCode::OK);
    let bulk = response_json(bulk_response).await;
    assert_eq!(bulk["Operations"][0]["status"], "400");

    // A Group container is validated the same way.
    for body in [
        r#"{"realm":"corp","displayName":"engineering","members":"user-1"}"#,
        r#"{"realm":"corp","displayName":"engineering","members":["user-1"]}"#,
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/scim/v2/Groups")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "body must be rejected: {body}"
        );
    }

    let group_request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Groups")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"realm":"corp","displayName":"engineering","members":[{"value":"user-1"}]}"#,
        ))
        .unwrap();
    let group_response = app.clone().oneshot(group_request).await.unwrap();
    assert_eq!(group_response.status(), StatusCode::CREATED);
    let group = response_json(group_response).await;
    let group_id = group["id"].as_str().unwrap().to_string();
    let group_version = group["meta"]["version"].as_str().unwrap().to_string();

    let patch_request = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/scim/v2/Groups/{group_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"Operations":[{"op":"add","path":"members","value":"user-2"}]}"#,
        ))
        .unwrap();
    let patch_response = app.clone().oneshot(patch_request).await.unwrap();
    assert_eq!(patch_response.status(), StatusCode::BAD_REQUEST);

    let group_get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/scim/v2/Groups/{group_id}"))
        .body(Body::empty())
        .unwrap();
    let group_get_response = app.clone().oneshot(group_get_request).await.unwrap();
    assert_eq!(group_get_response.status(), StatusCode::OK);
    let fetched_group = response_json(group_get_response).await;
    assert_eq!(
        fetched_group["members"],
        serde_json::json!([{"value": "user-1"}])
    );
    assert_eq!(fetched_group["meta"]["version"], group_version);
}

#[tokio::test]
async fn scim_write_bodies_must_be_json_objects() {
    let app = setup().await;
    // A JSON sequence must never be mapped positionally onto a payload, and
    // a complex container must never be a sequence either.
    for (path, body) in [
        ("/scim/v2/Users", r#"[]"#),
        ("/scim/v2/Users", r#"["corp","alice@example.com"]"#),
        (
            "/scim/v2/Users",
            r#"{"userName":"a@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":["x"]}"#,
        ),
        ("/scim/v2/Groups", r#"["corp","engineering"]"#),
        (
            "/scim/v2/Devices",
            r#"["corp","dev-positional",null,"Positional display",{"manufacturer":"acme"}]"#,
        ),
        (
            "/scim/v2/Devices",
            r#"{"urn:ietf:params:scim:schemas:extension:device:2.0:Device":[]}"#,
        ),
        (
            "/scim/v2/Devices",
            r#"{"urn:ietf:params:scim:schemas:extension:device:2.0:Device":["acme","model-x"]}"#,
        ),
        (
            "/scim/v2/EventSubscriptions",
            r#"["corp","sub-positional",null,1,"https://events.example.com/h",["user.created"],false]"#,
        ),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "body must be rejected: {body}"
        );
    }

    for path in [
        "/scim/v2/Users",
        "/scim/v2/Groups",
        "/scim/v2/Devices",
        "/scim/v2/EventSubscriptions",
    ] {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("{path}?realm=corp"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = response_json(response).await;
        assert_eq!(listed["totalResults"], 0, "a rejected write stores nothing");
    }
}
