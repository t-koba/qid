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

fn test_app<R: Repository>(repo: Arc<R>) -> Router {
    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    config.realms[0].protocols.scim.cursor_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    config.realms[0].protocols.scim.event_callback_allowed_hosts =
        vec!["events.example.com".into()];
    let mut other = config.realms[0].clone();
    other.id = "other".into();
    config.realms.push(other);
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap());
    qid_scim::scim_routes().with_state(state)
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn scim_discovery_advertises_enterprise_user_extension() {
    let app = setup().await;
    let schemas_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Schemas")
        .body(Body::empty())
        .unwrap();
    let schemas_response = app.clone().oneshot(schemas_request).await.unwrap();
    assert_eq!(schemas_response.status(), StatusCode::OK);
    let schemas = response_json(schemas_response).await;
    assert_eq!(schemas["totalResults"], 3);
    assert!(
        schemas["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource| {
                resource["id"] == ENTERPRISE_USER_SCHEMA
                    && resource["attributes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|attribute| attribute["name"] == "department")
            })
    );

    let resource_types_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/ResourceTypes")
        .body(Body::empty())
        .unwrap();
    let resource_types_response = app.oneshot(resource_types_request).await.unwrap();
    assert_eq!(resource_types_response.status(), StatusCode::OK);
    let resource_types = response_json(resource_types_response).await;
    let user = resource_types["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["id"] == "User")
        .unwrap();
    assert_eq!(
        user["schemaExtensions"][0]["schema"],
        ENTERPRISE_USER_SCHEMA
    );
    assert_eq!(user["schemaExtensions"][0]["required"], false);
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
        let initial = case["initial"].clone();
        let mut changed = case["changed"].clone();
        let response = realm_request(&app, Method::POST, resource, "corp", initial).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let incumbent = stored_resource(repo.as_ref(), resource).await;
        assert_eq!(incumbent["realm_id"], "corp");
        // A body claiming the incumbent realm must not override the other context.
        changed["realm_id"] = "corp".into();
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
        changed["realm_id"] = "other".into();
        let response = realm_request(&app, Method::POST, resource, "corp", changed.clone()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let updated = stored_resource(repo.as_ref(), resource).await;
        assert_ne!(updated, incumbent);
        changed["realm_id"] = "corp".into();
        for (key, value) in changed.as_object().unwrap() {
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
