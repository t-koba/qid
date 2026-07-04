use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{ETAG, IF_MATCH},
    },
};
use http_body_util::BodyExt;
use qid_core::{state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::FileRepository;
use std::sync::Arc;
use tower::ServiceExt;

const ENTERPRISE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

async fn setup() -> Router {
    let path = std::env::temp_dir().join(format!("qid-scim-{}.json", ulid::Ulid::new()));
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let mut config = test_helpers::test_config();
    config.realms[0].id = "corp".to_string();
    config.realms[0].protocols.scim.cursor_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    qid_scim::scim_routes().with_state(state)
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
    let bytes = schemas_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let schemas: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = resource_types_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let resource_types: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = patch_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let patched: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = soft_deleted_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let soft_deleted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = filter_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let filtered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(filtered["totalResults"], 1);
    assert_eq!(filtered["Resources"][0]["externalId"], "hr-1");

    let user_name_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=userName%20eq%20%22user0%40example.com%22")
        .body(Body::empty())
        .unwrap();
    let user_name_response = app.clone().oneshot(user_name_request).await.unwrap();
    assert_eq!(user_name_response.status(), StatusCode::OK);
    let bytes = user_name_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let user_name_filtered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = active_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let active_filtered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = enterprise_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let enterprise_filtered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(enterprise_filtered["totalResults"], 1);
    assert_eq!(enterprise_filtered["Resources"][0]["externalId"], "hr-1");

    let short_enterprise_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&filter=enterprise.department%20eq%20%22Operations%22")
        .body(Body::empty())
        .unwrap();
    let short_enterprise_response = app.clone().oneshot(short_enterprise_request).await.unwrap();
    assert_eq!(short_enterprise_response.status(), StatusCode::OK);
    let bytes = short_enterprise_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let short_enterprise_filtered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(short_enterprise_filtered["totalResults"], 2);

    let page_request = Request::builder()
        .method(Method::GET)
        .uri("/scim/v2/Users?realm=corp&start_index=2&count=1")
        .body(Body::empty())
        .unwrap();
    let page_response = app.clone().oneshot(page_request).await.unwrap();
    assert_eq!(page_response.status(), StatusCode::OK);
    let bytes = page_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = patch_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let patched: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = list_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let listed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = bulk_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let bulk: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = delete_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let deleted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(deleted["Operations"][0]["status"], "204");
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
    let bytes = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = patch_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let patched: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = get_soft_deleted_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let soft_deleted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
