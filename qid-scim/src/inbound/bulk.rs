use axum::{
    Json,
    extract::{Extension, State},
    response::IntoResponse,
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use super::groups::{create_group_record, patch_group_record, replace_group_record};
use super::users::{
    create_user_record, delete_user_record, patch_user_record, replace_user_record,
};
use super::{CreateGroup, CreateUser, MAX_BULK_OPERATIONS, PatchRequest};
use crate::ScimRequestContext;

#[derive(Debug, Deserialize)]
pub(crate) struct BulkRequest {
    #[serde(
        default = "super::default_bulk_fail_on_errors",
        rename = "failOnErrors"
    )]
    fail_on_errors: usize,
    #[serde(default, rename = "Operations")]
    operations: Vec<BulkOperation>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BulkOperation {
    method: String,
    path: String,
    #[serde(default, rename = "bulkId")]
    bulk_id: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

pub(crate) async fn bulk<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(req): Json<BulkRequest>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "bulk").increment(1);
    if req.operations.len() > MAX_BULK_OPERATIONS {
        return qid_http::error_response(qid_core::error::QidError::BadRequest {
            message: format!("SCIM Bulk supports at most {MAX_BULK_OPERATIONS} operations"),
        });
    }
    let mut failures = 0usize;
    let mut operations = Vec::new();
    let context_realm = context.as_ref().map(|ext| ext.realm_id.clone());
    for op in req.operations {
        let result = apply_bulk_operation(&state, context_realm.as_deref(), op).await;
        if result["status"]
            .as_str()
            .unwrap_or_default()
            .starts_with('4')
        {
            failures += 1;
        }
        operations.push(result);
        if req.fail_on_errors > 0 && failures >= req.fail_on_errors {
            break;
        }
    }
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
        "Operations": operations
    }))
    .into_response()
}

async fn apply_bulk_operation<R: Repository>(
    state: &SharedState<R>,
    context_realm: Option<&str>,
    op: BulkOperation,
) -> serde_json::Value {
    let method = op.method.to_ascii_uppercase();
    let (path, query) = normalize_bulk_path(&op.path);
    let operation_name = match (method.as_str(), path.as_str()) {
        ("POST", "/Users") | ("POST", "Users") => "create_user",
        ("PUT", p) if p.starts_with("/Users/") => "replace_user",
        ("PATCH", p) if p.starts_with("/Users/") => "patch_user",
        ("POST", "/Groups") | ("POST", "Groups") => "create_group",
        ("PUT", p) if p.starts_with("/Groups/") => "replace_group",
        ("PATCH", p) if p.starts_with("/Groups/") => "patch_group",
        ("DELETE", p) if p.starts_with("/Users/") => "delete_user",
        ("DELETE", p) if p.starts_with("/Groups/") => "delete_group",
        _ => "unknown",
    }
    .to_string();
    metrics::counter!("qid_scim_operations_total", "operation" => operation_name.clone())
        .increment(1);
    match (method.as_str(), path.as_str()) {
        ("POST", "/Users") | ("POST", "Users") => {
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let mut req = match serde_json::from_value::<CreateUser>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid user data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = realm_id.to_string();
            }
            match create_user_record(state, req).await {
                Ok(user) => bulk_success(
                    method,
                    op.bulk_id,
                    "201",
                    Some(format!("/scim/v2/Users/{}", user.id)),
                    Some(crate::response::scim_user(user)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PUT", path) if path.starts_with("/Users/") => {
            let id = path.trim_start_matches("/Users/");
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            if let Err(e) = ensure_user_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            let mut req = match serde_json::from_value::<CreateUser>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid user data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = realm_id.to_string();
            }
            match replace_user_record(state, id, req).await {
                Ok(user) => bulk_success(
                    method,
                    op.bulk_id,
                    "200",
                    Some(format!("/scim/v2/Users/{}", user.id)),
                    Some(crate::response::scim_user(user)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PATCH", path) if path.starts_with("/Users/") => {
            let id = path.trim_start_matches("/Users/");
            if let Err(e) = ensure_user_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let req = match serde_json::from_value::<PatchRequest>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid user patch data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            match patch_user_record(state, id, req).await {
                Ok(user) => bulk_success(
                    method,
                    op.bulk_id,
                    "200",
                    Some(format!("/scim/v2/Users/{}", user.id)),
                    Some(crate::response::scim_user(user)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("POST", "/Groups") | ("POST", "Groups") => {
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let mut req = match serde_json::from_value::<CreateGroup>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid group data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = realm_id.to_string();
            }
            match create_group_record(state, req).await {
                Ok(group) => bulk_success(
                    method,
                    op.bulk_id,
                    "201",
                    Some(format!("/scim/v2/Groups/{}", group.id)),
                    Some(crate::response::scim_group(group)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PUT", path) if path.starts_with("/Groups/") => {
            let id = path.trim_start_matches("/Groups/");
            if let Err(e) = ensure_group_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let mut req = match serde_json::from_value::<CreateGroup>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid group data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = realm_id.to_string();
            }
            match replace_group_record(state, id, req).await {
                Ok(group) => bulk_success(
                    method,
                    op.bulk_id,
                    "200",
                    Some(format!("/scim/v2/Groups/{}", group.id)),
                    Some(crate::response::scim_group(group)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PATCH", path) if path.starts_with("/Groups/") => {
            let id = path.trim_start_matches("/Groups/");
            if let Err(e) = ensure_group_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let req = match serde_json::from_value::<PatchRequest>(data).map_err(|e| {
                qid_core::error::QidError::BadRequest {
                    message: format!("invalid group patch data: {e}"),
                }
            }) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            match patch_group_record(state, id, req).await {
                Ok(group) => bulk_success(
                    method,
                    op.bulk_id,
                    "200",
                    Some(format!("/scim/v2/Groups/{}", group.id)),
                    Some(crate::response::scim_group(group)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("DELETE", path) if path.starts_with("/Users/") => {
            let id = path.trim_start_matches("/Users/");
            if let Err(e) = ensure_user_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            let hard_delete = query.as_deref() == Some("hard_delete=true");
            match delete_user_record(state, id, hard_delete).await {
                Ok(()) => bulk_success(method, op.bulk_id, "204", None, None),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("DELETE", path) if path.starts_with("/Groups/") => {
            let id = path.trim_start_matches("/Groups/");
            if let Err(e) = ensure_group_realm(state, id, context_realm).await {
                return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
            }
            match state.repo.delete_scim_group(id).await {
                Ok(()) => bulk_success(method, op.bulk_id, "204", None, None),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        _ => bulk_error(op.bulk_id, "400", "unsupported bulk operation"),
    }
}

async fn ensure_user_realm<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    context_realm: Option<&str>,
) -> qid_core::error::QidResult<()> {
    let Some(realm_id) = context_realm else {
        return Ok(());
    };
    let user =
        state
            .repo
            .get_scim_user(id)
            .await?
            .ok_or_else(|| qid_core::error::QidError::NotFound {
                resource: "scim user".to_string(),
            })?;
    if user.realm_id != realm_id {
        return Err(qid_core::error::QidError::NotFound {
            resource: "scim user".to_string(),
        });
    }
    Ok(())
}

async fn ensure_group_realm<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    context_realm: Option<&str>,
) -> qid_core::error::QidResult<()> {
    let Some(realm_id) = context_realm else {
        return Ok(());
    };
    let group = state.repo.get_scim_group(id).await?.ok_or_else(|| {
        qid_core::error::QidError::NotFound {
            resource: "scim group".to_string(),
        }
    })?;
    if group.realm_id != realm_id {
        return Err(qid_core::error::QidError::NotFound {
            resource: "scim group".to_string(),
        });
    }
    Ok(())
}

fn normalize_bulk_path(path: &str) -> (String, Option<String>) {
    let path = path.strip_prefix("/scim/v2").unwrap_or(path);
    let (path, query) = path
        .split_once('?')
        .map(|(path, query)| (path, Some(query.to_string())))
        .unwrap_or((path, None));
    (path.to_string(), query)
}

fn bulk_success(
    method: String,
    bulk_id: Option<String>,
    status: &str,
    location: Option<String>,
    response: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut item = serde_json::json!({ "method": method, "status": status });
    if let Some(bulk_id) = bulk_id {
        item["bulkId"] = serde_json::Value::String(bulk_id);
    }
    if let Some(location) = location {
        item["location"] = serde_json::Value::String(location);
    }
    if let Some(response) = response {
        item["response"] = response;
    }
    item
}

fn bulk_error(bulk_id: Option<String>, status: &str, detail: &str) -> serde_json::Value {
    let mut item = serde_json::json!({
        "status": status,
        "response": {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": detail,
            "status": status
        }
    });
    if let Some(bulk_id) = bulk_id {
        item["bulkId"] = serde_json::Value::String(bulk_id);
    }
    item
}
