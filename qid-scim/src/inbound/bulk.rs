use axum::{
    Json,
    extract::{Extension, State},
    response::IntoResponse,
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use super::groups::{
    create_group_record, delete_group_record, patch_group_record, replace_group_record,
};
use super::users::{
    create_user_record, delete_user_record, patch_user_record, replace_user_record,
};
use super::{CreateGroup, MAX_BULK_OPERATIONS, PatchRequest};
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
    #[serde(default)]
    version: Option<String>,
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
        // Every failed operation counts toward failOnErrors, including server
        // errors: a batch must stop after a repository failure, not just
        // after client errors.
        if !result["status"]
            .as_str()
            .unwrap_or_default()
            .starts_with('2')
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
    if method == "POST"
        && matches!(path.as_str(), "/Users" | "Users" | "/Groups" | "Groups")
        && op.version.is_some()
    {
        return bulk_error(
            op.bulk_id,
            "400",
            "version is not applicable to create operations",
        );
    }
    match (method.as_str(), path.as_str()) {
        (verb, path)
            if (verb == "POST" && matches!(path, "/Users" | "Users"))
                || (verb == "PUT" && path.starts_with("/Users/")) =>
        {
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let id = (verb == "PUT").then(|| path.trim_start_matches("/Users/"));
            let expected = if let Some(id) = id {
                match check_user_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                }
            } else {
                None
            };
            let mut req = match super::parse_create_user(data) {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = Some(realm_id.to_string());
            }
            let result = if let Some(id) = id {
                replace_user_record(state, id, req, expected).await
            } else {
                create_user_record(state, req)
                    .await
                    .map_err(super::write::WriteError::from)
            };
            let status = if id.is_some() { "200" } else { "201" };
            match result {
                Ok(user) => bulk_success(
                    method,
                    op.bulk_id,
                    status,
                    Some(format!("/scim/v2/Users/{}", user.id)),
                    Some(crate::response::scim_user(user)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PATCH", path) if path.starts_with("/Users/") => {
            let id = path.trim_start_matches("/Users/");
            let expected =
                match check_user_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                };
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let req = match parse_bulk_data::<PatchRequest>(data, "user patch") {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            match patch_user_record(state, id, req, expected).await {
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
        (verb, path)
            if (verb == "POST" && matches!(path, "/Groups" | "Groups"))
                || (verb == "PUT" && path.starts_with("/Groups/")) =>
        {
            let id = (verb == "PUT").then(|| path.trim_start_matches("/Groups/"));
            let expected = if let Some(id) = id {
                match check_group_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                }
            } else {
                None
            };
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let mut req = match parse_bulk_data::<CreateGroup>(data, "group") {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            if let Some(realm_id) = context_realm {
                req.realm = Some(realm_id.to_string());
            }
            let result = if let Some(id) = id {
                replace_group_record(state, id, req, expected).await
            } else {
                create_group_record(state, req)
                    .await
                    .map_err(super::write::WriteError::from)
            };
            let status = if id.is_some() { "200" } else { "201" };
            match result {
                Ok(group) => bulk_success(
                    method,
                    op.bulk_id,
                    status,
                    Some(format!("/scim/v2/Groups/{}", group.id)),
                    Some(crate::response::scim_group(group)),
                ),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("PATCH", path) if path.starts_with("/Groups/") => {
            let id = path.trim_start_matches("/Groups/");
            let expected =
                match check_group_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                };
            let Some(data) = op.data else {
                return bulk_error(op.bulk_id, "400", "data required");
            };
            let req = match parse_bulk_data::<PatchRequest>(data, "group patch") {
                Ok(req) => req,
                Err(e) => {
                    return bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message());
                }
            };
            match patch_group_record(state, id, req, expected).await {
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
            let expected =
                match check_user_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                };
            let hard_delete = query.as_deref() == Some("hard_delete=true");
            match delete_user_record(state, id, hard_delete, expected).await {
                Ok(()) => bulk_success(method, op.bulk_id, "204", None, None),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        ("DELETE", path) if path.starts_with("/Groups/") => {
            let id = path.trim_start_matches("/Groups/");
            let expected =
                match check_group_preconditions(state, id, context_realm, op.version.as_deref())
                    .await
                {
                    Ok(expected) => expected,
                    Err((status, detail)) => {
                        return bulk_error(op.bulk_id, &status.to_string(), &detail);
                    }
                };
            match delete_group_record(state, id, expected).await {
                Ok(()) => bulk_success(method, op.bulk_id, "204", None, None),
                Err(e) => bulk_error(op.bulk_id, &e.status_code().to_string(), &e.message()),
            }
        }
        _ => bulk_error(op.bulk_id, "400", "unsupported bulk operation"),
    }
}

// Carry the full condition into the serialized mutation for revalidation.
async fn check_user_preconditions<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    context_realm: Option<&str>,
    version: Option<&str>,
) -> Result<Option<super::write::Condition>, (u16, String)> {
    if context_realm.is_none() && version.is_none() {
        return Ok(None);
    }
    let user = state
        .repo
        .get_scim_user(id)
        .await
        .map_err(|e| (e.status_code(), e.message()))?
        .ok_or_else(|| (404, "scim user not found".to_string()))?;
    if context_realm.is_some_and(|realm_id| user.realm_id != realm_id) {
        return Err((404, "scim user not found".to_string()));
    }
    if let Some(version) = version {
        crate::response::check_resource_version(
            version,
            &crate::response::scim_user_version(&user),
        )
        .map_err(|detail| (412, detail.to_string()))?;
    }
    Ok(version.map(|version| super::write::Condition::new(user.realm_id, version)))
}

async fn check_group_preconditions<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    context_realm: Option<&str>,
    version: Option<&str>,
) -> Result<Option<super::write::Condition>, (u16, String)> {
    if context_realm.is_none() && version.is_none() {
        return Ok(None);
    }
    let group = state
        .repo
        .get_scim_group(id)
        .await
        .map_err(|e| (e.status_code(), e.message()))?
        .ok_or_else(|| (404, "scim group not found".to_string()))?;
    if context_realm.is_some_and(|realm_id| group.realm_id != realm_id) {
        return Err((404, "scim group not found".to_string()));
    }
    if let Some(version) = version {
        crate::response::check_resource_version(
            version,
            &crate::response::scim_group_version(&group),
        )
        .map_err(|detail| (412, detail.to_string()))?;
    }
    Ok(version.map(|version| super::write::Condition::new(group.realm_id, version)))
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

fn parse_bulk_data<T: serde::de::DeserializeOwned>(
    data: serde_json::Value,
    description: &str,
) -> qid_core::error::QidResult<T> {
    serde_json::from_value(data).map_err(|error| qid_core::error::QidError::BadRequest {
        message: format!("invalid {description} data: {error}"),
    })
}

#[cfg(test)]
#[path = "conditional_tests.rs"]
mod conditional_tests;
