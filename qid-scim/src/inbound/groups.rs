use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use qid_core::{
    error::{QidError, QidResult},
    models::ScimGroup,
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::filter;
use crate::response::{decode_cursor, encode_cursor, filter_fingerprint};
use crate::{ScimRequestContext, scoped_realm};

use super::{
    CreateGroup, ListQuery, MAX_LIST_RESULTS, PatchOperation, PatchRequest, string_value,
    users::scim_cursor_secret,
};

pub(crate) async fn list_groups<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "list_groups").increment(1);
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm.clone());
    let mut groups = match state.repo.list_scim_groups(&RealmId(realm.clone())).await {
        Ok(groups) => groups,
        Err(e) => return qid_http::error_response(e),
    };
    let applied_filter = query.filter.clone();
    if let Some(filter) = query.filter.as_deref() {
        let parsed = match filter::parse_eq_filter(filter, &["displayName"]) {
            Ok(parsed) => parsed,
            Err(e) => return qid_http::error_response(e),
        };
        match parsed.attribute {
            "displayName" => {
                groups.retain(|g| filter::string_filter_matches(&parsed.value, &g.display_name));
            }
            _ => {
                return qid_http::error_response(QidError::Internal {
                    message: "unexpected filter attribute".to_string(),
                });
            }
        }
    }
    let cursor_secret = match scim_cursor_secret(&state, &realm) {
        Ok(secret) => secret,
        Err(e) => return qid_http::error_response(e),
    };
    let filter_fingerprint = filter_fingerprint(applied_filter.as_deref());
    let (start, count) = if let Some(cursor) = query.cursor.as_deref() {
        match decode_cursor(cursor_secret.as_bytes(), cursor, &filter_fingerprint) {
            Some(state) => (state.start, state.count.min(MAX_LIST_RESULTS)),
            None => {
                return qid_http::error_response(QidError::BadRequest {
                    message: "invalid or expired SCIM pagination cursor".to_string(),
                });
            }
        }
    } else {
        (
            query.start_index.unwrap_or(1).saturating_sub(1),
            query.count.unwrap_or(100).min(MAX_LIST_RESULTS),
        )
    };
    let total = groups.len();
    let page: Vec<ScimGroup> = groups.into_iter().skip(start).take(count).collect();
    let next_cursor = if start + count < total {
        Some(encode_cursor(
            cursor_secret.as_bytes(),
            start + count,
            count,
            &filter_fingerprint,
        ))
    } else {
        None
    };
    let resources: Vec<_> = page.into_iter().map(crate::response::scim_group).collect();
    let mut body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start + 1,
        "itemsPerPage": resources.len(),
        "Resources": resources
    });
    if let Some(cursor) = next_cursor {
        body["nextCursor"] = serde_json::Value::String(cursor);
    }
    Json(body).into_response()
}

pub(crate) async fn create_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(mut req): Json<CreateGroup>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "create_group").increment(1);
    req.realm = scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm);
    match create_group_record(&state, req).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::CREATED, group),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn create_group_record<R: Repository>(
    state: &SharedState<R>,
    req: CreateGroup,
) -> QidResult<ScimGroup> {
    let group = ScimGroup {
        id: ulid::Ulid::new().to_string(),
        realm_id: req.realm,
        display_name: req.display_name,
        members_json: req.members.unwrap_or_else(|| serde_json::json!([])),
    };
    state.repo.create_scim_group(&group).await?;
    Ok(group)
}

pub(crate) async fn get_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "get_group").increment(1);
    match state.repo.get_scim_group(&id).await {
        Ok(Some(group))
            if context
                .as_ref()
                .is_none_or(|ctx| ctx.realm_id == group.realm_id) =>
        {
            crate::response::scim_group_response(StatusCode::OK, group)
        }
        Ok(Some(_)) => qid_http::error_response(QidError::NotFound {
            resource: "scim group".to_string(),
        }),
        Ok(None) => qid_http::error_response(QidError::NotFound {
            resource: "scim group".to_string(),
        }),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn replace_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<CreateGroup>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "replace_group").increment(1);
    let existing = match state.repo.get_scim_group(&id).await {
        Ok(Some(group)) => group,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim group".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && existing.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim group".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_group_version(&existing))
    {
        return crate::response::precondition_failed(detail);
    }
    req.realm = scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm);
    match replace_group_record(&state, &id, req).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::OK, group),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn replace_group_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: CreateGroup,
) -> QidResult<ScimGroup> {
    let existing = state
        .repo
        .get_scim_group(id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "scim group".to_string(),
        })?;
    let group = ScimGroup {
        id: id.to_string(),
        realm_id: req.realm,
        display_name: req.display_name,
        members_json: req.members.unwrap_or(existing.members_json),
    };
    state.repo.update_scim_group(&group).await?;
    Ok(group)
}

pub(crate) async fn patch_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "patch_group").increment(1);
    let group = match state.repo.get_scim_group(&id).await {
        Ok(Some(group)) => group,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim group".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && group.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim group".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_group_version(&group))
    {
        return crate::response::precondition_failed(detail);
    }
    match patch_group_record(&state, &id, req).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::OK, group),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn patch_group_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: PatchRequest,
) -> QidResult<ScimGroup> {
    let mut group = state
        .repo
        .get_scim_group(id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "scim group".to_string(),
        })?;
    for op in req.operations {
        apply_group_patch(&mut group, op)?;
    }
    state.repo.update_scim_group(&group).await?;
    Ok(group)
}

fn apply_group_patch(group: &mut ScimGroup, op: PatchOperation) -> Result<(), QidError> {
    let op_name = op.op.to_ascii_lowercase();
    let path = op.path.unwrap_or_default();
    match (op_name.as_str(), path.as_str()) {
        ("add" | "replace", "displayName") => {
            group.display_name = string_value(op.value, "displayName")?;
        }
        ("add" | "replace", "members") => {
            group.members_json = op.value.unwrap_or_else(|| serde_json::json!([]));
        }
        ("remove", "members") => {
            group.members_json = serde_json::json!([]);
        }
        _ => {
            return Err(QidError::BadRequest {
                message: format!("unsupported SCIM PATCH operation {} {}", op.op, path),
            });
        }
    }
    Ok(())
}

pub(crate) async fn delete_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "delete_group").increment(1);
    let group = match state.repo.get_scim_group(&id).await {
        Ok(Some(group)) => group,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim group".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && group.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim group".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_group_version(&group))
    {
        return crate::response::precondition_failed(detail);
    }
    match state.repo.delete_scim_group(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => qid_http::error_response(e),
    }
}
