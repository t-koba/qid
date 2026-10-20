use super::write::{Condition, WriteError, WriteResult};
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
use qid_storage::{ScimMutation, prelude::*};
use std::sync::Arc;

use crate::{ScimRequestContext, filter, scoped_realm};

use super::{CreateGroup, ListQuery, PatchOperation, PatchRequest, string_value};

pub(crate) async fn list_groups<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "list_groups").increment(1);
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm.clone());
    let pagination = match super::list::Pagination::new(&state, &realm, &query) {
        Ok(value) => value,
        Err(error) => return qid_http::error_response(error),
    };
    let (start, count) = (pagination.start, pagination.count);
    let realm_id = RealmId(realm);
    let (total, page) = if let Some(filter) = query.filter.as_deref() {
        let mut groups = match state.repo.list_scim_groups(&realm_id).await {
            Ok(groups) => groups,
            Err(e) => return qid_http::error_response(e),
        };
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
        let total = groups.len();
        let page: Vec<ScimGroup> = groups.into_iter().skip(start).take(count).collect();
        (total, page)
    } else {
        let total = match state.repo.count_scim_groups(&realm_id).await {
            Ok(total) => total,
            Err(e) => return qid_http::error_response(e),
        };
        let page = match state
            .repo
            .list_scim_groups_page(&realm_id, start, count)
            .await
        {
            Ok(groups) => groups,
            Err(e) => return qid_http::error_response(e),
        };
        (total, page)
    };
    let resources = page.into_iter().map(crate::response::scim_group).collect();
    pagination.response(total, resources)
}

pub(crate) async fn create_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(mut req): Json<CreateGroup>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "create_group").increment(1);
    req.realm = super::realm_opt(context.as_ref().map(|ext| &ext.0), req.realm);
    match create_group_record(&state, req).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::CREATED, group),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn create_group_record<R: Repository>(
    state: &SharedState<R>,
    req: CreateGroup,
) -> QidResult<ScimGroup> {
    super::complex::validate_group_complex(req.members.as_ref())?;
    let group = ScimGroup {
        id: ulid::Ulid::new().to_string(),
        realm_id: req.realm.unwrap_or_else(super::default_realm),
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
    match super::write::checked_resource(
        state.repo.get_scim_group(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        None,
        "scim group",
        |value| &value.realm_id,
        crate::response::scim_group_version,
    ) {
        Ok(value) => crate::response::scim_group_response(StatusCode::OK, value),
        Err(response) => *response,
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
    let existing = match super::write::checked_resource(
        state.repo.get_scim_group(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim group",
        |value| &value.realm_id,
        crate::response::scim_group_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    req.realm = super::realm_opt(context.as_ref().map(|ext| &ext.0), req.realm);
    let expected = Condition::from_headers(existing.realm_id, &headers);
    match replace_group_record(&state, &id, req, expected).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::OK, group),
        Err(e) => e.into_response(),
    }
}

fn replace_group_value(existing: ScimGroup, req: CreateGroup) -> QidResult<ScimGroup> {
    super::complex::validate_group_complex(req.members.as_ref())?;
    Ok(ScimGroup {
        id: existing.id.clone(),
        realm_id: req.realm.unwrap_or_else(super::default_realm),
        display_name: req.display_name,
        members_json: req.members.unwrap_or(existing.members_json),
    })
}

pub(crate) async fn replace_group_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: CreateGroup,
    expected: Option<Condition>,
) -> WriteResult<ScimGroup> {
    write_group(state, id, expected, move |current, conditional| {
        let mut req = req;
        if conditional {
            req.realm.get_or_insert(current.realm_id.clone());
        }
        replace_group_value(current, req)
    })
    .await
}

pub(crate) async fn patch_group<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "patch_group").increment(1);
    let group = match super::write::checked_resource(
        state.repo.get_scim_group(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim group",
        |value| &value.realm_id,
        crate::response::scim_group_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let expected = Condition::from_headers(group.realm_id, &headers);
    match patch_group_record(&state, &id, req, expected).await {
        Ok(group) => crate::response::scim_group_response(StatusCode::OK, group),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn patch_group_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: PatchRequest,
    expected: Option<Condition>,
) -> WriteResult<ScimGroup> {
    write_group(state, id, expected, move |current, _| {
        let mut group = current;
        for op in req.operations {
            apply_group_patch(&mut group, op)?;
        }
        Ok(group)
    })
    .await
}

fn apply_group_patch(group: &mut ScimGroup, op: PatchOperation) -> Result<(), QidError> {
    let op_name = op.op.to_ascii_lowercase();
    let path = op.path.unwrap_or_default();
    match (op_name.as_str(), path.as_str()) {
        ("add" | "replace", "displayName") => {
            group.display_name = string_value(op.value, "displayName")?
        }
        ("add", "members") => {
            let mut members = group.members_json.as_array().cloned().unwrap_or_default();
            match op.value {
                Some(serde_json::Value::Array(values)) => {
                    for value in &values {
                        super::complex::validate_member(value)?;
                    }
                    members.extend(values);
                }
                Some(value) => {
                    super::complex::validate_member(&value)?;
                    members.push(value);
                }
                None => {}
            }
            group.members_json = serde_json::Value::Array(members);
        }
        ("replace", "members") => {
            let value = op.value.unwrap_or(serde_json::json!([]));
            super::complex::validate_members(&value)?;
            group.members_json = value;
        }
        ("remove", "members") => group.members_json = serde_json::json!([]),
        _ => return Err(super::unsupported_patch(op.op.as_str(), path.as_str())),
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
    let group = match super::write::checked_resource(
        state.repo.get_scim_group(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim group",
        |value| &value.realm_id,
        crate::response::scim_group_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let expected = Condition::from_headers(group.realm_id, &headers);
    match delete_group_record(&state, &id, expected).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn delete_group_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    expected: Option<Condition>,
) -> WriteResult<()> {
    if let Some(condition) = expected {
        state
            .repo
            .mutate_scim_group(
                id,
                Box::new(move |current| {
                    Ok(if condition.matches_group(current) {
                        ScimMutation::Delete
                    } else {
                        ScimMutation::Reject
                    })
                }),
            )
            .await?
            .ok_or(WriteError::PreconditionFailed)?;
    } else {
        state.repo.delete_scim_group(id).await?;
    }
    Ok(())
}

/// Transform the locked row conditionally, or retain ordinary read/update behavior.
async fn write_group<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    expected: Option<Condition>,
    transform: impl FnOnce(ScimGroup, bool) -> QidResult<ScimGroup> + Send,
) -> WriteResult<ScimGroup> {
    if let Some(condition) = expected {
        state
            .repo
            .mutate_scim_group(
                id,
                Box::new(move |current| {
                    if !condition.matches_group(current) {
                        return Ok(ScimMutation::Reject);
                    }
                    Ok(ScimMutation::Replace(transform(current.clone(), true)?))
                }),
            )
            .await?
            .ok_or(WriteError::PreconditionFailed)
    } else {
        let current = state
            .repo
            .get_scim_group(id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: "scim group".to_string(),
            })?;
        let value = transform(current, false)?;
        state.repo.update_scim_group(&value).await?;
        Ok(value)
    }
}
