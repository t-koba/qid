use super::write::{Condition, WriteError, WriteResult};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use qid_core::{
    error::{QidError, QidResult},
    event::{Event, EventBus, EventKind, GLOBAL_EVENT_BUS},
    models::ScimUser,
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::{ScimMutation, prelude::*};
use std::sync::Arc;

use crate::{ENTERPRISE_USER_SCHEMA, ScimRequestContext, filter, scoped_realm};

use super::{
    CreateUser, DeleteQuery, ListQuery, PatchOperation, PatchRequest, bool_value,
    reject_unsupported_user_extensions, string_value, unsupported_user_schema_error,
};

pub(crate) async fn list_users<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "list_users").increment(1);
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm.clone());
    let pagination = match super::list::Pagination::new(&state, &realm, &query) {
        Ok(value) => value,
        Err(error) => return qid_http::error_response(error),
    };
    let (start, count) = (pagination.start, pagination.count);
    let realm_id = RealmId(realm);
    let (total, page) = if let Some(filter) = query.filter.as_deref() {
        let mut users = match state.repo.list_scim_users(&realm_id).await {
            Ok(users) => users,
            Err(e) => return qid_http::error_response(e),
        };
        let parsed = match filter::parse_eq_filter(
            filter,
            &[
                "userName",
                "externalId",
                "active",
                "enterprise.department",
                "enterprise.employeeNumber",
                "enterprise.costCenter",
                "enterprise.organization",
                "enterprise.division",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division",
            ],
        ) {
            Ok(parsed) => parsed,
            Err(e) => return qid_http::error_response(e),
        };
        match parsed.attribute {
            "userName" => {
                users.retain(|u| filter::string_filter_matches(&parsed.value, &u.user_name))
            }
            "externalId" => users.retain(|u| {
                u.external_id
                    .as_deref()
                    .is_some_and(|value| filter::string_filter_matches(&parsed.value, value))
            }),
            "active" => users.retain(|u| filter::bool_filter_matches(&parsed.value, u.active)),
            attribute => {
                let Some(enterprise_attribute) = filter::enterprise_filter_attribute(attribute)
                else {
                    return qid_http::error_response(QidError::Internal {
                        message: "unexpected filter attribute".to_string(),
                    });
                };
                users.retain(|u| {
                    u.enterprise_json
                        .get(enterprise_attribute)
                        .and_then(|value| value.as_str())
                        .is_some_and(|value| filter::string_filter_matches(&parsed.value, value))
                });
            }
        }
        let total = users.len();
        let page: Vec<ScimUser> = users.into_iter().skip(start).take(count).collect();
        (total, page)
    } else {
        let total = match state.repo.count_scim_users(&realm_id).await {
            Ok(total) => total,
            Err(e) => return qid_http::error_response(e),
        };
        let page = match state
            .repo
            .list_scim_users_page(&realm_id, start, count)
            .await
        {
            Ok(users) => users,
            Err(e) => return qid_http::error_response(e),
        };
        (total, page)
    };
    let resources = page.into_iter().map(crate::response::scim_user).collect();
    pagination.response(total, resources)
}

pub(crate) fn scim_cursor_secret<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
) -> QidResult<String> {
    let realm = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::BadRequest {
            message: "SCIM realm is not configured".to_string(),
        })?;
    realm
        .protocols
        .scim
        .cursor_secret
        .clone()
        .ok_or_else(|| QidError::Config {
            message: "SCIM cursor_secret is not configured".to_string(),
        })
}

pub(crate) async fn create_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Json(raw): Json<serde_json::Value>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "create_user").increment(1);
    let mut req = match super::parse_create_user(raw) {
        Ok(req) => req,
        Err(e) => return qid_http::error_response(e),
    };
    req.realm = super::realm_opt(context.as_ref().map(|ext| &ext.0), req.realm);
    match create_user_record(&state, req).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::CREATED, user),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn create_user_record<R: Repository>(
    state: &SharedState<R>,
    req: CreateUser,
) -> QidResult<ScimUser> {
    let mut enterprise_json = req.enterprise.unwrap_or_else(|| serde_json::json!({}));
    // The authoritative timestamp is server-owned: strip any client-supplied
    // marker so storage never persists a forged value. SCIM create never
    // stamps a deprovision.
    crate::response::strip_stored_enterprise_marker(&mut enterprise_json);
    let user = ScimUser {
        id: ulid::Ulid::new().to_string(),
        realm_id: req.realm.unwrap_or_else(super::default_realm),
        external_id: req.external_id,
        user_name: req.user_name,
        name_json: req.name.unwrap_or_else(|| serde_json::json!({})),
        emails_json: req.emails.unwrap_or_else(|| serde_json::json!([])),
        enterprise_json,
        // Server-owned: SCIM clients can neither set nor clear ownership.
        directory_provider_id: None,
        deprovisioned_at: None,
        active: req.active.unwrap_or(true),
    };
    state.repo.create_scim_user(&user).await?;
    publish_user_write(&user, "created");
    Ok(user)
}

pub(crate) async fn get_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "get_user").increment(1);
    match super::write::checked_resource(
        state.repo.get_scim_user(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        None,
        "scim user",
        |value| &value.realm_id,
        crate::response::scim_user_version,
    ) {
        Ok(value) => crate::response::scim_user_response(StatusCode::OK, value),
        Err(response) => *response,
    }
}

pub(crate) async fn replace_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(raw): Json<serde_json::Value>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "replace_user").increment(1);
    let existing = match super::write::checked_resource(
        state.repo.get_scim_user(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim user",
        |value| &value.realm_id,
        crate::response::scim_user_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let mut req = match super::parse_create_user(raw) {
        Ok(req) => req,
        Err(e) => return qid_http::error_response(e),
    };
    req.realm = super::realm_opt(context.as_ref().map(|ext| &ext.0), req.realm);
    let expected = Condition::from_headers(existing.realm_id, &headers);
    match replace_user_record(&state, &id, req, expected).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::OK, user),
        Err(e) => e.into_response(),
    }
}

fn replace_user_value(existing: ScimUser, req: CreateUser) -> QidResult<ScimUser> {
    // PUT preserves provider-owned raw-DN externalId; only identical round-trips are allowed.
    if existing.directory_provider_id.is_some()
        && let Some(supplied) = req.external_id.as_deref()
        && existing.external_id.as_deref() != Some(supplied)
    {
        return Err(owned_external_id_conflict("changed"));
    }
    let external_id = if existing.directory_provider_id.is_some() {
        existing.external_id.clone()
    } else {
        req.external_id.or(existing.external_id)
    };
    let mut enterprise_json = req.enterprise.unwrap_or(existing.enterprise_json);
    // Preserve the authoritative lifecycle timestamp, stripping any client-supplied marker.
    crate::response::strip_stored_enterprise_marker(&mut enterprise_json);
    Ok(ScimUser {
        id: existing.id.clone(),
        realm_id: req.realm.unwrap_or_else(super::default_realm),
        external_id,
        user_name: req.user_name,
        name_json: req.name.unwrap_or(existing.name_json),
        emails_json: req.emails.unwrap_or(existing.emails_json),
        enterprise_json,
        // PUT cannot forge or clear directory ownership.
        directory_provider_id: existing.directory_provider_id,
        deprovisioned_at: existing.deprovisioned_at,
        active: req.active.unwrap_or(existing.active),
    })
}

pub(crate) async fn replace_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: CreateUser,
    expected: Option<Condition>,
) -> WriteResult<ScimUser> {
    let user = write_user(state, id, expected, move |current, conditional| {
        let mut req = req;
        if conditional {
            req.realm.get_or_insert(current.realm_id.clone());
        }
        replace_user_value(current, req)
    })
    .await?;
    publish_user_write(&user, "replaced");
    Ok(user)
}

pub(crate) async fn patch_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "patch_user").increment(1);
    let user = match super::write::checked_resource(
        state.repo.get_scim_user(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim user",
        |value| &value.realm_id,
        crate::response::scim_user_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let expected = Condition::from_headers(user.realm_id, &headers);
    match patch_user_record(&state, &id, req, expected).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::OK, user),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn patch_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: PatchRequest,
    expected: Option<Condition>,
) -> WriteResult<ScimUser> {
    // PATCH preserves stored directory ownership; enterprise edits stay informational.
    let user = write_user(state, id, expected, move |current, _| {
        let mut user = current;
        let trusted_deprovisioned_at = user.deprovisioned_at;
        for op in req.operations {
            apply_user_patch(&mut user, op)?;
        }
        // SCIM PATCH can neither forge, change, nor remove the authoritative
        // timestamp; unrelated enterprise attributes still apply.
        user.deprovisioned_at = trusted_deprovisioned_at;
        crate::response::strip_stored_enterprise_marker(&mut user.enterprise_json);
        Ok(user)
    })
    .await?;
    publish_user_write(&user, "patched");
    Ok(user)
}

/// 409 for SCIM attempts to mutate the provider-owned raw-DN `external_id`.
/// Ownership lives in `directory_provider_id`; directory sync is the only writer.
fn owned_external_id_conflict(action: &str) -> QidError {
    QidError::Conflict {
        message: format!("externalId is managed by directory sync and cannot be {action} via SCIM"),
    }
}

fn apply_user_patch(user: &mut ScimUser, op: PatchOperation) -> Result<(), QidError> {
    let op_name = op.op.to_ascii_lowercase();
    let path = op.path.unwrap_or_default();
    let enterprise_path = format!("{ENTERPRISE_USER_SCHEMA}:");
    let core_path = format!("{}:", super::CORE_USER_SCHEMA);
    let unsupported_urn_path = super::has_urn_scheme(&path)
        && path != ENTERPRISE_USER_SCHEMA
        && !path.starts_with(&enterprise_path)
        && path != super::CORE_USER_SCHEMA
        && !path.starts_with(&core_path);
    if unsupported_urn_path
        || op
            .value
            .as_ref()
            .is_some_and(|value| reject_unsupported_user_extensions(value).is_err())
    {
        return Err(unsupported_user_schema_error());
    }
    match (op_name.as_str(), path.as_str()) {
        ("add" | "replace", "userName") => {
            user.user_name = string_value(op.value, "userName")?;
        }
        ("add" | "replace", "externalId") => {
            let new_value = string_value(op.value, "externalId")?;
            if user.directory_provider_id.is_some() {
                // Directory sync owns this raw DN; only an identical round-trip is allowed.
                if user.external_id.as_deref() != Some(new_value.as_str()) {
                    return Err(owned_external_id_conflict("changed"));
                }
            } else {
                user.external_id = Some(new_value);
            }
        }
        ("add" | "replace", "active") => {
            user.active = bool_value(op.value, "active")?;
        }
        ("add" | "replace", "name") => {
            user.name_json = op.value.unwrap_or_else(|| serde_json::json!({}));
        }
        ("add" | "replace", "emails") => {
            user.emails_json = op.value.unwrap_or_else(|| serde_json::json!([]));
        }
        ("add" | "replace", ENTERPRISE_USER_SCHEMA) | ("add" | "replace", "enterprise") => {
            user.enterprise_json = op.value.unwrap_or_else(|| serde_json::json!({}));
        }
        ("remove", "externalId") => {
            if user.directory_provider_id.is_some() {
                return Err(owned_external_id_conflict("removed"));
            }
            user.external_id = None;
        }
        ("remove", "active") => {
            user.active = false;
        }
        ("remove", "name") => {
            user.name_json = serde_json::json!({});
        }
        ("remove", "emails") => {
            user.emails_json = serde_json::json!([]);
        }
        ("remove", ENTERPRISE_USER_SCHEMA) | ("remove", "enterprise") => {
            user.enterprise_json = serde_json::json!({});
        }
        _ => {
            apply_enterprise_patch(user, op_name.as_str(), path.as_str(), op.value)?;
        }
    }
    Ok(())
}

fn apply_enterprise_patch(
    user: &mut ScimUser,
    op_name: &str,
    path: &str,
    value: Option<serde_json::Value>,
) -> Result<(), QidError> {
    let Some(attribute) = path
        .strip_prefix(&(ENTERPRISE_USER_SCHEMA.to_string() + ":"))
        .or_else(|| path.strip_prefix("enterprise."))
    else {
        return Err(QidError::BadRequest {
            message: format!("unsupported SCIM PATCH operation {op_name} {path}"),
        });
    };
    let Some(object) = user.enterprise_json.as_object_mut() else {
        user.enterprise_json = serde_json::json!({});
        return apply_enterprise_patch(user, op_name, path, value);
    };
    match op_name {
        "add" | "replace" => {
            object.insert(
                attribute.to_string(),
                value.ok_or_else(|| QidError::BadRequest {
                    message: format!("{attribute} value is required"),
                })?,
            );
        }
        "remove" => {
            object.remove(attribute);
        }
        _ => {
            return Err(QidError::BadRequest {
                message: format!("unsupported SCIM PATCH operation {op_name} {path}"),
            });
        }
    }
    Ok(())
}

pub(crate) async fn delete_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "delete_user").increment(1);
    let user = match super::write::checked_resource(
        state.repo.get_scim_user(&id).await,
        context.as_ref().map(|ctx| ctx.realm_id.as_str()),
        Some(&headers),
        "scim user",
        |value| &value.realm_id,
        crate::response::scim_user_version,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let expected = Condition::from_headers(user.realm_id, &headers);
    match delete_user_record(&state, &id, query.hard_delete, expected).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn delete_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    hard_delete: bool,
    expected: Option<Condition>,
) -> WriteResult<()> {
    let realm_id = if let Some(condition) = expected {
        let user = state
            .repo
            .mutate_scim_user(
                id,
                Box::new(move |current| {
                    if !condition.matches_user(current) {
                        return Ok(ScimMutation::Reject);
                    }
                    Ok(if hard_delete {
                        ScimMutation::Delete
                    } else {
                        let mut user = current.clone();
                        user.active = false;
                        ScimMutation::Replace(user)
                    })
                }),
            )
            .await?
            .ok_or(WriteError::PreconditionFailed)?;
        Some(user.realm_id)
    } else if hard_delete {
        let user = state.repo.get_scim_user(id).await?;
        state.repo.delete_scim_user(id).await?;
        user.map(|u| u.realm_id)
    } else {
        let user = write_user(state, id, None, |mut user, _| {
            user.active = false;
            Ok(user)
        })
        .await?;
        Some(user.realm_id)
    };
    GLOBAL_EVENT_BUS.publish(Event {
        kind: EventKind::ScimProvisioned,
        realm_id,
        tenant_id: None,
        payload: serde_json::json!({
            "scim_user_id": id,
            "operation": if hard_delete { "hard_deleted" } else { "soft_deleted" },
        }),
        timestamp: qid_core::util::now_seconds(),
    });
    Ok(())
}

/// Transform the locked row conditionally, or retain ordinary read/update behavior.
async fn write_user<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    expected: Option<Condition>,
    transform: impl FnOnce(ScimUser, bool) -> QidResult<ScimUser> + Send,
) -> WriteResult<ScimUser> {
    if let Some(condition) = expected {
        state
            .repo
            .mutate_scim_user(
                id,
                Box::new(move |current| {
                    if !condition.matches_user(current) {
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
            .get_scim_user(id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: "scim user".to_string(),
            })?;
        let value = transform(current, false)?;
        state.repo.update_scim_user(&value).await?;
        Ok(value)
    }
}

fn publish_user_write(user: &ScimUser, operation: &str) {
    GLOBAL_EVENT_BUS.publish(Event {
        kind: EventKind::ScimProvisioned,
        realm_id: Some(user.realm_id.clone()),
        tenant_id: None,
        payload: serde_json::json!({
            "scim_user_id": user.id,
            "user_name": user.user_name,
            "operation": operation,
        }),
        timestamp: qid_core::util::now_seconds(),
    });
}
