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
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::ENTERPRISE_USER_SCHEMA;
use crate::filter;
use crate::response::{decode_cursor, encode_cursor, filter_fingerprint};
use crate::{ScimRequestContext, scoped_realm};

use super::{
    CreateUser, DeleteQuery, ListQuery, MAX_LIST_RESULTS, PatchOperation, PatchRequest, bool_value,
    string_value,
};

pub(crate) async fn list_users<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "list_users").increment(1);
    let realm = scoped_realm(context.as_ref().map(|ext| &ext.0), query.realm);
    let cursor_secret = match scim_cursor_secret(&state, &realm) {
        Ok(secret) => secret,
        Err(e) => return qid_http::error_response(e),
    };
    let mut users = match state.repo.list_scim_users(&RealmId(realm)).await {
        Ok(users) => users,
        Err(e) => return qid_http::error_response(e),
    };
    let applied_filter = query.filter.clone();
    if let Some(filter) = query.filter.as_deref() {
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
    }
    let filter_fingerprint = filter_fingerprint(applied_filter.as_deref());
    // RFC 9865 §4.2: cursors take precedence over `startIndex`/`count`.
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
    let total = users.len();
    let page: Vec<ScimUser> = users.into_iter().skip(start).take(count).collect();
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
    let resources: Vec<_> = page.into_iter().map(crate::response::scim_user).collect();
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
    Json(mut req): Json<CreateUser>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "create_user").increment(1);
    req.realm = scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm);
    match create_user_record(&state, req).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::CREATED, user),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn create_user_record<R: Repository>(
    state: &SharedState<R>,
    req: CreateUser,
) -> QidResult<ScimUser> {
    let user = ScimUser {
        id: ulid::Ulid::new().to_string(),
        realm_id: req.realm,
        external_id: req.external_id,
        user_name: req.user_name,
        name_json: req.name.unwrap_or_else(|| serde_json::json!({})),
        emails_json: req.emails.unwrap_or_else(|| serde_json::json!([])),
        enterprise_json: req.enterprise.unwrap_or_else(|| serde_json::json!({})),
        active: req.active.unwrap_or(true),
    };
    state.repo.create_scim_user(&user).await?;
    GLOBAL_EVENT_BUS.publish(Event {
        kind: EventKind::ScimProvisioned,
        realm_id: Some(user.realm_id.clone()),
        tenant_id: None,
        payload: serde_json::json!({
            "scim_user_id": user.id,
            "user_name": user.user_name,
            "operation": "created",
        }),
        timestamp: qid_core::util::now_seconds(),
    });
    Ok(user)
}

pub(crate) async fn get_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "get_user").increment(1);
    match state.repo.get_scim_user(&id).await {
        Ok(Some(user))
            if context
                .as_ref()
                .is_none_or(|ctx| ctx.realm_id == user.realm_id) =>
        {
            crate::response::scim_user_response(StatusCode::OK, user)
        }
        Ok(Some(_)) => qid_http::error_response(QidError::NotFound {
            resource: "scim user".to_string(),
        }),
        Ok(None) => qid_http::error_response(QidError::NotFound {
            resource: "scim user".to_string(),
        }),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn replace_user<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    context: Option<Extension<ScimRequestContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<CreateUser>,
) -> impl IntoResponse {
    metrics::counter!("qid_scim_operations_total", "operation" => "replace_user").increment(1);
    let existing = match state.repo.get_scim_user(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim user".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && existing.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim user".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_user_version(&existing))
    {
        return crate::response::precondition_failed(detail);
    }
    req.realm = scoped_realm(context.as_ref().map(|ext| &ext.0), req.realm);
    match replace_user_record(&state, &id, req).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::OK, user),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn replace_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: CreateUser,
) -> QidResult<ScimUser> {
    let existing = state
        .repo
        .get_scim_user(id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "scim user".to_string(),
        })?;
    let user = ScimUser {
        id: id.to_string(),
        realm_id: req.realm,
        external_id: req.external_id.or(existing.external_id),
        user_name: req.user_name,
        name_json: req.name.unwrap_or(existing.name_json),
        emails_json: req.emails.unwrap_or(existing.emails_json),
        enterprise_json: req.enterprise.unwrap_or(existing.enterprise_json),
        active: req.active.unwrap_or(existing.active),
    };
    state.repo.update_scim_user(&user).await?;
    GLOBAL_EVENT_BUS.publish(Event {
        kind: EventKind::ScimProvisioned,
        realm_id: Some(user.realm_id.clone()),
        tenant_id: None,
        payload: serde_json::json!({
            "scim_user_id": user.id,
            "user_name": user.user_name,
            "operation": "replaced",
        }),
        timestamp: qid_core::util::now_seconds(),
    });
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
    let user = match state.repo.get_scim_user(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim user".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && user.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim user".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_user_version(&user))
    {
        return crate::response::precondition_failed(detail);
    }
    match patch_user_record(&state, &id, req).await {
        Ok(user) => crate::response::scim_user_response(StatusCode::OK, user),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn patch_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    req: PatchRequest,
) -> QidResult<ScimUser> {
    let mut user = state
        .repo
        .get_scim_user(id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "scim user".to_string(),
        })?;
    for op in req.operations {
        apply_user_patch(&mut user, op)?;
    }
    state.repo.update_scim_user(&user).await?;
    GLOBAL_EVENT_BUS.publish(Event {
        kind: EventKind::ScimProvisioned,
        realm_id: Some(user.realm_id.clone()),
        tenant_id: None,
        payload: serde_json::json!({
            "scim_user_id": user.id,
            "user_name": user.user_name,
            "operation": "patched",
        }),
        timestamp: qid_core::util::now_seconds(),
    });
    Ok(user)
}

fn apply_user_patch(user: &mut ScimUser, op: PatchOperation) -> Result<(), QidError> {
    let op_name = op.op.to_ascii_lowercase();
    let path = op.path.unwrap_or_default();
    match (op_name.as_str(), path.as_str()) {
        ("add" | "replace", "userName") => {
            user.user_name = string_value(op.value, "userName")?;
        }
        ("add" | "replace", "externalId") => {
            user.external_id = Some(string_value(op.value, "externalId")?);
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
    let user = match state.repo.get_scim_user(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "scim user".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if let Some(ctx) = context.as_ref()
        && user.realm_id != ctx.realm_id
    {
        return qid_http::error_response(QidError::NotFound {
            resource: "scim user".to_string(),
        });
    }
    if let Err(detail) =
        crate::response::check_if_match(&headers, &crate::response::scim_user_version(&user))
    {
        return crate::response::precondition_failed(detail);
    }
    if query.hard_delete {
        return match delete_user_record(&state, &id, true).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => qid_http::error_response(e),
        };
    }
    match delete_user_record(&state, &id, false).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn delete_user_record<R: Repository>(
    state: &SharedState<R>,
    id: &str,
    hard_delete: bool,
) -> QidResult<()> {
    if hard_delete {
        let user = state.repo.get_scim_user(id).await?;
        let realm_id = user.as_ref().map(|u| u.realm_id.clone());
        state.repo.delete_scim_user(id).await?;
        GLOBAL_EVENT_BUS.publish(Event {
            kind: EventKind::ScimProvisioned,
            realm_id,
            tenant_id: None,
            payload: serde_json::json!({
                "scim_user_id": id,
                "operation": "hard_deleted",
            }),
            timestamp: qid_core::util::now_seconds(),
        });
    } else {
        let mut user = state
            .repo
            .get_scim_user(id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: "scim user".to_string(),
            })?;
        let realm_id = user.realm_id.clone();
        user.active = false;
        state.repo.update_scim_user(&user).await?;
        GLOBAL_EVENT_BUS.publish(Event {
            kind: EventKind::ScimProvisioned,
            realm_id: Some(realm_id),
            tenant_id: None,
            payload: serde_json::json!({
                "scim_user_id": id,
                "operation": "soft_deleted",
            }),
            timestamp: qid_core::util::now_seconds(),
        });
    }
    Ok(())
}
