use super::*;
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use qid_core::config::{AdminSecurityConfig, DIRECTORY_PROVIDER_TYPES};
use qid_core::models::Admin;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

pub fn directory_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/directory/v1/providers", get(list_providers::<R>))
        .route("/directory/v1/providers/:id/hr", post(receive_hr::<R>))
        .route(
            "/directory/v1/providers/:id",
            get(get_provider::<R>).patch(update_provider_status::<R>),
        )
        .route("/directory/v1/providers/:id/sync", post(trigger_sync::<R>))
        .route(
            "/directory/v1/providers/:id/sync/status",
            get(get_sync_status::<R>),
        )
}

#[derive(Debug, serde::Deserialize)]
struct DirectoryRealmQuery {
    #[serde(default)]
    realm: Option<String>,
}

async fn list_providers<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRealmQuery>,
) -> impl IntoResponse {
    let admin = match require_directory_admin(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    let providers = realm.protocols.directory.providers.clone();

    let active: Vec<serde_json::Value> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "type": p.provider_type,
                "enabled": p.enabled,
                "syncable": qid_core::config::DIRECTORY_SYNC_PROVIDER_TYPES.contains(&p.provider_type.as_str()),
                "url": p.connection.url,
            })
        })
        .collect();

    Json(serde_json::json!({
        "providers": active,
        "supported": DIRECTORY_PROVIDER_TYPES,
    }))
    .into_response()
}

async fn get_provider<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRealmQuery>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let admin = match require_directory_admin(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    let provider = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|p| p.id == id)
        .cloned();

    match provider {
        Some(p) => {
            if p.provider_type == "webhook" {
                return Json(serde_json::json!({
                    "id": p.id, "type": p.provider_type, "enabled": p.enabled,
                    "syncable": false, "webhook": p.webhook.unwrap_or_default(),
                }))
                .into_response();
            }
            let deactivate_missing = p
                .sync
                .deactivate_missing
                .unwrap_or(p.provider_type != "csv");
            Json(serde_json::json!({
                "id": p.id,
                "type": p.provider_type,
                "enabled": p.enabled,
                "syncable": qid_core::config::DIRECTORY_SYNC_PROVIDER_TYPES.contains(&p.provider_type.as_str()),
                "url": p.connection.url,
                "base_dn": p.connection.base_dn,
                "deactivate_missing": deactivate_missing,
                "user_search_filter": p.sync.user_search_filter,
            }))
            .into_response()
        }
        None => directory_provider_not_found(&id),
    }
}

async fn update_provider_status<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRealmQuery>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let admin = match require_directory_admin(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    if realm
        .protocols
        .directory
        .providers
        .iter()
        .all(|p| p.id != id)
    {
        return directory_provider_not_found(&id);
    }
    directory_http_unsupported(
        &id,
        "provider configuration is managed through qid configuration; HTTP status updates are not implemented".to_string(),
    )
}

async fn trigger_sync<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRealmQuery>,
    Path(id): Path<String>,
) -> Response {
    let admin = match require_directory_admin(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    let Some(provider) = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|provider| provider.id == id)
    else {
        return directory_provider_not_found(&id);
    };
    if !qid_core::config::DIRECTORY_SYNC_PROVIDER_TYPES.contains(&provider.provider_type.as_str()) {
        return directory_http_unsupported(
            &id,
            "inbound webhook providers receive HR batches and do not run periodic directory sync"
                .to_string(),
        );
    }
    directory_http_unsupported(
        &id,
        format!(
            "the HTTP API does not schedule directory sync work; run `qid-worker directory-sync --realm {} --provider-id {id}` to execute a sync",
            realm.id
        ),
    )
}

async fn get_sync_status<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryRealmQuery>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let admin = match require_directory_admin(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    let Some(provider) = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|provider| provider.id == id)
    else {
        return directory_provider_not_found(&id);
    };
    if !qid_core::config::DIRECTORY_SYNC_PROVIDER_TYPES.contains(&provider.provider_type.as_str()) {
        return directory_http_unsupported(
            &id,
            "inbound webhook providers have no periodic directory sync status".to_string(),
        );
    }
    directory_http_unsupported(
        &id,
        format!(
            "the HTTP API does not track directory sync status; run `qid-worker directory-sync --realm {} --provider-id {id}` and inspect its report",
            realm.id
        ),
    )
}

fn directory_provider_not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "provider not found",
            "id": id,
        })),
    )
        .into_response()
}

fn directory_http_unsupported(id: &str, detail: String) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "unsupported",
            "id": id,
            "detail": detail,
        })),
    )
        .into_response()
}

async fn require_directory_admin<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> Result<Admin, Response> {
    let session_id = headers
        .get(ADMIN_SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unauthorized_response("admin session required"))?;
    let elevation = state
        .repo
        .get_admin_elevation(session_id)
        .await
        .map_err(|_| unauthorized_response("admin elevation lookup failed"))?
        .ok_or_else(|| unauthorized_response("admin elevation session not found"))?;
    let admin = state
        .repo
        .get_admin_by_id(&elevation.admin_id)
        .await
        .map_err(|_| unauthorized_response("admin lookup failed"))?
        .ok_or_else(|| unauthorized_response("admin record not found"))?;
    if admin.tenant_id != elevation.tenant_id {
        return Err(unauthorized_response(
            "admin elevation belongs to a different tenant",
        ));
    }
    enforce_admin_security(&elevation, &state.config.admin.security)
        .map_err(|error| error.into_response())?;
    if !admin.roles.iter().any(|role| {
        matches!(
            role.as_str(),
            "tenant.owner" | "realm.admin" | "directory.admin" | "security.admin"
        )
    }) {
        return Err(unauthorized_response(
            "admin role is not allowed for directory operations",
        ));
    }
    Ok(admin)
}

fn resolve_directory_realm<'a, R>(
    state: &'a SharedState<R>,
    requested_realm: Option<&str>,
    admin: &Admin,
) -> Result<&'a qid_core::config::RealmConfig, DirectoryRouteError> {
    let realm = if let Some(realm_id) = requested_realm.filter(|value| !value.trim().is_empty()) {
        state
            .config
            .realms
            .iter()
            .find(|realm| realm.id == realm_id)
            .ok_or(DirectoryRouteError::NotFound("realm not found"))?
    } else if state.config.realms.len() == 1 {
        &state.config.realms[0]
    } else {
        return Err(DirectoryRouteError::Unauthorized(
            "directory realm must be specified",
        ));
    };
    let Some(tenant_id) = realm.tenant_id.as_deref() else {
        return Err(DirectoryRouteError::Unauthorized(
            "directory realm is not bound to a tenant",
        ));
    };
    if tenant_id != admin.tenant_id {
        return Err(DirectoryRouteError::Unauthorized(
            "admin tenant does not match directory realm tenant",
        ));
    }
    Ok(realm)
}

enum DirectoryRouteError {
    Unauthorized(&'static str),
    NotFound(&'static str),
}

impl DirectoryRouteError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized(error) => unauthorized_response(error),
            Self::NotFound(error) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response(),
        }
    }
}

fn enforce_admin_security(
    elevation: &qid_core::models::AdminElevation,
    security: &AdminSecurityConfig,
) -> Result<(), DirectoryRouteError> {
    let now = qid_core::util::now_seconds();
    if elevation.elevation_expires_at <= now {
        return Err(DirectoryRouteError::Unauthorized(
            "admin elevation has expired",
        ));
    }
    if elevation.elevation_expires_at.saturating_sub(now) > security.max_elevation_seconds {
        return Err(DirectoryRouteError::Unauthorized(
            "admin elevation lifetime exceeds configured maximum",
        ));
    }
    if security.require_step_up {
        let acr_ok = elevation.acr.as_deref() == Some(security.required_acr.as_str());
        let amr_ok = elevation
            .amr
            .iter()
            .any(|method| security.required_amr.contains(method));
        if !acr_ok || !amr_ok {
            return Err(DirectoryRouteError::Unauthorized(
                "admin step-up is required",
            ));
        }
    }
    Ok(())
}

fn unauthorized_response(error: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": error })),
    )
        .into_response()
}

async fn receive_hr<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Query(query): Query<DirectoryRealmQuery>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let admin = match require_directory_admin(request.headers(), &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let realm = match resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        Ok(realm) => realm,
        Err(error) => return error.into_response(),
    };
    let Some(provider) = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|p| p.id == id)
    else {
        return directory_provider_not_found(&id);
    };
    if !realm.protocols.directory.enabled
        || !provider.enabled
        || provider.provider_type != "webhook"
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "enabled webhook binding required"})),
        )
            .into_response();
    }
    let limits = provider.webhook.clone().unwrap_or_default();
    let is_json = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(serde_json::json!({"error": "application/json required; no changes applied"})),
        )
            .into_response();
    }
    // Read the bounded raw body ourselves: no JSON extraction or default 2 MiB
    // extractor limit, and no caller-supplied authority fields are accepted.
    let bytes = match axum::body::to_bytes(request.into_body(), limits.max_request_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"error": "HR body exceeds byte limit or body could not be read; no changes applied"}))).into_response(),
    };
    // Derived structs accept positional arrays. Check object shapes without
    // discarding duplicate-field detection in the typed parse below.
    let shape: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(shape) => shape,
        Err(_) => return invalid_hr_envelope(),
    };
    if !shape.is_object()
        || !shape
            .get("records")
            .and_then(|v| v.as_array())
            .is_some_and(|records| records.iter().all(|r| r.is_object()))
    {
        return invalid_hr_envelope();
    }
    drop(shape);
    let envelope: HrEnvelope = match serde_json::from_slice(&bytes) {
        Ok(envelope) => envelope,
        Err(_) => return invalid_hr_envelope(),
    };
    if envelope.records.len() > limits.max_records as usize {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "HR record limit exceeded; no changes applied"})),
        )
            .into_response();
    }
    if envelope
        .records
        .iter()
        .any(|record| record.external_id.trim().is_empty() || record.user_name.trim().is_empty())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "HR external_id and user_name must be nonempty; no changes applied"})),
        )
            .into_response();
    }
    match import_hr_webhook(&state, &realm.id, &id, envelope, qid_core::util::sha256_hex(&bytes)).await {
        Ok(result) => Json(result).into_response(),
        Err(QidError::Conflict { .. }) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": "HR sequence or target conflict; no changes applied"}))).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "HR outcome uncertain; retry identical sequence and body"}))).into_response(),
    }
}

fn invalid_hr_envelope() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid HR envelope; no changes applied"})),
    )
        .into_response()
}
