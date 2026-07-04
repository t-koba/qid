use super::*;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use qid_core::config::AdminSecurityConfig;
use qid_core::models::Admin;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

pub fn directory_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/directory/v1/providers", get(list_providers::<R>))
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
        .filter(|p| p.enabled)
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "type": p.provider_type,
                "enabled": p.enabled,
                "url": p.connection.url,
            })
        })
        .collect();

    Json(serde_json::json!({
        "providers": active,
        "supported": ["ldap", "active-directory", "scim", "hr_csv"],
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
        Some(p) => Json(serde_json::json!({
            "id": p.id,
            "type": p.provider_type,
            "enabled": p.enabled,
            "url": p.connection.url,
            "base_dn": p.connection.base_dn,
            "sync_interval_minutes": p.sync.sync_interval_minutes,
            "deactivate_missing": p.sync.deactivate_missing,
            "user_search_filter": p.sync.user_search_filter,
        }))
        .into_response(),
        None => Json(serde_json::json!({
            "error": "provider not found",
            "id": id,
        }))
        .into_response(),
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
    if let Err(error) = resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        return error.into_response();
    }
    let status = "connected";
    Json(serde_json::json!({
        "id": id,
        "status": status,
        "updated_at": qid_core::util::now_seconds(),
    }))
    .into_response()
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
    let provider = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|p| p.id == id);

    match provider {
        Some(provider) => {
            let _ = state
                .repo
                .append_audit_event(&AuditEvent {
                    id: ulid::Ulid::new().to_string(),
                    realm_id: Some(realm.id.clone()),
                    actor: "directory-api".to_string(),
                    action: "directory.sync.trigger".to_string(),
                    target_type: "directory_provider".to_string(),
                    target_id: id.clone(),
                    reason: "API trigger".to_string(),
                    metadata_json: serde_json::json!({
                        "provider_id": id,
                        "provider_type": provider.provider_type,
                    }),
                    created_at: qid_core::util::now_seconds(),
                    previous_hash: None,
                    event_hash: None,
                })
                .await;

            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "sync_triggered",
                    "provider_id": id,
                    "message": "Sync has been triggered.",
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "provider not found",
                "id": id,
            })),
        )
            .into_response(),
    }
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
    if let Err(error) = resolve_directory_realm(&state, query.realm.as_deref(), &admin) {
        return error.into_response();
    }
    Json(serde_json::json!({
        "provider_id": id,
        "status": "idle",
        "last_sync_at": null,
        "last_sync_result": null,
    }))
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
