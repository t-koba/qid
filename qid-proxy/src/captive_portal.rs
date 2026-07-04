use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use qid_core::{
    config::ServerPaths,
    error::{QidError, QidResult},
    state::SharedState,
    util::now_seconds,
};
use qid_session::browser::{decode_cached_session, session_cache_put};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

const CAPPORT_CONTROL_CAPABILITY: &str = "captive_portal";
const CAPPORT_CONTROL_CAPABILITY_ALIAS: &str = "capport";

/// RFC 8908 §4.1 captive-portal API response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptivePortalApiResponse {
    /// RFC 8908 §4.1.1: `true` when the requesting client is operating from
    /// inside a captive portal. When `false` the other fields MAY be omitted
    /// or returned as `null`.
    pub captive: bool,
    /// RFC 8908 §4.1.2: URL the user should be redirected to in order to
    /// satisfy the portal's terms. Omitted when `captive` is `false`.
    #[serde(rename = "user-portal-url", skip_serializing_if = "Option::is_none")]
    pub user_portal_url: Option<String>,
    /// RFC 8908 §4.1.3: URL that human operators can visit to learn more
    /// about the venue that is operating the captive portal.
    #[serde(rename = "venue-info-url", skip_serializing_if = "Option::is_none")]
    pub venue_info_url: Option<String>,
    /// RFC 8908 §4.1.4: seconds remaining until the current grant of
    /// network access expires. Omitted when the portal does not enforce
    /// a time limit.
    #[serde(rename = "seconds-remaining", skip_serializing_if = "Option::is_none")]
    pub seconds_remaining: Option<u64>,
}

/// A binding between a src_ip, a session, and optionally a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptivePortalBinding {
    pub realm_id: String,
    pub src_ip: String,
    pub user_id: String,
    pub session_id: String,
    pub device_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

static CAPTIVE_PORTAL_BINDINGS: std::sync::LazyLock<Mutex<HashMap<String, CaptivePortalBinding>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn binding_key(realm_id: &str, src_ip: &str) -> String {
    format!("{}:{}", realm_id, src_ip)
}

pub fn set_binding(binding: CaptivePortalBinding) {
    let key = binding_key(&binding.realm_id, &binding.src_ip);
    let mut store = CAPTIVE_PORTAL_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    store.insert(key, binding);
    cleanup_expired_bindings_internal(&mut store);
}

pub fn get_binding(realm_id: &str, src_ip: &str) -> Option<CaptivePortalBinding> {
    let key = binding_key(realm_id, src_ip);
    let mut store = CAPTIVE_PORTAL_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    cleanup_expired_bindings_internal(&mut store);
    let binding = store.get(&key)?;
    if now_seconds() > binding.expires_at {
        store.remove(&key);
        return None;
    }
    Some(binding.clone())
}

pub fn remove_binding(realm_id: &str, src_ip: &str) {
    let key = binding_key(realm_id, src_ip);
    let mut store = CAPTIVE_PORTAL_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    store.remove(&key);
}

pub fn remove_bindings_for_session(realm_id: &str, session_id: &str) -> usize {
    let mut store = CAPTIVE_PORTAL_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let before = store.len();
    store.retain(|_, b| b.realm_id != realm_id || b.session_id != session_id);
    before - store.len()
}

fn cleanup_expired_bindings_internal(store: &mut HashMap<String, CaptivePortalBinding>) {
    let now = now_seconds();
    store.retain(|_, b| b.expires_at > now);
}

pub fn cleanup_expired_bindings() -> usize {
    let mut store = CAPTIVE_PORTAL_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let before = store.len();
    cleanup_expired_bindings_internal(&mut store);
    before - store.len()
}

#[derive(Debug, Deserialize)]
struct BindRequest {
    src_ip: String,
    session_id: String,
    device_id: Option<String>,
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BindResponse {
    status: String,
    src_ip: String,
    user_id: String,
    session_id: String,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    src_ip: String,
}

pub fn captive_portal_routes<R: Repository>(_paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            "/api/v1/:realm/captive-portal/bind",
            post(captive_portal_bind::<R>),
        )
        .route(
            "/api/v1/:realm/captive-portal/unbind",
            post(captive_portal_unbind::<R>),
        )
        .route(
            "/api/v1/:realm/captive-portal/lookup",
            get(captive_portal_lookup::<R>),
        )
        // RFC 8908 §4.1 CAPPORT API path.
        .route(
            "/api/v1/:realm/captive-portal/api/v1/details",
            get(captive_portal_details::<R>),
        )
}

async fn captive_portal_bind<R: Repository>(
    Path(realm): Path<String>,
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<BindRequest>,
) -> Response {
    if let Err(error) = authenticate_capport_control_adapter(&headers, &state, &realm) {
        return qid_http::error_response(error);
    }
    let _realm_config = match state.realm(&realm) {
        Some(cfg) => cfg,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let session = match state.session_cache_get(&req.session_id) {
        Some(cached) => match decode_cached_session(&cached, now_seconds()) {
            Ok(Some(s)) => s,
            _ => {
                return qid_http::error_response(QidError::NotFound {
                    resource: format!("session {}", req.session_id),
                });
            }
        },
        None => match state.repo.get_session(&req.session_id).await {
            Ok(Some(s)) => {
                let now = now_seconds();
                if let Ok(Some(cache_put)) = session_cache_put(&s, now) {
                    state.session_cache_put(
                        req.session_id.clone(),
                        cache_put.value,
                        cache_put.ttl_seconds,
                    );
                }
                s
            }
            Ok(None) => {
                return qid_http::error_response(QidError::NotFound {
                    resource: format!("session {}", req.session_id),
                });
            }
            Err(e) => return qid_http::error_response(e),
        },
    };

    let now = now_seconds();
    let ttl = req.ttl_seconds.unwrap_or(3600).min(86400);
    let binding = CaptivePortalBinding {
        realm_id: realm,
        src_ip: req.src_ip.clone(),
        user_id: session.user_id.clone(),
        session_id: session.id.clone(),
        device_id: req.device_id,
        created_at: now,
        expires_at: now + ttl,
    };

    set_binding(binding);

    Json(BindResponse {
        status: "bound".to_string(),
        src_ip: req.src_ip,
        user_id: session.user_id,
        session_id: session.id,
        expires_at: now + ttl,
    })
    .into_response()
}

#[allow(clippy::extra_unused_type_parameters)]
async fn captive_portal_unbind<R: Repository>(
    Path(realm): Path<String>,
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if let Err(error) = authenticate_capport_control_adapter(&headers, &state, &realm) {
        return qid_http::error_response(error);
    }
    let src_ip = req.get("src_ip").and_then(|v| v.as_str()).unwrap_or("");
    if src_ip.is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "src_ip required".to_string(),
        });
    }

    let session_id = req.get("session_id").and_then(|v| v.as_str());
    if let Some(sid) = session_id {
        let removed = remove_bindings_for_session(&realm, sid);
        let msg = if removed > 0 {
            "unbound"
        } else {
            "no_binding_found"
        };
        return Json(serde_json::json!({"status": msg, "removed": removed})).into_response();
    }

    remove_binding(&realm, src_ip);
    Json(serde_json::json!({"status": "unbound", "src_ip": src_ip})).into_response()
}

#[allow(clippy::extra_unused_type_parameters)]
async fn captive_portal_lookup<R: Repository>(
    Path(realm): Path<String>,
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<LookupQuery>,
) -> Response {
    if let Err(error) = authenticate_capport_control_adapter(&headers, &state, &realm) {
        return qid_http::error_response(error);
    }
    match get_binding(&realm, &query.src_ip) {
        Some(binding) => Json(serde_json::json!({
            "status": "bound",
            "realm_id": binding.realm_id,
            "src_ip": binding.src_ip,
            "user_id": binding.user_id,
            "session_id": binding.session_id,
            "device_id": binding.device_id,
            "created_at": binding.created_at,
            "expires_at": binding.expires_at,
        }))
        .into_response(),
        None => Json(serde_json::json!({
            "status": "not_bound",
            "src_ip": query.src_ip,
        }))
        .into_response(),
    }
}

fn authenticate_capport_control_adapter<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
) -> QidResult<()> {
    let token = qid_oauth::endpoints::extract_bearer_token(headers)?;
    let realm = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::Unauthorized {
            message: "CAPPORT control realm is not configured".to_string(),
        })?;

    let mut authenticated = false;
    for adapter in &realm.pep_registrations.registrations {
        if !adapter.capabilities.iter().any(|capability| {
            capability.effect == CAPPORT_CONTROL_CAPABILITY
                || capability.effect == CAPPORT_CONTROL_CAPABILITY_ALIAS
        }) {
            continue;
        }
        let Some(audience) = adapter.audience.as_deref() else {
            continue;
        };
        let Ok(decoded) = state.signer.decode_with_aud(token, audience) else {
            continue;
        };
        if decoded.claims.sub.as_deref() != Some(adapter.name.as_str()) {
            continue;
        }
        if let Some(claim_realm) = decoded
            .claims
            .extra
            .get("realm_id")
            .and_then(serde_json::Value::as_str)
            && claim_realm != realm.id
        {
            continue;
        }
        authenticated = true;
        break;
    }

    if authenticated {
        Ok(())
    } else {
        Err(QidError::Unauthorized {
            message: "CAPPORT control requires an authenticated PEP adapter with captive_portal capability".to_string(),
        })
    }
}

/// RFC 8908 §4.1 CAPPORT API handler.
async fn captive_portal_details<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
) -> Response {
    if state.realm(&realm).is_none() {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("realm {}", realm),
        });
    }
    let body = CaptivePortalApiResponse {
        captive: false,
        user_portal_url: None,
        venue_info_url: Some(format!(
            "{}/api/v1/{}/captive-portal/venue",
            state.plan.public_base_url.trim_end_matches('/'),
            realm
        )),
        seconds_remaining: None,
    };
    let mut response = Json(body).into_response();
    // The `Cache-Control` header on CAPPORT responses must forbid
    // shared caching to avoid leaking session state across users.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}
