//! qid-resource device module.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::error::QidError;
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use crate::session_auth;
use qid_core::models::Device;

//
// Device registry
//

#[derive(Debug, Deserialize)]
pub struct ListDevicesQuery {
    user_id: String,
}

pub async fn list_devices<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Query(query): Query<ListDevicesQuery>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &query.user_id).await {
        return e;
    }
    match state.repo.get_user_devices(&query.user_id).await {
        Ok(devices) => Json(serde_json::json!(devices)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    user_id: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

pub async fn register_device<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Response {
    if let Err(response) =
        session_auth::require_session(&headers, &state, &realm, &req.user_id).await
    {
        return response;
    }

    let now = qid_core::util::now_seconds();
    let device = Device {
        id: ulid::Ulid::new().to_string(),
        user_id: req.user_id,
        realm_id: realm,
        device_name: req.device_name,
        device_type: req.device_type.unwrap_or_else(|| "unknown".to_string()),
        posture: Vec::new(),
        registered_at: now,
        last_seen_at: now,
    };
    match state.repo.register_device(&device).await {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!(device))).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn device_heartbeat<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, device_id)): Path<(String, String)>,
) -> Response {
    // Look up the device to find its owner, then verify the session.
    let device = match state.repo.get_device(&device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("device {device_id}"),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if device.realm_id != realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("device {device_id}"),
        });
    }
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &device.user_id).await {
        return e;
    }
    let now = qid_core::util::now_seconds();
    match state.repo.update_device_last_seen(&device_id, now).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}
