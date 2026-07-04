use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use qid_core::{error::QidError, state::SharedState};
use qid_mfa::push::{
    PushChallenge, PushChallengeStatus, PushDevice, PushFatigueState, PushMfaConfig,
    create_push_challenge, generate_number_match_code, verify_push_response,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::browser::SessionManager;

/// In-memory state for push MFA.
#[derive(Debug)]
pub struct PushMfaState {
    pub devices: Mutex<Vec<PushDevice>>,
    pub challenges: Mutex<Vec<PushChallenge>>,
    pub fatigue: PushFatigueState,
}

impl PushMfaState {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(Vec::new()),
            challenges: Mutex::new(Vec::new()),
            fatigue: PushFatigueState::new(),
        }
    }
}

fn lock_push_state<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, QidError> {
    mutex.lock().map_err(|_| QidError::Internal {
        message: format!("push MFA {name} lock poisoned"),
    })
}

pub fn push_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            "/api/v1/:realm/auth/push/register",
            post(push_register::<R>),
        )
        .route(
            "/api/v1/:realm/auth/push/challenge",
            post(push_challenge::<R>),
        )
        .route("/api/v1/:realm/auth/push/verify", post(push_verify::<R>))
        .route(
            "/api/v1/:realm/auth/push/devices",
            get(push_list_devices::<R>),
        )
        .route(
            "/api/v1/:realm/auth/push/devices/:device_id",
            axum::routing::delete(push_remove_device::<R>),
        )
        .layer(Extension(Arc::new(PushMfaState::new())))
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=')
            && key.trim() == name
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

async fn get_session_user_id<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<String, Response> {
    let realm_config = state.realm(realm).ok_or_else(|| {
        qid_http::error_response(QidError::NotFound {
            resource: format!("realm {}", realm),
        })
    })?;
    let cookie_name = &realm_config.browser_session.cookie_name;
    let session_id = extract_cookie(headers, cookie_name).ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "missing session cookie".to_string(),
        })
    })?;
    let manager = SessionManager::new(
        state.repo.clone(),
        realm_config.browser_session.idle_timeout_minutes,
        realm_config.browser_session.absolute_timeout_hours,
    );
    let session = manager
        .get(&session_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            })
        })?;
    if session.realm_id != realm {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        }));
    }
    Ok(session.user_id)
}

#[derive(Debug, Deserialize)]
struct PushRegisterRequest {
    device_name: String,
    platform: String,
    push_token: String,
}

#[derive(Debug, Serialize)]
struct PushRegisterResponse {
    device_id: String,
    status: String,
}

async fn push_register<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Extension(push_state): Extension<Arc<PushMfaState>>,
    Json(req): Json<PushRegisterRequest>,
) -> Response {
    if req.device_name.trim().is_empty() || req.push_token.trim().is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "device_name and push_token must not be empty".to_string(),
        });
    }

    let user_id = match get_session_user_id(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let device_id = format!("push_dev_{:016x}", rand::random::<u64>());
    let device = PushDevice {
        id: device_id.clone(),
        user_id: user_id.clone(),
        device_name: req.device_name,
        platform: req.platform,
        push_token: req.push_token,
        created_at: now_seconds(),
        enabled: true,
    };

    {
        let mut devices = match lock_push_state(&push_state.devices, "devices") {
            Ok(devices) => devices,
            Err(e) => return qid_http::error_response(e),
        };
        devices.push(device);
    }

    metrics::counter!("qid_push_devices_registered_total").increment(1);
    (
        StatusCode::OK,
        Json(PushRegisterResponse {
            device_id,
            status: "registered".to_string(),
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct PushChallengeRequest {
    device_id: String,
    geo_display: Option<String>,
    requesting_device: Option<String>,
    requesting_ip: Option<String>,
}

#[derive(Debug, Serialize)]
struct PushChallengeResponse {
    challenge_id: String,
    status: String,
    resend_cooldown_seconds: u64,
}

async fn push_challenge<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Extension(push_state): Extension<Arc<PushMfaState>>,
    Json(req): Json<PushChallengeRequest>,
) -> Response {
    let user_id = match get_session_user_id(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let push_config = PushMfaConfig::default();

    // Fatigue detection
    let fatigued = match push_state.fatigue.check_and_record(&user_id, &push_config) {
        Ok(fatigued) => fatigued,
        Err(e) => return qid_http::error_response(e),
    };
    if fatigued {
        warn!("push fatigue detected for user {}", user_id);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many push requests, please wait".to_string(),
        });
    }

    // Find device
    let device = {
        let devices = match lock_push_state(&push_state.devices, "devices") {
            Ok(devices) => devices,
            Err(e) => return qid_http::error_response(e),
        };
        devices
            .iter()
            .find(|d| d.id == req.device_id && d.user_id == user_id && d.enabled)
            .cloned()
    };
    let device = match device {
        Some(d) => d,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: "push device".to_string(),
            });
        }
    };

    let challenge_id = format!("push_chal_{:016x}", rand::random::<u64>());
    let number_match_code = generate_number_match_code();
    let challenge = create_push_challenge(
        challenge_id.clone(),
        user_id.clone(),
        &device,
        number_match_code,
        req.geo_display,
        req.requesting_device,
        req.requesting_ip,
        &push_config,
    );

    {
        let mut challenges = match lock_push_state(&push_state.challenges, "challenges") {
            Ok(challenges) => challenges,
            Err(e) => return qid_http::error_response(e),
        };
        let now = now_seconds();
        for c in challenges.iter_mut() {
            if c.user_id == user_id
                && c.status == PushChallengeStatus::Pending
                && now > c.expires_at
            {
                c.status = PushChallengeStatus::Expired;
            }
        }
        challenges.push(challenge);
    }

    metrics::counter!("qid_mfa_challenges_total", "method" => "push").increment(1);
    metrics::counter!("qid_push_challenges_sent_total").increment(1);

    (
        StatusCode::OK,
        Json(PushChallengeResponse {
            challenge_id,
            status: "sent".to_string(),
            resend_cooldown_seconds: push_config.resend_cooldown_seconds,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct PushVerifyRequest {
    challenge_id: String,
    number_match_code: String,
}

#[derive(Debug, Serialize)]
struct PushVerifyResponse {
    status: String,
}

async fn push_verify<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Extension(push_state): Extension<Arc<PushMfaState>>,
    Json(req): Json<PushVerifyRequest>,
) -> Response {
    let user_id = match get_session_user_id(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut challenges = match lock_push_state(&push_state.challenges, "challenges") {
        Ok(challenges) => challenges,
        Err(e) => return qid_http::error_response(e),
    };
    let challenge = match challenges
        .iter_mut()
        .find(|c| c.id == req.challenge_id && c.user_id == user_id)
    {
        Some(c) => c,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: "push challenge".to_string(),
            });
        }
    };

    if !verify_push_response(challenge, &req.number_match_code) {
        challenge.status = PushChallengeStatus::Denied;
        metrics::counter!("qid_push_verification_failed_total").increment(1);
        return qid_http::error_response(QidError::Unauthorized {
            message: "incorrect number match code or challenge expired".to_string(),
        });
    }

    challenge.status = PushChallengeStatus::Approved;
    if let Err(e) = push_state.fatigue.clear(&user_id) {
        return qid_http::error_response(e);
    }
    metrics::counter!("qid_push_verification_succeeded_total").increment(1);

    (
        StatusCode::OK,
        Json(PushVerifyResponse {
            status: "approved".to_string(),
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct PushDeviceInfo {
    id: String,
    device_name: String,
    platform: String,
    created_at: u64,
    enabled: bool,
}

async fn push_list_devices<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Extension(push_state): Extension<Arc<PushMfaState>>,
) -> Response {
    let user_id = match get_session_user_id(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let devices = match lock_push_state(&push_state.devices, "devices") {
        Ok(devices) => devices,
        Err(e) => return qid_http::error_response(e),
    };
    let info: Vec<PushDeviceInfo> = devices
        .iter()
        .filter(|d| d.user_id == user_id)
        .map(|d| PushDeviceInfo {
            id: d.id.clone(),
            device_name: d.device_name.clone(),
            platform: d.platform.clone(),
            created_at: d.created_at,
            enabled: d.enabled,
        })
        .collect();

    (StatusCode::OK, Json(info)).into_response()
}

async fn push_remove_device<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, path)): Path<(String, String)>,
    headers: HeaderMap,
    Extension(push_state): Extension<Arc<PushMfaState>>,
) -> Response {
    let user_id = match get_session_user_id(&state, &realm, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    let device_id = path;
    let mut devices = match lock_push_state(&push_state.devices, "devices") {
        Ok(devices) => devices,
        Err(e) => return qid_http::error_response(e),
    };
    let pos = devices
        .iter()
        .position(|d| d.id == device_id && d.user_id == user_id);
    match pos {
        Some(idx) => {
            devices.remove(idx);
            metrics::counter!("qid_push_devices_removed_total").increment(1);
            StatusCode::NO_CONTENT.into_response()
        }
        None => qid_http::error_response(QidError::NotFound {
            resource: "push device".to_string(),
        }),
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
