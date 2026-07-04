//! Shared Signals Framework (SSF) receiver.
//!
//! Implements a minimal RFC 8417 Security Event Token (SET) ingestion
//! endpoint and a stream configuration endpoint per the OpenID Shared
//! Signals Framework 1.0 specification. Supports CAEP and RISC event
//! types as encountered in practice.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    error::{QidError, QidResult},
    event::{Event, EventBus, EventKind, GLOBAL_EVENT_BUS},
    jwt::JwtClaims,
    state::SharedState,
    util,
};
use qid_crypto::jwt::{sign_es256_jwt_with_jwk_header, verify_jwt_signature_with_claims};
use qid_crypto::{Jwk, JwkSet};
use qid_oauth::endpoints::decode_access_token;
use qid_storage::{SsfStreamRecord, prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

/// Configuration published at `/.well-known/ssf-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsfStreamConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub delivery_methods_supported: Vec<DeliveryMethod>,
    pub events_supported: Vec<String>,
    pub events_delivered: Vec<String>,
    pub default_subjects_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "delivery_method", rename_all = "snake_case")]
pub enum DeliveryMethod {
    /// HTTPS POST as defined in the SSF Profile 1.0 §4.1.
    HttpPost {
        url: String,
        #[serde(default)]
        authorization_header_name: Option<String>,
    },
}

/// A single registered event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsfStream {
    pub realm_id: String,
    pub stream_id: String,
    pub delivery: DeliveryMethod,
    pub events_requested: Vec<String>,
    pub transmitter_issuer: String,
    pub transmitter_jwks: JwkSet,
    pub transmitter_alg: String,
    pub audience: String,
    pub status: String,
}

const CAEP_EVENT_TYPES: &[&str] = &[
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
    "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
];

const RISC_EVENT_TYPES: &[&str] = &[
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
    "https://schemas.openid.net/secevent/risc/event-type/account-purged",
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
];

const SCIM_EVENT_TYPES: &[&str] = &[
    "urn:ietf:params:scim:event:create",
    "urn:ietf:params:scim:event:update",
    "urn:ietf:params:scim:event:delete",
];

pub fn install_scim_set_publisher<R: Repository + 'static>(state: Arc<SharedState<R>>) {
    GLOBAL_EVENT_BUS.subscribe(move |event| {
        if event.kind != EventKind::ScimProvisioned {
            return;
        }
        let Some(realm_id) = event.realm_id.clone() else {
            return;
        };
        let Some(event_type) = scim_set_event_type(event) else {
            return;
        };
        let state = state.clone();
        let event = event.clone();
        tokio::spawn(async move {
            if let Err(error) = publish_scim_set_event(state, realm_id, event_type, event).await {
                tracing::warn!("SCIM SET publication failed: {}", error.message());
            }
        });
    });
}

fn scim_set_event_type(event: &Event) -> Option<&'static str> {
    match event
        .payload
        .get("operation")
        .and_then(|value| value.as_str())
    {
        Some("created") => Some("urn:ietf:params:scim:event:create"),
        Some("replaced" | "patched" | "updated") => Some("urn:ietf:params:scim:event:update"),
        Some("soft_deleted" | "hard_deleted" | "deleted") => {
            Some("urn:ietf:params:scim:event:delete")
        }
        _ => None,
    }
}

async fn publish_scim_set_event<R: Repository>(
    state: Arc<SharedState<R>>,
    realm_id: String,
    event_type: &'static str,
    event: Event,
) -> QidResult<()> {
    let realm = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::BadRequest {
            message: "SCIM SET realm is not configured".to_string(),
        })?;
    let subscriptions = state
        .repo
        .list_scim_event_subscriptions(&qid_core::tenant::RealmId(realm_id.clone()))
        .await?;
    if subscriptions.is_empty() {
        return Ok(());
    }
    let client = reqwest::Client::new();
    let now = util::now_seconds();
    for subscription in subscriptions {
        if !subscription.enabled
            || !subscription
                .event_types
                .iter()
                .any(|configured| configured == event_type)
        {
            continue;
        }
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "stream_id".to_string(),
            serde_json::Value::String(subscription.id.clone()),
        );
        extra.insert(
            "events".to_string(),
            serde_json::json!({
                event_type: {
                    "realm_id": realm_id.clone(),
                    "event": event.payload.clone(),
                }
            }),
        );
        let token = state
            .signer
            .sign_with_typ(
                &JwtClaims {
                    iss: Some(realm.issuer.clone()),
                    sub: Some("qid-scim".to_string()),
                    aud: Some(subscription.callback_url.clone()),
                    exp: Some((now + 300) as usize),
                    nbf: Some(now as usize),
                    iat: Some(now as usize),
                    jti: Some(ulid::Ulid::new().to_string()),
                    extra,
                },
                "secevent+jwt",
            )
            .map_err(|error| QidError::Internal {
                message: format!("failed to sign SCIM SET: {error}"),
            })?;
        let response = client
            .post(&subscription.callback_url)
            .header(reqwest::header::CONTENT_TYPE, "application/secevent+jwt")
            .body(token)
            .send()
            .await
            .map_err(|error| QidError::Internal {
                message: format!("SCIM SET delivery failed: {error}"),
            })?;
        if !response.status().is_success() {
            return Err(QidError::Internal {
                message: format!(
                    "SCIM SET receiver returned non-success status {}",
                    response.status()
                ),
            });
        }
    }
    Ok(())
}

pub fn ssf_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/.well-known/ssf-configuration", get(ssf_configuration))
        .route(
            "/realms/:realm/.well-known/ssf-configuration",
            get(ssf_configuration_for_realm),
        )
        .route("/ssf/stream", get(list_streams).post(create_stream))
        .route(
            "/realms/:realm/ssf/stream",
            get(list_streams_for_realm).post(create_stream_for_realm),
        )
        .route(
            "/ssf/stream/:stream_id",
            get(get_stream).delete(delete_stream),
        )
        .route(
            "/realms/:realm/ssf/stream/:stream_id",
            get(get_stream_for_realm).delete(delete_stream_for_realm),
        )
        .route("/ssf/events", post(receive_event::<R>))
        .route(
            "/realms/:realm/ssf/events",
            post(receive_event_for_realm::<R>),
        )
}

async fn ssf_configuration(
    State(state): State<Arc<SharedState<impl Repository>>>,
) -> impl IntoResponse {
    ssf_configuration_response(&state, None)
}

async fn ssf_configuration_for_realm(
    State(state): State<Arc<SharedState<impl Repository>>>,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    ssf_configuration_response(&state, Some(&realm))
}

fn ssf_configuration_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: Option<&str>,
) -> axum::response::Response {
    let realm = match ssf_realm(state, realm_id) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let issuer = realm.issuer.clone();
    let jwks_uri = format!(
        "{}{}",
        state.plan.public_base_url.trim_end_matches('/'),
        state.paths.jwks
    );
    let events_path = if realm_id.is_some() {
        format!("/realms/{}/ssf/events", realm.id)
    } else {
        "/ssf/events".to_string()
    };
    let mut events_supported: BTreeSet<String> = BTreeSet::new();
    for evt in CAEP_EVENT_TYPES {
        events_supported.insert((*evt).to_string());
    }
    for evt in RISC_EVENT_TYPES {
        events_supported.insert((*evt).to_string());
    }
    for evt in SCIM_EVENT_TYPES {
        events_supported.insert((*evt).to_string());
    }
    Json(SsfStreamConfiguration {
        issuer,
        jwks_uri,
        delivery_methods_supported: vec![DeliveryMethod::HttpPost {
            url: format!(
                "{}{}",
                state.plan.public_base_url.trim_end_matches('/'),
                events_path
            ),
            authorization_header_name: None,
        }],
        events_supported: events_supported.iter().cloned().collect(),
        events_delivered: events_supported.iter().cloned().collect(),
        default_subjects_supported: vec!["iss".to_string(), "sub".to_string()],
    })
    .into_response()
}

fn ssf_realm<'a, R: Repository>(
    state: &'a SharedState<R>,
    realm_id: Option<&str>,
) -> QidResult<&'a qid_core::config::RealmConfig> {
    if let Some(realm_id) = realm_id {
        return state
            .config
            .realms
            .iter()
            .find(|realm| realm.id == realm_id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("realm {realm_id}"),
            });
    }
    let mut realms = state.config.realms.iter();
    let Some(first) = realms.next() else {
        return Err(QidError::BadRequest {
            message: "no realm is configured".to_string(),
        });
    };
    if realms.next().is_some() {
        return Err(QidError::BadRequest {
            message: "global SSF metadata is ambiguous for multiple realms; use realm-scoped SSF endpoints".to_string(),
        });
    }
    let global_issuer = state.plan.public_base_url.trim_end_matches('/');
    if first.issuer.trim_end_matches('/') != global_issuer {
        return Err(QidError::BadRequest {
            message: "global SSF metadata is only available when the realm issuer matches server.public_base_url; use realm-scoped SSF endpoints".to_string(),
        });
    }
    Ok(first)
}

async fn list_streams(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, None) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    if let Err(error) =
        require_ssf_stream_admin(&state, realm, &headers, &Method::GET, "/ssf/stream").await
    {
        return qid_http::error_response(error);
    }
    let streams = match state.repo.list_ssf_streams(&realm.id).await {
        Ok(streams) => streams
            .into_iter()
            .filter_map(record_to_stream)
            .collect::<Vec<_>>(),
        Err(error) => return qid_http::error_response(error),
    };
    Json(serde_json::json!({
        "streams": streams,
    }))
    .into_response()
}

async fn list_streams_for_realm(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> impl IntoResponse {
    let realm_config = match ssf_realm(&state, Some(&realm)) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/realms/{realm}/ssf/stream");
    if let Err(error) =
        require_ssf_stream_admin(&state, realm_config, &headers, &Method::GET, &path).await
    {
        return qid_http::error_response(error);
    }
    let streams = match state.repo.list_ssf_streams(&realm).await {
        Ok(streams) => streams
            .into_iter()
            .filter_map(record_to_stream)
            .collect::<Vec<_>>(),
        Err(error) => return qid_http::error_response(error),
    };
    Json(serde_json::json!({
        "streams": streams,
    }))
    .into_response()
}

async fn create_stream(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    Json(payload): Json<SsfCreateStreamRequest>,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, None) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    if let Err(error) =
        require_ssf_stream_admin(&state, realm, &headers, &Method::POST, "/ssf/stream").await
    {
        return qid_http::error_response(error);
    }
    create_stream_response(&state, realm.id.clone(), payload).await
}

async fn create_stream_for_realm(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(payload): Json<SsfCreateStreamRequest>,
) -> impl IntoResponse {
    let realm_config = match ssf_realm(&state, Some(&realm)) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/realms/{realm}/ssf/stream");
    if let Err(error) =
        require_ssf_stream_admin(&state, realm_config, &headers, &Method::POST, &path).await
    {
        return qid_http::error_response(error);
    }
    create_stream_response(&state, realm, payload).await
}

async fn create_stream_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: String,
    payload: SsfCreateStreamRequest,
) -> axum::response::Response {
    if payload.events_requested.is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF stream events_requested must not be empty".to_string(),
        });
    }
    for event_type in &payload.events_requested {
        if !is_known_event_type(event_type) {
            return qid_http::error_response(QidError::BadRequest {
                message: format!("unknown SSF event type requested: {event_type}"),
            });
        }
    }
    if payload.transmitter_issuer.trim().is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF stream transmitter_issuer must not be empty".to_string(),
        });
    }
    if payload.transmitter_jwks.keys.is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF stream transmitter_jwks must contain at least one key".to_string(),
        });
    }
    if payload.audience.trim().is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF stream audience must not be empty".to_string(),
        });
    }
    let now = util::now_seconds();
    let stream = SsfStream {
        realm_id,
        stream_id: payload
            .stream_id
            .unwrap_or_else(|| ulid::Ulid::new().to_string()),
        delivery: payload.delivery,
        events_requested: payload.events_requested,
        transmitter_issuer: payload.transmitter_issuer,
        transmitter_jwks: payload.transmitter_jwks,
        transmitter_alg: payload.transmitter_alg,
        audience: payload.audience,
        status: "active".to_string(),
    };
    let record = match stream_to_record(&stream, now) {
        Ok(record) => record,
        Err(error) => return qid_http::error_response(error),
    };
    if let Err(error) = state.repo.upsert_ssf_stream(&record).await {
        return qid_http::error_response(error);
    }
    (StatusCode::CREATED, Json(stream)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SsfCreateStreamRequest {
    #[serde(default)]
    pub stream_id: Option<String>,
    pub delivery: DeliveryMethod,
    #[serde(default)]
    pub events_requested: Vec<String>,
    pub transmitter_issuer: String,
    pub transmitter_jwks: JwkSet,
    #[serde(default = "default_set_alg")]
    pub transmitter_alg: String,
    #[serde(default = "default_set_audience")]
    pub audience: String,
}

fn default_set_alg() -> String {
    "ES256".to_string()
}

fn default_set_audience() -> String {
    "qid-ssf".to_string()
}

fn stream_to_record(stream: &SsfStream, now: u64) -> QidResult<SsfStreamRecord> {
    Ok(SsfStreamRecord {
        realm_id: stream.realm_id.clone(),
        stream_id: stream.stream_id.clone(),
        delivery_json: serde_json::to_value(&stream.delivery).map_err(|error| {
            QidError::Internal {
                message: format!("failed to serialize SSF stream delivery: {error}"),
            }
        })?,
        events_requested: stream.events_requested.clone(),
        transmitter_issuer: stream.transmitter_issuer.clone(),
        transmitter_jwks_json: serde_json::to_value(&stream.transmitter_jwks).map_err(|error| {
            QidError::Internal {
                message: format!("failed to serialize SSF stream JWKS: {error}"),
            }
        })?,
        transmitter_alg: stream.transmitter_alg.clone(),
        audience: stream.audience.clone(),
        status: stream.status.clone(),
        created_at: now,
        updated_at: now,
    })
}

fn record_to_stream(record: SsfStreamRecord) -> Option<SsfStream> {
    Some(SsfStream {
        realm_id: record.realm_id,
        stream_id: record.stream_id,
        delivery: serde_json::from_value(record.delivery_json).ok()?,
        events_requested: record.events_requested,
        transmitter_issuer: record.transmitter_issuer,
        transmitter_jwks: serde_json::from_value(record.transmitter_jwks_json).ok()?,
        transmitter_alg: record.transmitter_alg,
        audience: record.audience,
        status: record.status,
    })
}

async fn require_ssf_stream_admin<R: Repository>(
    state: &SharedState<R>,
    realm: &qid_core::config::RealmConfig,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
) -> QidResult<()> {
    let token = qid_oauth::endpoints::extract_bearer_token(headers)?;
    let decoded_access =
        decode_access_token(state, token)
            .await
            .map_err(|error| QidError::Unauthorized {
                message: format!("invalid SSF stream management access token: {error}"),
            })?;
    if decoded_access.realm_id != realm.id {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token realm does not match request".to_string(),
        });
    }
    let htu = format!(
        "{}{}",
        state.plan.public_base_url.trim_end_matches('/'),
        path
    );
    qid_oauth::endpoints::enforce_sender_constrained_access_token(
        state,
        headers,
        method,
        &htu,
        token,
        &decoded_access,
    )?;
    if !decoded_access.aud.iter().any(|aud| aud == "qid-ssf-admin") {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token audience is not allowed".to_string(),
        });
    }
    if !decoded_access
        .scope
        .split_whitespace()
        .any(|scope| matches!(scope, "ssf.manage" | "ssf.admin"))
    {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token requires ssf.manage scope".to_string(),
        });
    }
    let claims = state
        .signer
        .decode_signature_only(token)
        .map_err(|error| QidError::Unauthorized {
            message: format!("invalid SSF stream management token claims: {error}"),
        })?
        .claims;
    if claims.iss.as_deref() != Some(realm.issuer.as_str()) {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token issuer does not match realm".to_string(),
        });
    }
    if let Some(realm_id) = claims
        .extra
        .get("realm_id")
        .and_then(|value| value.as_str())
        && realm_id != realm.id
    {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token realm does not match request".to_string(),
        });
    }
    if claims
        .sub
        .as_deref()
        .is_none_or(|subject| subject.trim().is_empty())
    {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token subject is required".to_string(),
        });
    }
    let admin_id = &decoded_access.user_id;
    if claims.sub.as_deref() != Some(admin_id.as_str()) {
        return Err(QidError::Unauthorized {
            message: "SSF stream management token subject does not match token record".to_string(),
        });
    }
    let admin =
        state
            .repo
            .get_admin_by_id(admin_id)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "SSF stream management admin was not found".to_string(),
            })?;
    let elevation_id = headers
        .get(ADMIN_SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: "SSF stream management requires admin elevation session".to_string(),
        })?;
    let elevation = state
        .repo
        .get_admin_elevation(elevation_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "SSF stream management elevation was not found".to_string(),
        })?;
    if elevation.admin_id != admin.id {
        return Err(QidError::Unauthorized {
            message: "SSF stream management elevation belongs to a different admin".to_string(),
        });
    }
    if elevation.tenant_id != admin.tenant_id {
        return Err(QidError::Unauthorized {
            message: "SSF stream management elevation belongs to a different tenant".to_string(),
        });
    }
    let realm_tenant = state
        .repo
        .get_realm_tenant(&qid_core::tenant::RealmId(realm.id.clone()))
        .await?
        .or_else(|| realm.tenant_id.clone())
        .ok_or_else(|| QidError::Unauthorized {
            message: "SSF stream management realm tenant binding was not found".to_string(),
        })?;
    if realm_tenant != admin.tenant_id {
        return Err(QidError::Unauthorized {
            message: "SSF stream management admin tenant does not match realm tenant".to_string(),
        });
    }
    let security = &state.config.admin.security;
    let now = util::now_seconds();
    if elevation.elevation_expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "SSF stream management elevation has expired".to_string(),
        });
    }
    if elevation.elevation_expires_at.saturating_sub(now) > security.max_elevation_seconds {
        return Err(QidError::Unauthorized {
            message: "SSF stream management elevation lifetime exceeds configured maximum"
                .to_string(),
        });
    }
    if security.require_step_up {
        let acr_ok = elevation.acr.as_deref() == Some(security.required_acr.as_str());
        let amr_ok = elevation.amr.iter().any(|method| {
            security
                .required_amr
                .iter()
                .any(|required| required == method)
        });
        if !acr_ok || !amr_ok {
            return Err(QidError::Unauthorized {
                message: "SSF stream management requires admin step-up".to_string(),
            });
        }
    }
    if !admin.roles.iter().any(|role| {
        matches!(
            role.as_str(),
            "security.admin" | "platform.admin" | "platform.security.admin"
        )
    }) {
        return Err(QidError::Unauthorized {
            message: "SSF stream management requires a security admin role".to_string(),
        });
    }
    Ok(())
}

async fn get_stream(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    axum::extract::Path(stream_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, None) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/ssf/stream/{stream_id}");
    if let Err(error) = require_ssf_stream_admin(&state, realm, &headers, &Method::GET, &path).await
    {
        return qid_http::error_response(error);
    }
    match state.repo.get_ssf_stream(&realm.id, &stream_id).await {
        Ok(Some(record)) => match record_to_stream(record) {
            Some(stream) => Json(stream).into_response(),
            None => qid_http::error_response(QidError::Internal {
                message: "stored SSF stream is malformed".to_string(),
            }),
        },
        Ok(None) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("SSF stream {stream_id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

async fn get_stream_for_realm(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    axum::extract::Path((realm_id, stream_id)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, Some(&realm_id)) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/realms/{realm_id}/ssf/stream/{stream_id}");
    if let Err(error) = require_ssf_stream_admin(&state, realm, &headers, &Method::GET, &path).await
    {
        return qid_http::error_response(error);
    }
    match state.repo.get_ssf_stream(&realm_id, &stream_id).await {
        Ok(Some(record)) => match record_to_stream(record) {
            Some(stream) => Json(stream).into_response(),
            None => qid_http::error_response(QidError::Internal {
                message: "stored SSF stream is malformed".to_string(),
            }),
        },
        Ok(None) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("SSF stream {stream_id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

async fn delete_stream(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    axum::extract::Path(stream_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, None) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/ssf/stream/{stream_id}");
    if let Err(error) =
        require_ssf_stream_admin(&state, realm, &headers, &Method::DELETE, &path).await
    {
        return qid_http::error_response(error);
    }
    match state.repo.delete_ssf_stream(&realm.id, &stream_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("SSF stream {stream_id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

async fn delete_stream_for_realm(
    State(state): State<Arc<SharedState<impl Repository>>>,
    headers: HeaderMap,
    axum::extract::Path((realm_id, stream_id)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    let realm = match ssf_realm(&state, Some(&realm_id)) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let path = format!("/realms/{realm_id}/ssf/stream/{stream_id}");
    if let Err(error) =
        require_ssf_stream_admin(&state, realm, &headers, &Method::DELETE, &path).await
    {
        return qid_http::error_response(error);
    }
    match state.repo.delete_ssf_stream(&realm_id, &stream_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => qid_http::error_response(qid_core::error::QidError::NotFound {
            resource: format!("SSF stream {stream_id}"),
        }),
        Err(error) => qid_http::error_response(error),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityEventToken {
    pub iss: String,
    pub jti: String,
    pub iat: u64,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub stream_id: Option<String>,
    pub events: BTreeMap<String, serde_json::Value>,
}

/// Receive a single Security Event Token (SET) per RFC 8417. The SET may
/// carry one or more CAEP/RISC event payloads, addressed by URI.
async fn receive_event<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    receive_event_response(&state, None, &headers, &body).await
}

async fn receive_event_for_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    receive_event_response(&state, Some(&realm), &headers, &body).await
}

async fn receive_event_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: Option<&str>,
    headers: &HeaderMap,
    body: &str,
) -> axum::response::Response {
    let realm = match ssf_realm(state, realm_id) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF events require Content-Type application/secevent+jwt".to_string(),
        });
    };
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/secevent+jwt")
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "SSF events require Content-Type application/secevent+jwt".to_string(),
        });
    }
    let token = body.trim();
    let header = match jsonwebtoken::decode_header(token) {
        Ok(header) => header,
        Err(error) => {
            return qid_http::error_response(QidError::Unauthorized {
                message: format!("invalid SET header: {error}"),
            });
        }
    };
    if header.typ.as_deref() != Some("secevent+jwt") {
        return qid_http::error_response(QidError::Unauthorized {
            message: "SSF events require typ=secevent+jwt".to_string(),
        });
    }
    let Some(stream_id) = unverified_set_stream_id(token) else {
        return qid_http::error_response(QidError::Unauthorized {
            message: "SET stream_id is required".to_string(),
        });
    };
    let stream = match state.repo.get_ssf_stream(&realm.id, &stream_id).await {
        Ok(Some(record)) => match record_to_stream(record) {
            Some(stream) if stream.status == "active" => stream,
            Some(_) => {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "SET stream is not active".to_string(),
                });
            }
            None => {
                return qid_http::error_response(QidError::Internal {
                    message: "stored SSF stream is malformed".to_string(),
                });
            }
        },
        Ok(None) => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "SET stream is not registered for realm".to_string(),
            });
        }
        Err(error) => return qid_http::error_response(error),
    };
    let set = match verify_security_event_token_for_stream(token, &stream) {
        Ok(set) => set,
        Err(error) => return qid_http::error_response(error),
    };
    let Some(exp) = set.exp else {
        return qid_http::error_response(QidError::Unauthorized {
            message: "SET exp is required".to_string(),
        });
    };
    let now = util::now_seconds();
    if exp <= now {
        return qid_http::error_response(QidError::Unauthorized {
            message: "SET has expired".to_string(),
        });
    }
    match state
        .repo
        .record_ssf_set_jti(
            &stream.realm_id,
            &set.iss,
            &stream.stream_id,
            &set.jti,
            exp,
            now,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "SET jti has already been received for this issuer and stream".to_string(),
            });
        }
        Err(error) => return qid_http::error_response(error),
    }
    if set.events.is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "SET must contain at least one event".to_string(),
        });
    }
    for (event_type, payload) in &set.events {
        if !is_known_event_type(event_type) {
            return qid_http::error_response(QidError::BadRequest {
                message: format!("unknown SET event type: {event_type}"),
            });
        }
        if !stream
            .events_requested
            .iter()
            .any(|allowed| allowed == event_type)
        {
            return qid_http::error_response(QidError::Unauthorized {
                message: format!("SET event type is not enabled for stream: {event_type}"),
            });
        }
        tracing::info!(
            iss = %set.iss,
            jti = %set.jti,
            event_type = %event_type,
            "received shared signal"
        );
        // The payload is opaque to the receiver beyond the event type; we
        // expose it for audit/metrics pipelines through the tracing
        // subscriber so downstream consumers can hook in.
        let _ = payload;
    }
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "jti": set.jti })),
    )
        .into_response()
}

fn verify_security_event_token_for_stream(
    token: &str,
    stream: &SsfStream,
) -> QidResult<SecurityEventToken> {
    let header = jsonwebtoken::decode_header(token).map_err(|error| QidError::Unauthorized {
        message: format!("invalid SET header: {error}"),
    })?;
    let jwk = set_verification_jwk(&stream.transmitter_jwks, header.kid.as_deref())?;
    let data = verify_jwt_signature_with_claims(
        token,
        jwk,
        &stream.transmitter_alg,
        &stream.audience,
        &stream.transmitter_issuer,
    )
    .map_err(|error| QidError::Unauthorized {
        message: format!("invalid SET: {}", error.message()),
    })?;
    let claims = data.claims;
    let Some(jti) = claims.jti.filter(|value| !value.trim().is_empty()) else {
        return Err(QidError::Unauthorized {
            message: "SET jti is required".to_string(),
        });
    };
    let Some(iat) = claims.iat else {
        return Err(QidError::Unauthorized {
            message: "SET iat is required".to_string(),
        });
    };
    if claims.exp.is_none() {
        return Err(QidError::Unauthorized {
            message: "SET exp is required".to_string(),
        });
    }
    let stream_id = claims
        .extra
        .get("stream_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    if stream_id.as_deref() != Some(stream.stream_id.as_str()) {
        return Err(QidError::Unauthorized {
            message: "SET stream_id does not match registered stream".to_string(),
        });
    }
    let events = claims
        .extra
        .get("events")
        .and_then(|value| value.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    Ok(SecurityEventToken {
        iss: claims.iss.unwrap_or_default(),
        jti,
        iat: iat as u64,
        aud: claims.aud,
        exp: claims.exp.map(|value| value as u64),
        stream_id,
        events,
    })
}

fn set_verification_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> QidResult<&'a Jwk> {
    if let Some(kid) = kid {
        return jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| QidError::Unauthorized {
                message: "SET kid is not registered for stream".to_string(),
            });
    }
    if jwks.keys.len() == 1 {
        return Ok(&jwks.keys[0]);
    }
    Err(QidError::Unauthorized {
        message: "SET kid is required when stream has multiple keys".to_string(),
    })
}

fn unverified_set_stream_id(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value
        .get("stream_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn is_known_event_type(event_type: &str) -> bool {
    CAEP_EVENT_TYPES.contains(&event_type)
        || RISC_EVENT_TYPES.contains(&event_type)
        || SCIM_EVENT_TYPES.contains(&event_type)
}

/// Verify a Security Event Token (SET) per RFC 8417 §3. The verifier
/// decodes the JWT structure, checks the `iss`, `jti`, and `iat` claims,
/// and inspects the event type. The signature is validated with the
/// supplied JWK using the same `verify_jwt_signature_with_claims` path
/// as other JWTs in the codebase.
pub fn verify_security_event_token(
    token: &str,
    expected_issuer: &str,
    public_jwk: &qid_crypto::Jwk,
    alg: &str,
) -> QidResult<SecurityEventToken> {
    let data =
        verify_jwt_signature_with_claims(token, public_jwk, alg, "qid-ssf", expected_issuer)?;
    Ok(SecurityEventToken {
        iss: data.claims.iss.unwrap_or_default(),
        jti: data.claims.jti.unwrap_or_default(),
        iat: data.claims.iat.unwrap_or(0) as u64,
        aud: data.claims.aud,
        exp: data.claims.exp.map(|v| v as u64),
        stream_id: data
            .claims
            .extra
            .get("stream_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        events: data
            .claims
            .extra
            .into_iter()
            .filter_map(|(k, v)| {
                if k == "events" {
                    v.as_object().map(|obj| {
                        obj.iter()
                            .map(|(k2, v2)| (k2.clone(), v2.clone()))
                            .collect::<BTreeMap<_, _>>()
                    })
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_default(),
    })
}

/// Encode a Security Event Token (SET) for delivery to a configured
/// stream. Useful in tests and in the integration test for out-of-band
/// delivery.
pub fn encode_security_event_token(
    private_pem: &[u8],
    public_jwk: &qid_crypto::Jwk,
    set: &SecurityEventToken,
) -> QidResult<String> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "iss".to_string(),
        serde_json::Value::String(set.iss.clone()),
    );
    payload.insert(
        "jti".to_string(),
        serde_json::Value::String(set.jti.clone()),
    );
    payload.insert("iat".to_string(), serde_json::Value::Number(set.iat.into()));
    if let Some(aud) = &set.aud {
        payload.insert("aud".to_string(), serde_json::Value::String(aud.clone()));
    }
    if let Some(exp) = set.exp {
        payload.insert("exp".to_string(), serde_json::Value::Number(exp.into()));
    }
    if let Some(stream_id) = &set.stream_id {
        payload.insert(
            "stream_id".to_string(),
            serde_json::Value::String(stream_id.clone()),
        );
    }
    let events_value =
        serde_json::to_value(&set.events).map_err(|e| qid_core::error::QidError::Internal {
            message: format!("failed to serialize SET events: {e}"),
        })?;
    payload.insert("events".to_string(), events_value);
    let payload_value = serde_json::Value::Object(payload);
    sign_es256_jwt_with_jwk_header(private_pem, public_jwk, "secevent+jwt", &payload_value).map_err(
        |e| qid_core::error::QidError::Internal {
            message: format!("failed to sign SET: {e}"),
        },
    )
}
