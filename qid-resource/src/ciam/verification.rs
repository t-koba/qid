//! Session-bound email verification. The repository owns confirmation atomicity.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{
    models::{AuditEvent, CiamVerificationChallengeRecord},
    notification::{NotificationChannel, NotificationRequest},
    state::SharedState,
    util,
    web::JsonObject,
};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIssueRequest {}

// Deliberately not Debug or Serialize: the submitted secret must not escape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationConfirmRequest {
    pub challenge_id: String,
    pub code: String,
}

fn rejected() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":"email verification challenge unavailable"})),
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error":"email verification delivery unavailable"})),
    )
        .into_response()
}

// JSON array encoding makes the domain-separated binding unambiguous, including
// addresses containing delimiters. No process-local key: durable across restart.
fn secret_hash(record: &CiamVerificationChallengeRecord, code: &str) -> String {
    util::sha256_base64url(
        serde_json::json!([
            "qid.email-verification.v1",
            record.id,
            record.realm_id,
            record.user_id,
            record.channel,
            record.address,
            record.purpose,
            record.created_at_epoch_seconds,
            record.expires_at_epoch_seconds,
            code
        ])
        .to_string(),
    )
}

pub async fn verification_issue<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    JsonObject(_req): JsonObject<VerificationIssueRequest>,
) -> Response {
    let owner = match crate::session_auth::require_any_session(&headers, &state, &realm).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let (Some(config), Some(transport)) = (
        &state.config.server.notification,
        &state.notification_transport,
    ) else {
        return unavailable();
    };
    let Some(policy) = state
        .config
        .realms
        .iter()
        .find(|configured| configured.id == realm)
        .map(|configured| &configured.authentication.email_verification)
    else {
        return rejected();
    };
    let user = match state
        .repo
        .get_user_by_id_in_realm(&realm.clone().into(), &owner)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return rejected(),
        Err(error) => return qid_http::error_response(error),
    };
    let Some(address) = user.email.filter(|address| !address.trim().is_empty()) else {
        return rejected();
    };
    let now = util::now_seconds();
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let mut record = CiamVerificationChallengeRecord {
        id: format!("verify_{}", ulid::Ulid::new()),
        realm_id: realm.clone(),
        user_id: owner,
        channel: "email".into(),
        address,
        purpose: "email_verification".into(),
        code_hash: String::new(),
        attempt_count: 0,
        expires_at_epoch_seconds: now + policy.ttl_seconds,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: now,
    };
    record.code_hash = secret_hash(&record, &code);
    let response = transport
        .send(NotificationRequest {
            channel: NotificationChannel::Email,
            provider: config.provider.clone(),
            recipient: record.address.clone(),
            subject: Some("Verify your email".into()),
            body: format!(
                "Email verification challenge: {}\nCode: {code}\nExpires at: {}",
                record.id, record.expires_at_epoch_seconds
            ),
            template_id: None,
            data_json: serde_json::json!({}),
        })
        .await;
    let status = match response {
        Ok(response) if response.sent && (200..300).contains(&response.status) => response.status,
        _ => return unavailable(), // Never log secret-bearing adapter errors.
    };
    if let Err(error) = state.repo.store_ciam_verification_challenge(&record).await {
        return qid_http::error_response(error);
    }
    let event = AuditEvent {
        id: format!("audit_{}", ulid::Ulid::new()),
        realm_id: Some(realm),
        actor: "system".into(),
        action: "ciam.email_verification.delivery_accepted".into(),
        target_type: "ciam_verification_challenge".into(),
        target_id: record.id.clone(),
        reason: "delivery accepted".into(),
        metadata_json: serde_json::json!({"challenge_id":record.id, "status":status}),
        created_at: now,
        previous_hash: None,
        event_hash: None,
    };
    if let Err(error) = state.repo.append_audit_event(&event).await {
        return qid_http::error_response(error);
    }
    Json(serde_json::json!({"challenge_id":record.id, "expires_at_epoch_seconds":record.expires_at_epoch_seconds})).into_response()
}

pub async fn verification_confirm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    JsonObject(req): JsonObject<VerificationConfirmRequest>,
) -> Response {
    let owner = match crate::session_auth::require_any_session(&headers, &state, &realm).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    if req.challenge_id.len() > 128 || req.code.len() > 128 {
        return rejected();
    }
    let realm_id = realm.clone().into();
    let record = match state
        .repo
        .get_ciam_verification_challenge(&realm_id, &req.challenge_id)
        .await
    {
        Ok(Some(record))
            if record.user_id == owner
                && record.channel == "email"
                && record.purpose == "email_verification" =>
        {
            record
        }
        Ok(_) => return rejected(),
        Err(error) => return qid_http::error_response(error),
    };
    let Some(policy) = state
        .config
        .realms
        .iter()
        .find(|configured| configured.id == realm)
        .map(|configured| &configured.authentication.email_verification)
    else {
        return rejected();
    };
    match state
        .repo
        .confirm_ciam_email_verification(
            &realm_id,
            &record.id,
            &owner,
            &secret_hash(&record, &req.code),
            util::now_seconds(),
            policy.max_attempts,
        )
        .await
    {
        Ok(true) => Json(serde_json::json!({"verified":true})).into_response(),
        Ok(false) => rejected(),
        Err(error) => qid_http::error_response(error),
    }
}
