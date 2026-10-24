use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::web::JsonObject;
use qid_core::{
    QidError, QidResult,
    models::{AuditEvent, PasswordCredential, PasswordResetToken},
    notification::{NotificationChannel, NotificationRequest},
    state::SharedState,
    util,
};
use qid_crypto::ARGON2ID_ALGORITHM;
use qid_storage::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetIssueRequest {
    pub user_id: String,
    pub device_id: Option<String>,
    #[serde(default = "default_password_reset_risk")]
    pub risk: serde_json::Value,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetChallenge {
    pub id: String,
    pub user_id: String,
    pub expires_at_epoch_seconds: u64,
    pub delivery_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedPasswordResetChallenge {
    pub challenge: PasswordResetChallenge,
    pub token_hash: String,
    pub delivery_secret: String,
    pub created_at_epoch_seconds: u64,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct PasswordResetConsumeRequest {
    pub token_id: String,
    pub token: String,
    pub device_id: Option<String>,
    pub new_password: String,
    pub now_epoch_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamProtectionRequest {
    #[serde(default)]
    pub user_id: Option<String>,
    pub client_id: String,
    pub action: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub asn: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub known_bad_ip: bool,
    #[serde(default)]
    pub automation_signals: Vec<String>,
    #[serde(default)]
    pub recent_attempts: u32,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub window_seconds: u64,
    pub now_epoch_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiamProtectionOutcome {
    Allow,
    Challenge,
    RateLimit,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiamProtectionDecision {
    pub outcome: CiamProtectionOutcome,
    pub score: u32,
    pub labels: Vec<String>,
    pub rate_limit_key: String,
    pub retry_after_seconds: Option<u64>,
    pub max_attempts: u32,
}

pub async fn password_reset_issue<R: Repository + 'static>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    JsonObject(req): JsonObject<PasswordResetIssueRequest>,
) -> Response {
    let issued = match issue_password_reset(&realm, &req) {
        Ok(issued) => issued,
        Err(error) => return qid_http::error_response(error),
    };
    let Some(realm_config) = state.config.realms.iter().find(|config| config.id == realm) else {
        return password_reset_accepted();
    };
    if !realm_config.authentication.password.enabled
        || qid_crypto::realm_password_context(&state, &realm).is_err()
    {
        return password_reset_accepted();
    }
    let (Some(notification), Some(transport)) = (
        state.config.server.notification.as_ref(),
        state.notification_transport.clone(),
    ) else {
        return password_reset_accepted();
    };
    let provider = notification.provider.clone();
    let realm_id = realm.clone().into();
    let user = match state
        .repo
        .get_user_by_id_in_realm(&realm_id, &req.user_id)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return password_reset_accepted(),
        Err(_) => {
            tracing::warn!("password reset account lookup failed");
            return password_reset_accepted();
        }
    };
    let Some(address) = user.email.filter(|value| !value.trim().is_empty()) else {
        return password_reset_accepted();
    };
    let record = PasswordResetToken {
        id: issued.challenge.id.clone(),
        realm_id: realm.clone(),
        user_id: user.id,
        token_hash: issued.token_hash,
        device_id: req.device_id.clone(),
        risk_json: req.risk,
        expires_at_epoch_seconds: issued.challenge.expires_at_epoch_seconds,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: issued.created_at_epoch_seconds,
    };
    let body = serde_json::json!({
        "instructions": "Submit this one-time token to the password-reset consume endpoint and provide a new password. Server time is authoritative.",
        "realm": realm,
        "token_id": record.id,
        "token": issued.delivery_secret,
        "device_id": req.device_id,
        "new_password": "<your new password>",
        "now_epoch_seconds": 0,
        "expires_at_epoch_seconds": record.expires_at_epoch_seconds
    })
    .to_string();
    let request = NotificationRequest {
        channel: NotificationChannel::Email,
        provider,
        recipient: address,
        subject: Some("Password reset instructions".into()),
        body,
        template_id: None,
        data_json: serde_json::json!({}),
    };
    let state_for_delivery = state.clone();
    tokio::spawn(async move {
        deliver_password_reset(state_for_delivery, transport, record, request).await;
    });
    password_reset_accepted()
}

fn password_reset_accepted() -> Response {
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "If the account is eligible, password reset instructions may be sent."
        })),
    )
        .into_response()
}

async fn deliver_password_reset<R: Repository>(
    state: Arc<SharedState<R>>,
    transport: Arc<dyn qid_core::notification::NotificationTransport>,
    record: PasswordResetToken,
    request: NotificationRequest,
) {
    if state
        .repo
        .store_password_reset_token(&record)
        .await
        .is_err()
    {
        tracing::warn!("password reset challenge persistence failed");
        return;
    }
    let response = transport.send(request).await;
    let status = match response {
        Ok(response) if response.sent && (200..300).contains(&response.status) => response.status,
        _ => {
            // Adapter errors can contain the secret-bearing request body.
            tracing::warn!("password reset delivery was not accepted");
            return;
        }
    };
    let event = AuditEvent {
        id: format!("audit_{}", ulid::Ulid::new()),
        realm_id: Some(record.realm_id.clone()),
        actor: "system".into(),
        action: "ciam.password_reset.delivery_accepted".into(),
        target_type: "password_reset_token".into(),
        target_id: record.id,
        reason: "delivery accepted".into(),
        metadata_json: serde_json::json!({"status": status}),
        created_at: util::now_seconds(),
        previous_hash: None,
        event_hash: None,
    };
    if state.repo.append_audit_event(&event).await.is_err() {
        tracing::warn!("password reset delivery audit failed");
    }
}

pub async fn password_reset_consume<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    JsonObject(req): JsonObject<PasswordResetConsumeRequest>,
) -> Response {
    let record = match state.repo.get_password_reset_token(&req.token_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"password reset token not found"})),
            )
                .into_response();
        }
        Err(err) => return qid_http::error_response(err),
    };
    match consume_password_reset(&record, &req) {
        Ok(()) => {
            let credentials = match qid_crypto::realm_password_context(&state, &realm) {
                Ok(credentials) => credentials,
                Err(error) => return qid_http::error_response(error),
            };
            let hash = match credentials.hash(&req.new_password) {
                Ok(hash) => hash,
                Err(err) => {
                    return qid_http::error_response(qid_core::error::QidError::Internal {
                        message: format!("password reset hashing failed: {err}"),
                    });
                }
            };
            if let Err(err) = state
                .repo
                .replace_password_with_reset_token(
                    &record.id,
                    &realm.into(),
                    &util::sha256_base64url(&req.token),
                    req.device_id.as_deref(),
                    &PasswordCredential {
                        user_id: record.user_id.clone(),
                        hash,
                        algorithm: ARGON2ID_ALGORITHM.to_string(),
                    },
                    util::now_seconds(),
                )
                .await
            {
                return qid_http::error_response(err);
            }
            Json(serde_json::json!({"reset": "ok"})).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn protection_evaluate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    JsonObject(req): JsonObject<CiamProtectionRequest>,
) -> Response {
    let actor = match crate::session_auth::require_any_session(&headers, &state, &realm).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let decision = evaluate_ciam_protection(&realm, &req);
    let event = ciam_protection_audit_event(&realm, &actor, &req, &decision, util::now_seconds());
    if let Err(err) = state.repo.append_audit_event(&event).await {
        return qid_http::error_response(err);
    }
    Json(serde_json::json!({
        "realm": realm,
        "decision": decision,
        "audit_event_id": event.id,
    }))
    .into_response()
}

fn default_password_reset_risk() -> serde_json::Value {
    serde_json::json!({})
}

pub fn issue_password_reset(
    realm: &str,
    req: &PasswordResetIssueRequest,
) -> QidResult<IssuedPasswordResetChallenge> {
    if realm.trim().is_empty() || req.user_id.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "password reset realm and user_id must not be empty".to_string(),
        });
    }
    if req.ttl_seconds == 0 || req.ttl_seconds > 1800 {
        return Err(QidError::BadRequest {
            message: "password reset ttl_seconds must be between 1 and 1800".to_string(),
        });
    }
    if !req.risk.is_object() {
        return Err(QidError::BadRequest {
            message: "password reset risk must be an object".to_string(),
        });
    }
    let id = format!("pwdreset_{}", ulid::Ulid::new());
    let token = generate_password_reset_token();
    let now = util::now_seconds();
    let expires_at_epoch_seconds =
        now.checked_add(req.ttl_seconds)
            .ok_or_else(|| QidError::BadRequest {
                message: "password reset expiry is out of range".to_string(),
            })?;
    let challenge = PasswordResetChallenge {
        id,
        user_id: req.user_id.clone(),
        expires_at_epoch_seconds,
        delivery_ref: format!("pwdreset_delivery_{}", ulid::Ulid::new()),
    };
    Ok(IssuedPasswordResetChallenge {
        token_hash: util::sha256_base64url(&token),
        delivery_secret: token,
        challenge,
        created_at_epoch_seconds: now,
    })
}

pub fn consume_password_reset(
    record: &PasswordResetToken,
    req: &PasswordResetConsumeRequest,
) -> QidResult<()> {
    if record.consumed_at_epoch_seconds.is_some() {
        return Err(QidError::BadRequest {
            message: "already_consumed".to_string(),
        });
    }
    if util::now_seconds() > record.expires_at_epoch_seconds {
        return Err(QidError::BadRequest {
            message: "expired".to_string(),
        });
    }
    if record.device_id != req.device_id {
        return Err(QidError::BadRequest {
            message: "device_mismatch".to_string(),
        });
    }
    if req.new_password.len() < 12 {
        return Err(QidError::BadRequest {
            message: "password_too_short".to_string(),
        });
    }
    let expected = util::sha256_base64url(&req.token);
    if !util::constant_time_eq(&expected, &record.token_hash) {
        return Err(QidError::BadRequest {
            message: "token_mismatch".to_string(),
        });
    }
    Ok(())
}

pub fn evaluate_ciam_protection(
    realm: &str,
    req: &CiamProtectionRequest,
) -> CiamProtectionDecision {
    use std::collections::BTreeSet;

    let max_attempts = match req.action.as_str() {
        "password_reset" | "email_verification" | "phone_verification" => 5,
        "login" => 10,
        _ => 20,
    };
    let window_seconds = req.window_seconds.clamp(60, 3600);
    let mut score = 0u32;
    let mut labels = BTreeSet::new();

    if req.known_bad_ip {
        score += 80;
        labels.insert("known_bad_ip".to_string());
    }
    if req
        .device_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        score += 10;
        labels.insert("unknown_device".to_string());
    }
    if req.failed_attempts >= max_attempts {
        score += 45;
        labels.insert("failed_attempt_threshold".to_string());
    } else if req.failed_attempts >= max_attempts / 2 {
        score += 20;
        labels.insert("elevated_failed_attempts".to_string());
    }
    if req.recent_attempts > max_attempts * 2 {
        score += 40;
        labels.insert("attempt_rate_exceeded".to_string());
    } else if req.recent_attempts > max_attempts {
        score += 20;
        labels.insert("attempt_rate_elevated".to_string());
    }
    for signal in &req.automation_signals {
        let normalized = signal.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        score += match normalized.as_str() {
            "headless" | "webdriver" | "impossible_timing" => 35,
            "datacenter_asn" | "tor_exit" | "credential_stuffing" => 45,
            _ => 15,
        };
        labels.insert(format!("automation:{normalized}"));
    }

    let outcome = if req.known_bad_ip || score >= 100 {
        CiamProtectionOutcome::Block
    } else if req.recent_attempts > max_attempts * 2 || req.failed_attempts >= max_attempts {
        CiamProtectionOutcome::RateLimit
    } else if score >= 35 {
        CiamProtectionOutcome::Challenge
    } else {
        CiamProtectionOutcome::Allow
    };
    let retry_after_seconds = match outcome {
        CiamProtectionOutcome::RateLimit => Some(window_seconds),
        CiamProtectionOutcome::Block => Some(window_seconds * 2),
        _ => None,
    };

    CiamProtectionDecision {
        outcome,
        score: score.min(100),
        labels: labels.into_iter().collect(),
        rate_limit_key: ciam_rate_limit_key(realm, req),
        retry_after_seconds,
        max_attempts,
    }
}

fn ciam_rate_limit_key(realm: &str, req: &CiamProtectionRequest) -> String {
    let material = format!(
        "{}:{}:{}:{}:{}:{}",
        realm,
        req.client_id,
        req.action,
        req.user_id.as_deref().unwrap_or("anonymous"),
        req.ip.as_deref().unwrap_or("unknown_ip"),
        req.device_id.as_deref().unwrap_or("unknown_device")
    );
    format!("ciam_rate_{}", util::sha256_base64url(material))
}

fn ciam_protection_audit_event(
    realm: &str,
    actor: &str,
    req: &CiamProtectionRequest,
    decision: &CiamProtectionDecision,
    now: u64,
) -> qid_core::models::AuditEvent {
    qid_core::models::AuditEvent {
        id: format!("ciam_protect_{}", ulid::Ulid::new()),
        realm_id: Some(realm.to_string()),
        actor: actor.to_string(),
        action: "ciam.protection.evaluate".to_string(),
        target_type: "ciam_client_action".to_string(),
        target_id: format!("{}:{}", req.client_id, req.action),
        reason: "CIAM bot and rate protection evaluation".to_string(),
        metadata_json: serde_json::json!({
            "client_id": req.client_id,
            "action": req.action,
            "outcome": decision.outcome,
            "score": decision.score,
            "labels": decision.labels,
            "rate_limit_key": decision.rate_limit_key,
            "retry_after_seconds": decision.retry_after_seconds,
            "ip_present": req.ip.is_some(),
            "asn": req.asn,
            "device_present": req.device_id.is_some(),
            "recent_attempts": req.recent_attempts,
            "failed_attempts": req.failed_attempts,
        }),
        created_at: now,
        previous_hash: None,
        event_hash: None,
    }
}

fn generate_password_reset_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciam_protection_blocks_bad_ip_and_rate_limits_attempt_bursts() {
        let blocked = evaluate_ciam_protection(
            "corp",
            &CiamProtectionRequest {
                user_id: Some("user-1".to_string()),
                client_id: "web".to_string(),
                action: "login".to_string(),
                ip: Some("203.0.113.10".to_string()),
                asn: Some("64500".to_string()),
                device_id: None,
                user_agent: Some("headless".to_string()),
                known_bad_ip: true,
                automation_signals: vec!["webdriver".to_string()],
                recent_attempts: 3,
                failed_attempts: 1,
                window_seconds: 300,
                now_epoch_seconds: 1_800_000_000,
            },
        );
        assert_eq!(blocked.outcome, CiamProtectionOutcome::Block);
        assert!(blocked.labels.contains(&"known_bad_ip".to_string()));

        let limited = evaluate_ciam_protection(
            "corp",
            &CiamProtectionRequest {
                user_id: Some("user-1".to_string()),
                client_id: "web".to_string(),
                action: "password_reset".to_string(),
                ip: Some("203.0.113.20".to_string()),
                asn: None,
                device_id: Some("device-1".to_string()),
                user_agent: None,
                known_bad_ip: false,
                automation_signals: Vec::new(),
                recent_attempts: 12,
                failed_attempts: 5,
                window_seconds: 120,
                now_epoch_seconds: 1_800_000_000,
            },
        );
        assert_eq!(limited.outcome, CiamProtectionOutcome::RateLimit);
        assert_eq!(limited.retry_after_seconds, Some(120));
        assert!(limited.rate_limit_key.starts_with("ciam_rate_"));
    }

    #[test]
    fn password_reset_token_is_single_use_short_ttl_and_device_bound() {
        let req = PasswordResetIssueRequest {
            user_id: "user-1".to_string(),
            device_id: Some("device-1".to_string()),
            risk: serde_json::json!({"score": 10}),
            ttl_seconds: 900,
        };
        let issued = issue_password_reset("corp", &req).unwrap();
        let challenge = issued.challenge;
        let material = issued.delivery_secret;
        let record = PasswordResetToken {
            id: challenge.id.clone(),
            realm_id: "corp".to_string(),
            user_id: "user-1".to_string(),
            token_hash: issued.token_hash,
            device_id: Some("device-1".to_string()),
            risk_json: serde_json::json!({"score": 10}),
            expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
            consumed_at_epoch_seconds: None,
            created_at_epoch_seconds: 1_800_000_000,
        };

        consume_password_reset(
            &record,
            &PasswordResetConsumeRequest {
                token_id: challenge.id.clone(),
                token: material.clone(),
                device_id: Some("device-1".to_string()),
                new_password: "new-secure-password".to_string(),
                now_epoch_seconds: 1_800_000_100,
            },
        )
        .unwrap();

        let err = consume_password_reset(
            &record,
            &PasswordResetConsumeRequest {
                token_id: challenge.id,
                token: material,
                device_id: Some("other-device".to_string()),
                new_password: "new-secure-password".to_string(),
                now_epoch_seconds: 1_800_000_100,
            },
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "bad request: device_mismatch");
    }
}
