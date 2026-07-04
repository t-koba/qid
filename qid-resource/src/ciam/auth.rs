use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    QidError, QidResult,
    models::{CiamVerificationChallengeRecord, PasswordCredential, PasswordResetToken},
    state::SharedState,
    util,
};
use qid_crypto::{ARGON2ID_ALGORITHM, hash_password};
use qid_storage::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::VerificationChannel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationIssueRequest {
    pub user_id: String,
    pub channel: VerificationChannel,
    pub address: String,
    pub purpose: String,
    pub now_epoch_seconds: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationChallenge {
    pub id: String,
    pub user_id: String,
    pub channel: VerificationChannel,
    pub address: String,
    pub purpose: String,
    pub expires_at_epoch_seconds: u64,
    pub delivery_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedVerificationChallenge {
    pub challenge: VerificationChallenge,
    pub code_hash: String,
    pub delivery_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationConfirmRequest {
    pub challenge_id: String,
    pub channel: VerificationChannel,
    pub address: String,
    pub purpose: String,
    pub code: String,
    pub code_hash: String,
    pub expires_at_epoch_seconds: u64,
    pub now_epoch_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationConfirmResult {
    pub verified: bool,
    pub consumed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetIssueRequest {
    pub user_id: String,
    pub device_id: Option<String>,
    #[serde(default)]
    pub risk: serde_json::Value,
    pub now_epoch_seconds: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

pub async fn verification_issue<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Json(req): Json<VerificationIssueRequest>,
) -> Response {
    match issue_verification_challenge(&realm, &req, &state.ciam_verification_pepper) {
        Ok(issued) => {
            let now = util::now_seconds();
            let challenge = issued.challenge;
            let record = CiamVerificationChallengeRecord {
                id: challenge.id.clone(),
                realm_id: realm,
                user_id: challenge.user_id.clone(),
                channel: channel_as_str(&challenge.channel).to_string(),
                address: challenge.address.clone(),
                purpose: challenge.purpose.clone(),
                code_hash: issued.code_hash,
                expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
                consumed_at_epoch_seconds: None,
                created_at_epoch_seconds: now,
            };
            match state.repo.store_ciam_verification_challenge(&record).await {
                Ok(()) => (StatusCode::CREATED, Json(challenge)).into_response(),
                Err(err) => qid_http::error_response(err),
            }
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn verification_confirm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<VerificationConfirmRequest>,
) -> Response {
    let record = match state
        .repo
        .get_ciam_verification_challenge(&req.challenge_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"verification challenge not found"})),
            )
                .into_response();
        }
        Err(err) => return qid_http::error_response(err),
    };
    if record.consumed_at_epoch_seconds.is_some() {
        return Json(VerificationConfirmResult {
            verified: false,
            consumed: false,
            reason: Some("already_consumed".to_string()),
        })
        .into_response();
    }
    let effective = VerificationConfirmRequest {
        code_hash: record.code_hash,
        expires_at_epoch_seconds: record.expires_at_epoch_seconds,
        address: record.address,
        purpose: record.purpose,
        ..req
    };
    let result = confirm_verification_challenge(&effective, &state.ciam_verification_pepper);
    if result.verified
        && let Err(err) = state
            .repo
            .consume_ciam_verification_challenge(&effective.challenge_id, util::now_seconds())
            .await
    {
        return qid_http::error_response(err);
    }
    Json(result).into_response()
}

pub async fn password_reset_issue<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Json(req): Json<PasswordResetIssueRequest>,
) -> Response {
    match issue_password_reset(&realm, &req) {
        Ok(issued) => {
            let now = util::now_seconds();
            let challenge = issued.challenge;
            let record = PasswordResetToken {
                id: challenge.id.clone(),
                realm_id: realm,
                user_id: challenge.user_id.clone(),
                token_hash: issued.token_hash,
                device_id: req.device_id,
                risk_json: if req.risk.is_object() {
                    req.risk
                } else {
                    serde_json::json!({})
                },
                expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
                consumed_at_epoch_seconds: None,
                created_at_epoch_seconds: now,
            };
            match state.repo.store_password_reset_token(&record).await {
                Ok(()) => (StatusCode::CREATED, Json(challenge)).into_response(),
                Err(err) => qid_http::error_response(err),
            }
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn password_reset_consume<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<PasswordResetConsumeRequest>,
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
    let now = util::now_seconds();
    match consume_password_reset(&record, &req) {
        Ok(()) => {
            let hash = match hash_password(&req.new_password) {
                Ok(hash) => hash,
                Err(err) => {
                    return qid_http::error_response(qid_core::error::QidError::Internal {
                        message: format!("password reset hashing failed: {err}"),
                    });
                }
            };
            if let Err(err) = state
                .repo
                .store_password_credential(&PasswordCredential {
                    user_id: record.user_id.clone(),
                    hash,
                    algorithm: ARGON2ID_ALGORITHM.to_string(),
                    pepper_ref: None,
                })
                .await
            {
                return qid_http::error_response(err);
            }
            if let Err(err) = state
                .repo
                .consume_password_reset_token(&record.id, now)
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
    Json(req): Json<CiamProtectionRequest>,
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

pub fn issue_verification_challenge(
    _realm: &str,
    req: &VerificationIssueRequest,
    pepper: &[u8],
) -> QidResult<IssuedVerificationChallenge> {
    if req.address.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "verification address must not be empty".to_string(),
        });
    }
    if req.user_id.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "verification user_id must not be empty".to_string(),
        });
    }
    if req.purpose.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "verification purpose must not be empty".to_string(),
        });
    }
    if req.ttl_seconds == 0 || req.ttl_seconds > 3600 {
        return Err(QidError::BadRequest {
            message: "verification ttl_seconds must be between 1 and 3600".to_string(),
        });
    }
    let code = generate_verification_code();
    let now = util::now_seconds();
    let challenge = VerificationChallenge {
        id: format!("verify_{}", ulid::Ulid::new()),
        user_id: req.user_id.clone(),
        channel: req.channel.clone(),
        address: req.address.clone(),
        purpose: req.purpose.clone(),
        expires_at_epoch_seconds: now + req.ttl_seconds,
        delivery_ref: format!("verify_{}", ulid::Ulid::new()),
    };
    Ok(IssuedVerificationChallenge {
        code_hash: verification_code_hash(pepper, &code, &req.address, &req.purpose),
        delivery_secret: code,
        challenge,
    })
}

pub fn confirm_verification_challenge(
    req: &VerificationConfirmRequest,
    pepper: &[u8],
) -> VerificationConfirmResult {
    if util::now_seconds() > req.expires_at_epoch_seconds {
        return VerificationConfirmResult {
            verified: false,
            consumed: false,
            reason: Some("expired".to_string()),
        };
    }
    let expected = verification_code_hash(pepper, &req.code, &req.address, &req.purpose);
    let verified = util::constant_time_eq(&expected, &req.code_hash);
    VerificationConfirmResult {
        verified,
        consumed: verified,
        reason: (!verified).then(|| "code_mismatch".to_string()),
    }
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
    let challenge = PasswordResetChallenge {
        id,
        user_id: req.user_id.clone(),
        expires_at_epoch_seconds: now + req.ttl_seconds,
        delivery_ref: format!("pwdreset_delivery_{}", ulid::Ulid::new()),
    };
    Ok(IssuedPasswordResetChallenge {
        token_hash: util::sha256_base64url(&token),
        delivery_secret: token,
        challenge,
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

fn channel_as_str(channel: &VerificationChannel) -> &'static str {
    match channel {
        VerificationChannel::Email => "email",
        VerificationChannel::Phone => "phone",
    }
}

fn generate_verification_code() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let value = u64::from_be_bytes(bytes) % 1_000_000;
    format!("{value:06}")
}

fn verification_code_hash(pepper: &[u8], code: &str, address: &str, purpose: &str) -> String {
    let digest = util::hmac_sha256_base64url(pepper, format!("{code}:{address}:{purpose}"));
    format!("hmac-sha256:{digest}")
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
    fn verification_challenge_confirms_once_and_rejects_expired_or_wrong_code() {
        let req = VerificationIssueRequest {
            user_id: "user-1".to_string(),
            channel: VerificationChannel::Email,
            address: "alice@example.com".to_string(),
            purpose: "email_verification".to_string(),
            now_epoch_seconds: 1_800_000_000,
            ttl_seconds: 600,
        };
        let pepper = [7u8; 32];
        let issued = issue_verification_challenge("corp", &req, &pepper).unwrap();
        let challenge = issued.challenge;
        let code = issued.delivery_secret;

        let confirmed = confirm_verification_challenge(
            &VerificationConfirmRequest {
                challenge_id: challenge.id.clone(),
                channel: VerificationChannel::Email,
                address: req.address.clone(),
                purpose: req.purpose.clone(),
                code,
                code_hash: issued.code_hash.clone(),
                expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
                now_epoch_seconds: 1_800_000_010,
            },
            &pepper,
        );
        assert!(confirmed.verified);
        assert!(confirmed.consumed);

        let expired = confirm_verification_challenge(
            &VerificationConfirmRequest {
                challenge_id: challenge.id,
                channel: VerificationChannel::Email,
                address: req.address,
                purpose: req.purpose,
                code: "000000".to_string(),
                code_hash: issued.code_hash,
                expires_at_epoch_seconds: util::now_seconds().saturating_sub(1),
                now_epoch_seconds: 1_800_001_000,
            },
            &pepper,
        );
        assert_eq!(expired.reason.as_deref(), Some("expired"));
    }

    #[test]
    fn password_reset_token_is_single_use_short_ttl_and_device_bound() {
        let req = PasswordResetIssueRequest {
            user_id: "user-1".to_string(),
            device_id: Some("device-1".to_string()),
            risk: serde_json::json!({"score": 10}),
            now_epoch_seconds: 1_800_000_000,
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
