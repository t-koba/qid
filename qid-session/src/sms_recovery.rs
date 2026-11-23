//! Explicit recovery, never a primary-login option or a provider-approved factor.
use crate::{
    api::{extract_cookie, set_session_cookie},
    browser::SessionManager,
    delivered_challenge::{challenge_hash, protected, random_secret, well_formed},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use qid_core::{
    config::SMS_RECOVERY_BINDING_COOKIE_NAME as COOKIE,
    models::CiamVerificationChallengeRecord,
    notification::{NotificationChannel, NotificationRequest},
    plan::RuntimeRealm,
    state::SharedState,
    util::now_seconds,
};
use qid_storage::prelude::*;
use rand::{Rng, rngs::OsRng};
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument::WithSubscriber;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendRequest {
    user_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedeemRequest {
    user_id: String,
    challenge_id: String,
    code: String,
}
fn available<'a, R: Repository>(
    state: &'a SharedState<R>,
    realm: &str,
) -> Option<&'a RuntimeRealm> {
    let runtime = state.realm(realm).filter(|r| r.mfa.sms_recovery.enabled)?;
    (state.config.server.notification.is_some()
        && state.notification_transport.is_some()
        && !state
            .plan
            .realms
            .iter()
            .any(|r| r.browser_session.cookie_name == COOKIE)
        && url::Url::parse(&state.config.server.public_base_url).is_ok_and(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        }))
    .then_some(runtime)
}
fn binding(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, COOKIE).filter(|v| well_formed(v))
}
fn invalid() -> Response {
    protected(
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status":"recovery_failed"})),
        )
            .into_response(),
    )
}
pub(crate) async fn send<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<SendRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return invalid();
    };
    let binding = binding(&headers).unwrap_or_else(random_secret);
    let id = random_secret();
    // Identical response for unknown, unenrolled, disabled, suppressed and failed delivery.
    let mut response = protected(
        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "challenge_id": id, "message": "If recovery is available, a code may be sent."
            })),
        )
            .into_response(),
    );
    let Ok(cookie) = HeaderValue::from_str(&format!(
        "{COOKIE}={binding}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600"
    )) else {
        return response;
    };
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    let Some(runtime) = available(&state, &realm) else {
        return response;
    };
    let policy = &runtime.mfa.sms_recovery;
    let Some(address) = policy.destinations.get(&req.user_id).cloned() else {
        return response;
    };
    let Ok(permit) = state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
    else {
        return response;
    };
    let (ttl, max_issuances, window) = (
        policy.ttl_seconds,
        policy.max_issuances_per_window,
        policy.issuance_window_seconds,
    );
    let now = now_seconds();
    let code = format!("{:08}", OsRng.gen_range(0..100_000_000u32));
    let mut record = CiamVerificationChallengeRecord {
        id,
        realm_id: realm,
        user_id: req.user_id,
        channel: "phone".into(),
        address: address.clone(),
        purpose: "sms_recovery".into(),
        code_hash: String::new(),
        attempt_count: 0,
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now.saturating_add(ttl),
        consumed_at_epoch_seconds: None,
    };
    record.code_hash = challenge_hash(&record, &code, &binding);
    let (Some(notification), Some(transport)) = (
        state.config.server.notification.clone(),
        state.notification_transport.clone(),
    ) else {
        return response;
    };
    let request = NotificationRequest {
        channel: NotificationChannel::Sms,
        provider: notification.provider,
        recipient: address,
        subject: None,
        body: format!(
            "Your qid account recovery code is {code}. Use only in the browser requesting recovery. Do not share it."
        ),
        template_id: None,
        data_json: serde_json::json!({}),
    };
    tokio::spawn(async move {
        let _permit = permit;
        match state.repo.try_issue_delivery_challenge(&record, max_issuances, window).await {
            Ok(true) => {}, Ok(false) => return, Err(_) => { tracing::warn!("SMS recovery issuance failed"); return; }
        }
        // Acceptance is delivery only; no session or approval is created here.
        if !matches!(tokio::time::timeout(std::time::Duration::from_secs(notification.timeout_seconds), transport.send(request)).await,
            Ok(Ok(ref r)) if r.sent && (200..300).contains(&r.status)) {
            tracing::warn!("SMS recovery delivery failed");
        }
    }.with_current_subscriber());
    response
}
pub(crate) async fn redeem<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<RedeemRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return invalid();
    };
    let Some(runtime) = available(&state, &realm) else {
        return invalid();
    };
    if !well_formed(&req.challenge_id) {
        return invalid();
    }
    let Some(binding) = binding(&headers) else {
        return invalid();
    };
    let policy = &runtime.mfa.sms_recovery;
    let record = match state
        .repo
        .get_ciam_verification_challenge(&realm.clone().into(), &req.challenge_id)
        .await
    {
        Ok(Some(r))
            if r.realm_id == realm
                && r.user_id == req.user_id
                && r.channel == "phone"
                && r.purpose == "sms_recovery"
                && policy.destinations.get(&req.user_id) == Some(&r.address) =>
        {
            r
        }
        _ => return invalid(),
    };
    let now = now_seconds();
    if now >= record.expires_at_epoch_seconds {
        return invalid();
    }
    let code = if req.code.len() == 8 && req.code.bytes().all(|b| b.is_ascii_digit()) {
        &req.code
    } else {
        "invalid-code"
    };
    let hash = challenge_hash(&record, code, &binding);
    let user = match state
        .repo
        .redeem_delivery_challenge(
            &realm.clone().into(),
            &record.id,
            &hash,
            now,
            policy.max_attempts,
            "sms_recovery",
        )
        .await
    {
        Ok(Some(user)) => user,
        _ => return invalid(),
    };
    // Durable consumption precedes session creation; errors must never revive the code.
    let config = &runtime.browser_session;
    let manager =
        SessionManager::from_browser_session_config(state.repo.clone(), config, state.clone());
    let old = extract_cookie(&headers, &config.cookie_name);
    let session = match manager
        .create_with_regeneration(
            &realm,
            &user.id,
            "urn:qid:acr:recovery",
            &["sms_recovery".into()],
            old.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("SMS recovery session creation failed");
            return invalid();
        }
    };
    let mut response = protected(Json(serde_json::json!({"status":"recovered"})).into_response());
    if set_session_cookie(
        response.headers_mut(),
        config,
        &session.id,
        "SMS recovery session cookie failed",
    )
    .is_err()
    {
        return invalid();
    }
    response
}
#[cfg(test)]
mod tests;
