//! Delivered passwordless primary authentication. Delivery is never approval.
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    models::CiamVerificationChallengeRecord,
    notification::{NotificationChannel, NotificationRequest},
    state::SharedState,
    util::now_seconds,
};
use qid_storage::prelude::*;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::instrument::WithSubscriber;

use crate::{
    api::{extract_cookie, set_session_cookie},
    browser::SessionManager,
};

const BINDING_COOKIE: &str = qid_core::config::EMAIL_MAGIC_LINK_BINDING_COOKIE_NAME;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyRequest {
    challenge_id: String,
    token: String,
}

fn random_secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn well_formed(value: &str) -> bool {
    value.len() == 43 && URL_SAFE_NO_PAD.decode(value).is_ok_and(|v| v.len() == 32)
}

fn binding(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, BINDING_COOKIE).filter(|v| well_formed(v))
}

// Versioned, separately domain-separated proofs; every component is length-prefixed.
// Storage checks the browser proof before spending any token attempt.
fn challenge_hash(c: &CiamVerificationChallengeRecord, token: &str, binding: &str) -> String {
    let digest = |domain: &str, secret: &str| {
        let mut hash = Sha256::new();
        for part in [
            domain,
            &c.id,
            &c.realm_id,
            &c.user_id,
            &c.address,
            &c.channel,
            &c.purpose,
            secret,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        qid_core::util::hex_encode_lower(&hash.finalize())
    };
    format!(
        "ml2:{}:{}",
        digest("qid:email-magic-link:v2:binding", binding),
        digest("qid:email-magic-link:v2:token", token)
    )
}

fn protected(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(crate) async fn send<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SendRequest>,
) -> Response {
    let binding = binding(&headers).unwrap_or_else(random_secret);
    // The cookie and body have the same shape for all eligibility outcomes.
    let mut response = protected(
        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "message": "If the account is eligible, sign-in instructions may be sent."
            })),
        )
            .into_response(),
    );
    let cookie =
        format!("{BINDING_COOKIE}={binding}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600");
    if let Ok(cookie) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    } else {
        return response;
    }
    let Some(runtime) = state.realm(&realm).filter(|r| r.email_magic_link.enabled) else {
        return response;
    };
    let (Some(notification), Some(transport)) = (
        state.config.server.notification.as_ref(),
        state.notification_transport.clone(),
    ) else {
        return response;
    };
    let Ok(permit) = state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
    else {
        return response;
    };
    let user = match state
        .repo
        .get_user_by_email(&realm.clone().into(), &req.email)
        .await
    {
        Ok(Some(user)) if user.email_verified && user.realm_id == realm => user,
        Ok(_) => return response,
        Err(_) => {
            tracing::warn!("email magic link account lookup failed");
            return response;
        }
    };
    let Some(address) = user.email.filter(|v| !v.trim().is_empty()) else {
        return response;
    };
    let policy = runtime.email_magic_link.clone();
    let now = now_seconds();
    let token = random_secret();
    let mut record = CiamVerificationChallengeRecord {
        id: random_secret(),
        realm_id: realm.clone(),
        user_id: user.id,
        channel: "email".into(),
        address: address.clone(),
        purpose: "email_magic_link".into(),
        code_hash: String::new(),
        attempt_count: 0,
        created_at_epoch_seconds: now,
        expires_at_epoch_seconds: now.saturating_add(policy.ttl_seconds),
        consumed_at_epoch_seconds: None,
    };
    record.code_hash = challenge_hash(&record, &token, &binding);
    let Ok(mut link) = url::Url::parse(&state.config.server.public_base_url) else {
        return response;
    };
    // Configuration validation requires HTTPS. Also fail closed for unchecked runtime configs.
    if link.scheme() != "https"
        || link.host_str().is_none()
        || !link.username().is_empty()
        || link.password().is_some()
        || link.query().is_some()
        || link.fragment().is_some()
    {
        return response;
    }
    let Ok(mut segments) = link.path_segments_mut() else {
        return response;
    };
    for segment in state
        .config
        .server
        .paths
        .auth_email_magic_link_verify
        .trim_start_matches('/')
        .split('/')
    {
        segments.push(if segment == ":realm" { &realm } else { segment });
    }
    drop(segments);
    link.set_fragment(Some(&format!("{}.{}", record.id, token)));
    let request = NotificationRequest {
        channel: NotificationChannel::Email,
        provider: notification.provider.clone(),
        recipient: address,
        subject: Some("Confirm your sign-in".into()),
        body: format!(
            "Open this link in the same browser that requested it, then press Confirm sign-in. Do not share this link.\n{link}"
        ),
        template_id: None,
        data_json: serde_json::json!({}),
    };
    tokio::spawn(
        async move {
            let _permit = permit;
            match state
                .repo
                .try_issue_email_magic_link_challenge(
                    &record,
                    policy.max_issuances_per_window,
                    policy.issuance_window_seconds,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => return,
                Err(_) => {
                    tracing::warn!("email magic link issuance failed");
                    return;
                }
            }
            let status = match transport.send(request).await {
                Ok(result) if result.sent && (200..300).contains(&result.status) => result.status,
                _ => {
                    tracing::warn!("email magic link delivery failed");
                    return;
                }
            };
            let event = qid_core::models::AuditEvent {
                id: format!("audit_{}", ulid::Ulid::new()),
                realm_id: Some(record.realm_id.clone()),
                actor: "system".into(),
                action: "auth.email_magic_link.delivery_accepted".into(),
                target_type: "authentication_challenge".into(),
                target_id: record.id.clone(),
                reason: "delivery accepted".into(),
                metadata_json: serde_json::json!({"status": status}),
                created_at: now_seconds(),
                previous_hash: None,
                event_hash: None,
            };
            if state.repo.append_audit_event(&event).await.is_err() {
                tracing::warn!("email magic link delivery audit failed");
            }
        }
        .with_current_subscriber(),
    );
    response
}

pub(crate) async fn landing() -> Response {
    let nonce = random_secret();
    let page = format!(
        r##"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Confirm sign-in</title>
<button id="confirm" type="button">Confirm sign-in</button><p id="status" role="status"></p>
<script nonce="{nonce}">
'use strict';
const parts = location.hash.slice(1).split('.');
history.replaceState(null, '', location.pathname);
const button = document.getElementById('confirm');
button.addEventListener('click', async () => {{
  button.disabled = true;
  const status = document.getElementById('status');
  try {{
    const response = await fetch(location.pathname, {{method: 'POST', credentials: 'same-origin', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{challenge_id: parts[0] || '', token: parts[1] || ''}})}});
    status.textContent = response.ok ? 'Authenticated. You may return to your application.' : 'Sign-in failed. Open this link in the browser where you requested it, or restart sign-in there.';
  }} catch (_) {{ status.textContent = 'Sign-in failed. Open this link in the browser where you requested it, or restart sign-in there.'; }}
  parts.fill('');
}});
</script></html>"##
    );
    let mut response = protected(Html(page).into_response());
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    );
    if let Ok(value) = HeaderValue::from_str(&csp) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

fn invalid() -> Response {
    protected(
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status": "authentication_failed"})),
        )
            .into_response(),
    )
}

pub(crate) async fn verify<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<VerifyRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return invalid();
    };
    let Some(runtime) = state.realm(&realm).filter(|r| r.email_magic_link.enabled) else {
        return invalid();
    };
    if state.config.server.notification.is_none()
        || state.notification_transport.is_none()
        || !well_formed(&req.challenge_id)
    {
        return invalid();
    }
    let Some(binding) = binding(&headers) else {
        return invalid();
    };
    let realm_id = realm.clone().into();
    let record = match state
        .repo
        .get_ciam_verification_challenge(&realm_id, &req.challenge_id)
        .await
    {
        Ok(Some(record)) => record,
        _ => return invalid(),
    };
    // Malformed tokens still spend an attempt from the correct browser, but do not
    // hash an attacker-controlled unbounded string. Valid tokens are fixed-width.
    let candidate_token = if well_formed(&req.token) {
        req.token.as_str()
    } else {
        "invalid-token"
    };
    let hash = challenge_hash(&record, candidate_token, &binding);
    let user = match state
        .repo
        .redeem_email_magic_link_challenge(
            &realm_id,
            &req.challenge_id,
            &hash,
            now_seconds(),
            runtime.email_magic_link.max_attempts,
        )
        .await
    {
        Ok(Some(user)) => user,
        _ => return invalid(),
    };
    // Consumed before session creation: any later failure must not revive this credential.
    let manager =
        SessionManager::from_browser_session_config(state.repo.clone(), &runtime.browser_session);
    let old_session = extract_cookie(&headers, &runtime.browser_session.cookie_name);
    let session = match manager
        .create_with_regeneration(
            &realm,
            &user.id,
            "urn:qid:acr:email_magic_link",
            &["email".into()],
            old_session.as_deref(),
        )
        .await
    {
        Ok(session) => session,
        Err(_) => {
            tracing::warn!("email magic link session creation failed");
            return invalid();
        }
    };
    let mut response =
        protected(Json(serde_json::json!({"status": "authenticated"})).into_response());
    if set_session_cookie(
        response.headers_mut(),
        &runtime.browser_session,
        &session.id,
        "email magic link session cookie failed",
    )
    .is_err()
    {
        tracing::warn!("email magic link session cookie failed");
        return invalid();
    }
    response
}

#[cfg(test)]
mod tests;
