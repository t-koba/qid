//! Account-owned enrollment. The device signs a destination-bound delivered nonce;
//! neither browser-supplied AMR nor delivery acceptance is authentication proof.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    config::ServerPaths,
    error::QidResult,
    models::{
        PushAuthenticator, PushPublicJwk, PushRegistrationChallenge, Session,
        valid_push_device_metadata,
    },
    notification::{NotificationChannel, NotificationRequest},
    state::SharedState,
    util::{constant_time_eq, now_seconds, sha256_hex},
};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use crate::push::{available, invalid, secret};

pub(super) fn routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    let base = format!("{}/push/registrations", paths.auth_password);
    Router::new()
        .route(&base, get(list::<R>))
        .route(&format!("{base}/start"), post(start::<R>))
        .route(&format!("{base}/finish"), post(finish::<R>))
        .route(&format!("{base}/revoke"), post(revoke::<R>))
        // Fits the hard 8192-byte proof ceiling plus base64 and metadata.
        .layer(DefaultBodyLimit::max(16384))
}

async fn owner_session<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> QidResult<Session> {
    let session = super::load_browser_session(state, realm, headers)
        .await
        .map_err(|_| invalid())?
        .session;
    state
        .repo
        .get_user_by_id(&session.user_id)
        .await?
        .filter(|u| u.realm_id == realm)
        .ok_or_else(invalid)?;
    Ok(session)
}

async fn recent_session<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> QidResult<Session> {
    let policy = &state.require_realm(realm)?.mfa.push;
    let session = owner_session(state, realm, headers).await?;
    let user = state
        .repo
        .get_user_by_id(&session.user_id)
        .await?
        .filter(|u| u.realm_id == realm)
        .ok_or_else(invalid)?;
    let now = now_seconds();
    if session.auth_time > now || now - session.auth_time > policy.recent_reauth_seconds {
        return Err(invalid());
    }
    let totp = state
        .repo
        .get_totp_credential(&session.user_id)
        .await?
        .filter(|c| c.enabled);
    let passkeys = state
        .repo
        .get_webauthn_credentials(&session.user_id)
        .await?;
    let method = |name: &str| session.amr.iter().any(|m| m == name);
    // AMR is issued by the existing TOTP/WebAuthn authentication endpoints, not
    // by enrollment. A method must still have a current account-owned credential.
    let stronger = totp
        .as_ref()
        .is_some_and(|c| c.created_at <= session.auth_time && method("totp"))
        || passkeys
            .iter()
            .any(|c| c.created_at <= session.auth_time && method("webauthn"));
    let no_stronger_factor = totp.is_none() && passkeys.is_empty();
    let password = method("pwd") && no_stronger_factor;
    let email = method("email")
        && no_stronger_factor
        && user.email_verified
        && state
            .realm(realm)
            .is_some_and(|runtime| runtime.email_magic_link.enabled);
    // Existing TOTP/WebAuthn proof is required whenever that factor is active.
    // Email and password are bootstrap methods only when no stronger factor is
    // configured, and must still satisfy an already enrolled push factor.
    if !(stronger
        || (password || email)
            && crate::auth::push_factor_satisfied(
                state.repo.as_ref(),
                &realm.into(),
                &session.user_id,
                &session.amr,
            )
            .await?)
    {
        return Err(invalid());
    }
    Ok(session)
}

// Bind the durable registration ID to the exact initiating browser session, with
// a domain-separated digest and a random prefix. No raw cookie or additional
// protocol/session state is stored in generic factor records. Never reuse IDs.
fn bound_id(prefix: &str, session: &Session) -> String {
    let binding = serde_json::json!([
        "qid:push:registration:session:v1",
        prefix,
        session.realm_id,
        session.user_id,
        session.id,
    ])
    .to_string();
    format!("{prefix}.{}", sha256_hex(binding.as_bytes()))
}
fn same_session(id: &str, session: &Session) -> bool {
    let Some((prefix, _)) = id.split_once('.') else {
        return false;
    };
    prefix.len() == 43
        && id.len() == 108
        && constant_time_eq(id.as_bytes(), bound_id(prefix, session).as_bytes())
}
async fn list<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    respond(list_inner(&state, &realm, &headers).await)
}
async fn list_inner<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> QidResult<Response> {
    // Account management stays available when push delivery is disabled.
    let session = owner_session(state, realm, headers).await?;
    let rows = state
        .repo
        .list_push_authenticators(&realm.into(), &session.user_id)
        .await?;
    let devices: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "registration_id": a.id,
                "device_name": a.device_name,
                "device_platform": a.device_platform,
                "created_at": a.created_at,
                "status": if a.revoked_at.is_none() { "active" } else { "revoked" },
            })
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "authenticators": devices })),
    )
        .into_response())
}
fn respond(result: QidResult<Response>) -> Response {
    // Uniform errors never expose destinations, nonces or provider diagnostics.
    super::push::protected(result.unwrap_or_else(|_| qid_http::error_response(invalid())))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    destination: String,
    device_name: String,
    device_platform: String,
    public_jwk: PushPublicJwk,
}
async fn start<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<StartRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return respond(Err(invalid()));
    };
    respond(start_inner(&state, &realm, &headers, req).await)
}
async fn start_inner<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
    req: StartRequest,
) -> QidResult<Response> {
    let session = recent_session(state, realm, headers).await?;
    let policy = &available(state, realm)?.mfa.push;
    if req.destination.trim().is_empty()
        || req.destination.len() > policy.max_destination_bytes
        || req.destination.chars().any(char::is_control)
        || !valid_push_device_metadata(&req.device_name)
        || !valid_push_device_metadata(&req.device_platform)
    {
        return Err(invalid());
    }
    qid_mfa::push::validate_public_key(&req.public_jwk)?;
    let _permit = state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| invalid())?;
    let now = now_seconds();
    let nonce = secret();
    let c = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: bound_id(&secret(), &session),
            realm_id: realm.into(),
            user_id: session.user_id,
            destination: req.destination,
            device_name: req.device_name,
            device_platform: req.device_platform,
            public_jwk: req.public_jwk,
            created_at: now,
            revoked_at: None,
        },
        nonce_verifier: sha256_hex(nonce.as_bytes()),
        expires_at: now + policy.ttl_seconds,
        max_attempts: policy.max_attempts,
        attempt_count: 0,
    };
    if !state
        .repo
        .try_issue_push_registration(
            &c,
            policy.max_issuances_per_window,
            policy.issuance_window_seconds,
        )
        .await?
    {
        return Err(invalid());
    }
    let notification = state
        .config
        .server
        .notification
        .as_ref()
        .ok_or_else(invalid)?;
    let delivery = NotificationRequest {
        channel: NotificationChannel::Push,
        provider: notification.provider.clone(),
        recipient: c.authenticator.destination.clone(),
        subject: Some("Register sign-in device".into()),
        body: "Confirm this device for push sign-in.".into(),
        template_id: None,
        data_json: serde_json::json!({
            "realm_id": realm, "user_id": c.authenticator.user_id,
            "registration_id": c.authenticator.id, "purpose": "registration",
            "nonce": nonce, "expires_at": c.expires_at,
        }),
    };
    let sent = tokio::time::timeout(
        std::time::Duration::from_secs(notification.timeout_seconds),
        state
            .notification_transport
            .as_ref()
            .ok_or_else(invalid)?
            .send(delivery),
    )
    .await;
    if !matches!(sent, Ok(Ok(ref response)) if response.sent) {
        return Err(invalid());
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "registration_id": c.authenticator.id, "expires_at": c.expires_at,
        })),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequest {
    registration_id: String,
    nonce: String,
    proof: String,
}
async fn finish<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<FinishRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return respond(Err(invalid()));
    };
    respond(finish_inner(&state, &realm, &headers, req).await)
}
async fn finish_inner<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
    req: FinishRequest,
) -> QidResult<Response> {
    let session = recent_session(state, realm, headers).await?;
    if !same_session(&req.registration_id, &session) {
        return Err(invalid());
    }
    let c = state
        .repo
        .get_push_registration(&realm.into(), &session.user_id, &req.registration_id)
        .await?
        .ok_or_else(invalid)?;
    let policy = &available(state, realm)?.mfa.push;
    let proof = (req.proof.len() <= policy.max_proof_bytes.div_ceil(3) * 4)
        .then(|| URL_SAFE_NO_PAD.decode(&req.proof).ok())
        .flatten();
    let verified = req.nonce.len() == 43
        && proof.as_deref().is_some_and(|proof| {
            proof.len() <= policy.max_proof_bytes
                && qid_mfa::push::verify_registration(&c, &req.nonce, proof).is_ok()
        });
    // Atomic storage spends failed attempts, checks immutable bindings, expiry
    // and one-use activation. Reads alone are never activation authority.
    let accepted = state
        .repo
        .attempt_push_registration(&c, verified, now_seconds())
        .await?;
    if !accepted || !verified {
        return Err(invalid());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    authenticator_id: String,
}
async fn revoke<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    request: Result<Json<RevokeRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(req)) = request else {
        return respond(Err(invalid()));
    };
    respond(
        async {
            // Revocation remains available during delivery outages or when disabled.
            let session = recent_session(&state, &realm, &headers).await?;
            if req.authenticator_id.is_empty()
                || req.authenticator_id.len() > 256
                || !state
                    .repo
                    .revoke_push_authenticator(
                        &realm.into(),
                        &session.user_id,
                        &req.authenticator_id,
                        now_seconds(),
                    )
                    .await?
            {
                return Err(invalid());
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
