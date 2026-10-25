//! Direct password-login completion. Browser state is not an OIDC continuation.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{error::QidResult, state::SharedState, util::sha256_hex};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    auth::AuthResult,
    push::{self as factor, invalid},
};

const COOKIE: &str = "__Host-qid-password-push";

pub(super) fn protected(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

// Separate from OIDC's browser verifier even if a cookie is manually substituted.
fn verifier(binding: &str) -> String {
    sha256_hex(format!("qid:session:password-push:v1:{binding}").as_bytes())
}

fn check_cookie<R: Repository>(state: &SharedState<R>) -> QidResult<()> {
    if state
        .plan
        .realms
        .iter()
        .any(|r| r.browser_session.cookie_name == COOKIE)
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) async fn start<R: Repository>(
    state: &SharedState<R>,
    auth: &AuthResult,
) -> QidResult<Response> {
    check_cookie(state)?;
    let binding = factor::secret();
    let pending = factor::prepare(
        state,
        &auth.user.realm_id,
        &auth.user.id,
        verifier(&binding),
    )
    .await?;
    let challenge = pending.send(state).await?;
    let mut response = (StatusCode::ACCEPTED, Json(serde_json::json!({
        "transaction_number": factor::transaction_number(&challenge), "challenge": "push_required", "challenge_id": challenge.id, "realm_id": challenge.realm_id, "user_id": challenge.user_id, "expires_at": challenge.expires_at
    }))).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={binding}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            challenge.expires_at - challenge.created_at
        ))
        .map_err(|_| invalid())?,
    );
    Ok(protected(response))
}

pub(super) async fn decision<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Json(req): Json<factor::DecisionRequest>,
) -> Response {
    // The path is authoritative; never accept a different realm in the body.
    protected(
        match factor::record_decision_in_realm(&state, &realm, req).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => qid_http::error_response(e),
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompleteRequest {
    user_id: String,
    challenge_id: String,
}

pub(super) async fn complete<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Response {
    protected(match finish(&state, &realm, &headers, req).await {
        Ok(response) => response,
        Err(e) => qid_http::error_response(e),
    })
}

async fn finish<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
    req: CompleteRequest,
) -> QidResult<Response> {
    check_cookie(state)?;
    factor::available(state, realm)?;
    let binding = super::extract_cookie(headers, COOKIE)
        .filter(|v| v.len() == 43 && URL_SAFE_NO_PAD.decode(v).is_ok_and(|b| b.len() == 32))
        .ok_or_else(invalid)?;
    let challenge = state
        .repo
        .get_push_login(&realm.into(), &req.user_id, &req.challenge_id)
        .await?
        .ok_or_else(invalid)?;
    // Only this server-issued password transaction plus atomic device approval
    // may produce pwd+push AMR; neither method comes from the request body.
    let auth = factor::complete_password(state, &challenge, &verifier(&binding)).await?;
    let mut response = super::password::establish_session(state, realm, headers, auth).await?;
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-qid-password-push=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    Ok(response)
}

pub(super) async fn resend<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Response {
    protected(match resend_bound(&state, &realm, &headers, req).await {
        Ok(c) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"challenge_id": c.id,
            "realm_id": c.realm_id, "user_id": c.user_id, "expires_at": c.expires_at,
            "transaction_number": factor::transaction_number(&c)})),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    })
}
async fn resend_bound<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    headers: &HeaderMap,
    req: CompleteRequest,
) -> QidResult<qid_core::models::PushLoginChallenge> {
    check_cookie(state)?;
    let binding = super::extract_cookie(headers, COOKIE)
        .filter(|v| v.len() == 43 && URL_SAFE_NO_PAD.decode(v).is_ok_and(|b| b.len() == 32))
        .ok_or_else(invalid)?;
    factor::resend(
        state,
        realm,
        &req.user_id,
        &req.challenge_id,
        &verifier(&binding),
    )
    .await
}
