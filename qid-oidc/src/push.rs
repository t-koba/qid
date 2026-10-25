//! OIDC owns the validated protocol continuation; device approval alone issues nothing.
use super::*;
use axum::{
    Json,
    http::{HeaderValue, StatusCode},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use qid_core::{
    models::{OidcAuthorizationContinuation, PushDecision},
    util::{now_seconds, sha256_hex},
};
use qid_session::push::{self as factor, DecisionRequest};
use rand::RngCore;
use sha2::{Digest, Sha256};

const COOKIE: &str = "__Host-qid-oidc-push";

// Only a derived DPoP thumbprint is retained, never a reusable proof JWT.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    request: AuthorizeParameters,
    auth_time: u64,
}

fn secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn invalid() -> QidError {
    unauthorized("push authentication is not available")
}
fn protected(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

pub(super) async fn start<R: Repository>(
    state: &SharedState<R>,
    mut request: AuthorizeParameters,
    client: &Client,
    auth: &qid_session::auth::AuthResult,
) -> QidResult<Response> {
    if auth.user.realm_id != client.realm_id
        || state
            .plan
            .realms
            .iter()
            .any(|r| r.browser_session.cookie_name == COOKIE)
    {
        return Err(invalid());
    }
    let binding = secret();
    let pending = factor::prepare(
        state,
        &client.realm_id,
        &auth.user.id,
        verifier(&binding, &client.client_id),
    )
    .await?;
    let challenge = &pending.challenge;
    let now = challenge.created_at;
    request.dpop_apv = dpop_apv_for_request(client, request.dpop_proof.as_deref());
    request.dpop_proof = None;
    let envelope = Envelope {
        version: 1,
        request,
        auth_time: now,
    };
    let continuation = OidcAuthorizationContinuation {
        id: challenge.id.clone(),
        realm_id: client.realm_id.clone(),
        user_id: auth.user.id.clone(),
        client_id: client.client_id.clone(),
        context_json: serde_json::to_string(&envelope).map_err(|_| invalid())?,
        browser_binding_sha256: Sha256::digest(binding.as_bytes()).into(),
        created_at: now,
        expires_at: challenge.expires_at,
    };
    state
        .repo
        .create_oidc_continuation(&continuation, now)
        .await?;
    let challenge = pending.send(state).await?;
    let mut response = protected((StatusCode::ACCEPTED, Json(serde_json::json!({"transaction_number": factor::transaction_number(&challenge), "challenge": "push_required", "challenge_id": challenge.id, "realm_id": challenge.realm_id, "user_id": challenge.user_id, "client_id": client.client_id, "expires_at": challenge.expires_at}))).into_response());
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={binding}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            challenge.expires_at - challenge.created_at
        ))
        .map_err(|_| invalid())?,
    );
    Ok(response)
}

pub(crate) async fn decision<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<DecisionRequest>,
) -> Response {
    protected(match factor::record_decision(&state, req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => qid_http::error_response(e),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompleteRequest {
    realm_id: String,
    user_id: String,
    client_id: String,
    challenge_id: String,
}

pub(crate) async fn complete<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Response {
    protected(match resume(&state, &headers, req).await {
        Ok(response) => response,
        Err(e) => qid_http::error_response(e),
    })
}
async fn resume<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    req: CompleteRequest,
) -> QidResult<Response> {
    let binding = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_cookie(v, COOKIE))
        .filter(|v| v.len() == 43 && URL_SAFE_NO_PAD.decode(v).is_ok_and(|b| b.len() == 32))
        .ok_or_else(invalid)?;
    let realm_id = req.realm_id.clone().into();
    factor::available(state, &req.realm_id)?;
    if state
        .plan
        .realms
        .iter()
        .any(|r| r.browser_session.cookie_name == COOKIE)
    {
        return Err(invalid());
    }
    let c = state
        .repo
        .get_push_login(&realm_id, &req.user_id, &req.challenge_id)
        .await?
        .ok_or_else(invalid)?;
    // Check readiness before consuming protocol context. A wrong browser cannot
    // spend either record. A wrong client cannot spend device approval.
    if c.decision != Some(PushDecision::Approve)
        || c.consumed_at.is_some()
        || now_seconds() >= c.expires_at
        || verifier(&binding, &req.client_id) != c.browser_binding_verifier
    {
        return Err(invalid());
    }
    let record = state
        .repo
        .consume_oidc_continuation(
            &realm_id,
            &req.user_id,
            &req.client_id,
            &req.challenge_id,
            &Sha256::digest(binding.as_bytes()).into(),
            now_seconds(),
        )
        .await?
        .ok_or_else(invalid)?;
    let envelope: Envelope = serde_json::from_str(&record.context_json).map_err(|_| invalid())?;
    let resolved = envelope.request;
    if envelope.version != 1
        || resolved.client_id != req.client_id
        || envelope.auth_time != record.created_at
        || c.created_at != record.created_at
        || c.expires_at != record.expires_at
    {
        return Err(invalid());
    }
    let client = state
        .repo
        .get_client_by_client_id(&realm_id, &req.client_id)
        .await?
        .ok_or_else(invalid)?;
    validate_authorize_request(state, &resolved, &client)?;
    let auth = factor::complete_password(state, &c, &verifier(&binding, &req.client_id)).await?;
    // Never resolve the original request or consume PAR again. max_age and
    // prompt were applied before password reauthentication; auth_time is that
    // reauthentication time, not delayed device/browser completion time.
    let code =
        issue_authorization_code(state, &client, &auth, envelope.auth_time, &resolved).await?;
    authorization_response_redirect(state, &resolved, &client, &code, None).await
}

// Include client identity so a resend with a substituted client cannot spend quota.
fn verifier(binding: &str, client: &str) -> String {
    sha256_hex(
        serde_json::json!(["qid:oidc:push:v1", client, binding])
            .to_string()
            .as_bytes(),
    )
}
pub(crate) async fn resend<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Response {
    protected(match resend_bound(&state, &headers, req).await {
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
    headers: &HeaderMap,
    req: CompleteRequest,
) -> QidResult<qid_core::models::PushLoginChallenge> {
    if state
        .plan
        .realms
        .iter()
        .any(|r| r.browser_session.cookie_name == COOKIE)
    {
        return Err(invalid());
    }
    let binding = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_cookie(v, COOKIE))
        .filter(|v| v.len() == 43 && URL_SAFE_NO_PAD.decode(v).is_ok_and(|b| b.len() == 32))
        .ok_or_else(invalid)?;
    // No continuation retrieval/consumption: the client is bound by its verifier.
    factor::resend(
        state,
        &req.realm_id,
        &req.user_id,
        &req.challenge_id,
        &verifier(&binding, &req.client_id),
    )
    .await
}
