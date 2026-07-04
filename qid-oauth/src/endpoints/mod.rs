//! OAuth 2.0 endpoints.

use axum::{
    Router,
    routing::{get, post},
};
use qid_core::config::{OAuthProtocolConfig, TokenTtlConfig};
use qid_core::{config::ServerPaths, state::SharedState};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Add OAuth endpoint routes with configurable paths.
pub fn routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    signed_routes::<R>(paths).merge(unsigned_routes::<R>(paths))
}

/// Routes that may be placed behind RFC 9421 HTTP Message Signature
/// verification for FAPI-style back-channel ingress. Public metadata and
/// browser front-channel endpoints must stay outside this router.
pub fn signed_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(&paths.token, post(token))
        .route(&paths.introspect, post(introspect))
        .route(&paths.revoke, post(revoke))
        .route(
            &paths.dynamic_client_registration,
            post(dynamic_client_registration),
        )
        .route(
            &paths.dynamic_client_registration_management,
            get(dynamic_client_registration_get)
                .put(dynamic_client_registration_update)
                .delete(dynamic_client_registration_delete),
        )
}

/// OAuth routes that must remain reachable without message signatures.
pub fn unsigned_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    let device_approval_path = format!("{}/approve", paths.device_authorization);
    let ciba_approval_path = format!("{}/approve", paths.backchannel_authentication);
    Router::new()
        .route(&paths.device_authorization, post(device_authorization))
        .route(&device_approval_path, post(device_authorization_approve))
        .route(
            &paths.backchannel_authentication,
            post(backchannel_authentication),
        )
        .route(
            &ciba_approval_path,
            post(backchannel_authentication_approve),
        )
        .route("/oauth2/challenge", post(challenge::<R>))
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub device_code: Option<String>,
    pub auth_req_id: Option<String>,
    pub assertion: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub response_format: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_format: Option<qid_core::models::TokenFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_introspection: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub(crate) fn token_ttl<R: Repository>(state: &SharedState<R>, realm_id: &str) -> TokenTtlConfig {
    state
        .realm(realm_id)
        .map(|realm| realm.token_ttl.clone())
        .unwrap_or_default()
}

pub(crate) fn oauth_feature_enabled<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    feature: impl FnOnce(&OAuthProtocolConfig) -> bool,
) -> bool {
    state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .is_some_and(|realm| feature(&realm.protocols.oauth))
}

mod challenge;
mod ciba;
mod dcr;
mod device_flow;
mod introspect;
mod revoke;
mod token;
mod token_grant;
mod token_issue;

pub use challenge::challenge;
pub(crate) use ciba::ciba_grant;
pub use ciba::{backchannel_authentication, backchannel_authentication_approve};
pub use dcr::{
    dynamic_client_registration, dynamic_client_registration_delete,
    dynamic_client_registration_get, dynamic_client_registration_update,
};
pub(crate) use device_flow::device_code_grant;
pub use device_flow::{device_authorization, device_authorization_approve};
pub use introspect::{
    decode_access_token, enforce_sender_constrained_access_token, extract_bearer_token, introspect,
};
pub use revoke::revoke;
pub use token::token;
pub(crate) use token::{extract_basic_client_auth, verify_client_secret};
pub use token_grant::{authorization_code_grant, client_credentials_grant, refresh_token_grant};
pub use token_issue::{
    TokenIssueClaims, access_token_type_for_cnf, decode_opaque_access_token,
    encode_opaque_access_token, format_access_token, issue_access_token, issue_id_token,
    issue_token_pair, sign_access_token, sign_refresh_token,
};

pub(crate) use token_issue::generate_jti;
