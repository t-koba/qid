#![forbid(unsafe_code)]
mod session_auth;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use qid_core::{
    config::{RealmConfig, ServerPaths},
    error::QidError,
    state::SharedState,
};

use qid_storage::prelude::*;
use std::sync::Arc;

pub fn resource_routes<R>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .merge(device_routes::<R>())
        .merge(par_routes::<R>(paths))
        .merge(fedcm_routes::<R>())
        .merge(ciam_routes::<R>())
        .merge(spiffe_routes::<R>(paths))
}

pub fn device_routes<R>() -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route("/api/v1/:realm/devices", get(list_devices::<R>))
        .route("/api/v1/:realm/devices", post(register_device::<R>))
        .route(
            "/api/v1/:realm/devices/:device_id/heartbeat",
            put(device_heartbeat::<R>),
        )
}

pub fn spiffe_routes<R>(_paths: &ServerPaths) -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route(
            "/api/v1/:realm/spiffe/workload-api/x509-svid",
            get(spiffe::fetch_x509_svid),
        )
        .route(
            "/api/v1/:realm/spiffe/workload-api/jwt-svid",
            get(spiffe::fetch_jwt_svid),
        )
        .route(
            "/.well-known/spiffe-bundle",
            get(spiffe::spiffe_bundle_endpoint),
        )
}

pub fn par_routes<R>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new().route(&paths.par, post(push_authorization_request::<R>))
}

pub fn fedcm_routes<R>() -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route(
            "/.well-known/web-identity",
            get(fedcm_web_identity_manifest::<R>),
        )
        .route("/.well-known/fedcm.json", get(fedcm_well_known_config::<R>))
        .route(
            "/realms/:realm/.well-known/fedcm.json",
            get(fedcm_well_known_config_for_realm::<R>),
        )
        .route(
            "/api/v1/:realm/fedcm/accounts",
            get(list_fedcm_accounts::<R>),
        )
        .route(
            "/api/v1/:realm/fedcm/accounts",
            post(create_fedcm_identity::<R>),
        )
        .route(
            "/api/v1/:realm/fedcm/token",
            post(generate_fedcm_token::<R>),
        )
}

/// The realms of the deployment that enable the FedCM protocol.
///
/// The FedCM discovery documents describe these realms and nothing
/// else, so a document never names a realm the deployment does not
/// have or a realm that does not offer FedCM.
fn fedcm_realms<R: Repository>(state: &SharedState<R>) -> Vec<&RealmConfig> {
    state
        .config
        .realms
        .iter()
        .filter(|realm| realm.protocols.fedcm.enabled)
        .collect()
}

/// The FedCM configuration document of one realm: the endpoints a
/// FedCM client uses for that realm.
fn fedcm_config_document<R: Repository>(
    state: &SharedState<R>,
    realm: &RealmConfig,
) -> serde_json::Value {
    let base = state.plan.public_base_url.trim_end_matches('/');
    serde_json::json!({
        "supported_api_versions": ["1.0"],
        "id": realm.id,
        "name": realm.display_name.clone().unwrap_or_else(|| realm.id.clone()),
        "default_login_url": format!("{}{}", base, state.paths.authorize),
        "accounts_endpoint": format!("{base}/api/v1/{}/fedcm/accounts", realm.id),
        "id_assertion_endpoint": format!("{base}/api/v1/{}/fedcm/token", realm.id),
    })
}

/// FedCM browser-side API: `/.well-known/web-identity` (W3C FedID
/// Identity Provider Discovery draft). The manifest publishes the
/// IdP endpoints (`accounts_endpoint`, `id_assertion_endpoint`,
/// `login_url`, `branding`) so the FedCM browser API can discover
/// the IdP. Each realm that enables the FedCM protocol is listed as
/// a separate identity provider, and the provider `url` is that
/// realm's own FedCM configuration document, which the server serves.
async fn fedcm_web_identity_manifest<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
) -> Response {
    let realms = fedcm_realms(&state);
    if realms.is_empty() {
        return not_found_response("no realm enables the FedCM protocol");
    }
    let base = state.plan.public_base_url.trim_end_matches('/');
    let login_url = format!("{}{}", base, state.paths.authorize);
    let mut providers: Vec<serde_json::Value> = Vec::new();
    for realm in realms {
        providers.push(serde_json::json!({
            "id": realm.id,
            "name": realm.display_name.clone().unwrap_or_else(|| realm.id.clone()),
            "url": format!("{base}/realms/{}/.well-known/fedcm.json", realm.id),
            "accounts_endpoint": format!("{base}/api/v1/{}/fedcm/accounts", realm.id),
            "id_assertion_endpoint": format!("{base}/api/v1/{}/fedcm/token", realm.id),
            "login_url": login_url.clone(),
            "branding": {
                "background_color": "#1f2937",
                "color": "#ffffff",
                "icons": [],
            },
        }));
    }
    Json(serde_json::json!({
        "provider_lists": [{
            "providers": providers,
        }],
    }))
    .into_response()
}

/// FedCM `/.well-known/fedcm.json` endpoint (W3C FedCM
/// configuration). The document describes the realm that enables the
/// FedCM protocol. A deployment that enables it in several realms has
/// no single realm to describe, and says so instead of naming one.
async fn fedcm_well_known_config<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
) -> Response {
    let realms = fedcm_realms(&state);
    match realms.as_slice() {
        [] => not_found_response("no realm enables the FedCM protocol"),
        [realm] => Json(fedcm_config_document(&state, realm)).into_response(),
        _ => qid_http::error_response(QidError::BadRequest {
            message: "the FedCM configuration is ambiguous for multiple realms; use the realm-scoped configuration".to_string(),
        }),
    }
}

/// The FedCM configuration document of one realm, at the path the
/// provider manifest publishes. The realm must be a configured realm
/// that enables the FedCM protocol.
async fn fedcm_well_known_config_for_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm_id): Path<String>,
) -> Response {
    let Some(config) = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id && realm.protocols.fedcm.enabled)
    else {
        return not_found_response(&format!("no FedCM configuration for realm {realm_id}"));
    };
    Json(fedcm_config_document(&state, config)).into_response()
}

pub fn workload_routes<R>() -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route(
            "/api/v1/:realm/workload-identities",
            post(create_workload_identity::<R>),
        )
        .route(
            "/api/v1/:realm/workload-identities/:spiffe_id",
            get(get_workload_identity::<R>),
        )
        .route(
            "/api/v1/:realm/workload-certificates",
            get(list_workload_certificates::<R>),
        )
        .route(
            "/api/v1/:realm/workload-certificates",
            post(issue_workload_certificate::<R>),
        )
        .route(
            "/api/v1/:realm/workload-certificates/:certificate_id/revoke",
            post(revoke_workload_certificate::<R>),
        )
}

pub fn ciam_routes<R>() -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route("/api/v1/:realm/ciam/profile/plan", post(profile_plan))
        .route(
            "/api/v1/:realm/ciam/profile/submit",
            post(profile_submit::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/passwordless/migrate",
            post(passwordless_migrate::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/passwordless/campaign",
            get(passwordless_campaign::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/consent/evaluate",
            post(consent_evaluate::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/consent/grants",
            post(consent_grant::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/identity-links",
            post(identity_link_create::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/identity-links/lookup",
            post(identity_link_lookup::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/users/:user_id/identity-links",
            get(identity_links_list::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/identity-links/:link_id",
            delete(identity_link_delete::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/privacy/:user_id",
            get(privacy_dashboard::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/verification/issue",
            post(verification_issue::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/verification/confirm",
            post(verification_confirm::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/password-reset/issue",
            post(password_reset_issue::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/password-reset/consume",
            post(password_reset_consume::<R>),
        )
        .route(
            "/api/v1/:realm/ciam/protection/evaluate",
            post(protection_evaluate::<R>),
        )
}

pub(crate) fn not_found_response(msg: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

//
pub mod ciam;
mod device;
pub mod eat;
mod fedcm;
mod par;
mod spiffe;
mod workload;
mod workload_auth;

pub use eat::{
    CorimEntry, CoswidEntity, CoswidEntry, CoswidEvidence, EatClaims, EatProfile, SpiffeJwtSvid,
    SpiffeX509Svid, coswid_fingerprint, validate_spiffe_id,
};

pub use ciam::*;
pub(crate) use device::*;
pub(crate) use fedcm::*;
pub(crate) use par::*;
pub(crate) use workload::*;
