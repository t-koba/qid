//! OIDC Provider routes.

use crate::provider::{authorize_get, authorize_post};
use axum::{
    Form, Json, Router,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderValue, Method, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use qid_core::{
    config::{OAuthProtocolConfig, OAuthResourceServerConfig, OidcProtocolConfig, ServerPaths},
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::Client,
    state::SharedState,
    tenant::RealmId,
    util,
};
use qid_storage::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;

async fn build_logout_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    user_id: &str,
    sid: Option<&str>,
    client: &Client,
) -> Option<String> {
    let now = util::now_seconds() as usize;

    // Get the user to include in the logout token
    let user = state.repo.get_user_by_id(user_id).await.ok().flatten();

    // Build claims for logout token
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: user.as_ref().map(|u| u.id.clone()),
        aud: Some(client.client_id.clone()),
        exp: Some(now + 300), // 5 minutes
        nbf: Some(now),
        iat: Some(now),
        jti: Some(ulid::Ulid::new().to_string()),
        extra: {
            let mut extra = HashMap::new();
            extra.insert(
                "events".to_string(),
                json!({
                    "http://schemas.openid.net/event/backchannel-logout": {}
                }),
            );
            if let Some(sid) = sid {
                extra.insert("sid".to_string(), json!(sid));
            }
            extra
        },
    };

    // Sign the logout token
    state.signer.sign(&claims).ok()
}

async fn send_backchannel_logout(logout_uri: &str, logout_token: &str) -> QidResult<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|error| QidError::Internal {
            message: format!("failed to build backchannel logout client: {error}"),
        })?;
    let response = client
        .post(logout_uri)
        .form(&[("logout_token", logout_token)])
        .send()
        .await
        .map_err(|error| QidError::Internal {
            message: format!("backchannel logout POST failed: {error}"),
        })?;
    if !response.status().is_success() {
        return Err(QidError::BadRequest {
            message: format!(
                "backchannel logout endpoint returned HTTP {}",
                response.status()
            ),
        });
    }
    Ok(())
}

/// Build OIDC discovery routes with shared state and configurable paths.
pub fn routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            &paths.well_known_openid_configuration,
            get(openid_configuration),
        )
        .route(
            &paths.well_known_oauth_authorization_server,
            get(oauth_authorization_server),
        )
        .route(
            &paths.well_known_oauth_protected_resource,
            get(oauth_protected_resource),
        )
        .route(
            "/realms/:realm/.well-known/openid-configuration",
            get(openid_configuration_for_realm::<R>),
        )
        .route(
            "/.well-known/oauth-authorization-server/realms/:realm",
            get(oauth_authorization_server_for_realm::<R>),
        )
        .route(
            "/realms/:realm/session/check",
            get(check_session_iframe_for_realm::<R>),
        )
        .route(&paths.authorize, get(authorize_get).post(authorize_post))
        .route(&paths.userinfo, get(userinfo))
        .route(&paths.logout, post(logout))
        .route(&paths.backchannel_logout, post(backchannel_logout))
        .route(&paths.frontchannel_logout, get(frontchannel_logout))
        .route("/session/check", get(check_session_iframe::<R>))
        .route("/.well-known/webfinger", get(webfinger::<R>))
}

async fn openid_configuration<R: Repository>(State(state): State<Arc<SharedState<R>>>) -> Response {
    openid_configuration_response(&state, None)
}

async fn openid_configuration_for_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
) -> Response {
    openid_configuration_response(&state, Some(&realm))
}

fn openid_configuration_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: Option<&str>,
) -> Response {
    let base = state.plan.public_base_url.trim_end_matches('/');
    let realm = match metadata_realm(state, realm_id) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let issuer = realm.issuer.clone();
    let oauth = Some(&realm.protocols.oauth);
    let oidc = Some(&realm.protocols.oidc);
    let oidc_config = &realm.protocols.oidc;
    if !oidc_config.enabled {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC is disabled".to_string(),
        });
    }
    let grant_types = grant_types_supported(oauth, Some(oidc_config));
    let auth_methods = token_endpoint_auth_methods_supported(oauth);
    let mut metadata = Map::new();
    metadata.insert("issuer".to_string(), json!(issuer));
    if oidc_config.authorization_code.enabled {
        metadata.insert(
            "authorization_endpoint".to_string(),
            json!(format!("{}{}", base, state.paths.authorize)),
        );
    }
    metadata.insert(
        "token_endpoint".to_string(),
        json!(format!("{}{}", base, state.paths.token)),
    );
    if oidc_config.userinfo {
        metadata.insert(
            "userinfo_endpoint".to_string(),
            json!(format!("{}{}", base, state.paths.userinfo)),
        );
    }
    metadata.insert(
        "jwks_uri".to_string(),
        json!(format!("{}{}", base, state.paths.jwks)),
    );
    if oidc_config.session_management {
        let check_session_iframe = if realm_id.is_some() {
            format!("{}/realms/{}/session/check", base, realm.id)
        } else {
            format!("{}/session/check", base)
        };
        metadata.insert(
            "check_session_iframe".to_string(),
            json!(check_session_iframe),
        );
    }
    insert_optional_oauth_endpoints(&mut metadata, base, &state.paths, oauth);
    if oidc_config.logout.backchannel || oidc_config.logout.frontchannel {
        metadata.insert(
            "end_session_endpoint".to_string(),
            json!(format!("{}{}", base, state.paths.logout)),
        );
    }
    metadata.insert(
        "backchannel_logout_supported".to_string(),
        json!(oidc_config.logout.backchannel),
    );
    metadata.insert(
        "frontchannel_logout_supported".to_string(),
        json!(oidc_config.logout.frontchannel),
    );
    metadata.insert(
        "response_types_supported".to_string(),
        if oidc_config.authorization_code.enabled {
            json!(["code"])
        } else {
            json!([])
        },
    );
    metadata.insert("grant_types_supported".to_string(), json!(grant_types));
    metadata.insert(
        "subject_types_supported".to_string(),
        json!(["public", "pairwise"]),
    );
    metadata.insert(
        "id_token_signing_alg_values_supported".to_string(),
        json!(["ES256"]),
    );
    metadata.insert(
        "token_endpoint_auth_methods_supported".to_string(),
        json!(auth_methods),
    );
    metadata.insert(
        "code_challenge_methods_supported".to_string(),
        json!(["S256"]),
    );
    metadata.insert(
        "scopes_supported".to_string(),
        json!(
            oidc_config
                .default_scope
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        ),
    );
    metadata.insert("request_parameter_supported".to_string(), json!(true));
    metadata.insert("request_uri_parameter_supported".to_string(), json!(true));
    metadata.insert(
        "request_object_signing_alg_values_supported".to_string(),
        json!(request_object_alg_values_supported(oidc)),
    );
    metadata.insert(
        "response_modes_supported".to_string(),
        json!(response_modes_supported(oauth, true)),
    );
    Json(Value::Object(metadata)).into_response()
}

async fn oauth_authorization_server<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
) -> Response {
    oauth_authorization_server_response(&state, None)
}

async fn oauth_authorization_server_for_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
) -> Response {
    oauth_authorization_server_response(&state, Some(&realm))
}

fn oauth_authorization_server_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: Option<&str>,
) -> Response {
    let base = state.plan.public_base_url.trim_end_matches('/');
    let realm = match metadata_realm(state, realm_id) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    let issuer = realm.issuer.clone();
    let oauth = Some(&realm.protocols.oauth);
    let oidc = Some(&realm.protocols.oidc);
    let grant_types = grant_types_supported(oauth, oidc);
    let auth_methods = token_endpoint_auth_methods_supported(oauth);
    let subject_token_types = subject_token_types_supported();
    let protected_resources =
        protected_resource_identifiers(&realm.protocols.oauth.resource_servers);
    let mut metadata = Map::new();
    metadata.insert("issuer".to_string(), json!(issuer));
    metadata.insert(
        "token_endpoint".to_string(),
        json!(format!("{}{}", base, state.paths.token)),
    );
    metadata.insert(
        "authorization_endpoint".to_string(),
        json!(format!("{}{}", base, state.paths.authorize)),
    );
    insert_optional_oauth_endpoints(&mut metadata, base, &state.paths, oauth);
    if oauth.is_some_and(|o| o.introspection.enabled) {
        metadata.insert(
            "introspection_endpoint".to_string(),
            json!(format!("{}{}", base, state.paths.introspect)),
        );
    }
    if oauth.is_some_and(|o| o.revocation.enabled) {
        metadata.insert(
            "revocation_endpoint".to_string(),
            json!(format!("{}{}", base, state.paths.revoke)),
        );
    }
    metadata.insert(
        "jwks_uri".to_string(),
        json!(format!("{}{}", base, state.paths.jwks)),
    );
    metadata.insert("grant_types_supported".to_string(), json!(grant_types));
    metadata.insert(
        "token_endpoint_auth_methods_supported".to_string(),
        json!(auth_methods),
    );
    metadata.insert(
        "code_challenge_methods_supported".to_string(),
        json!(["S256"]),
    );
    metadata.insert(
        "token_endpoint_auth_signing_alg_values_supported".to_string(),
        json!(["ES256"]),
    );
    metadata.insert(
        "subject_token_types_supported".to_string(),
        json!(subject_token_types),
    );
    metadata.insert(
        "protected_resources".to_string(),
        json!(protected_resources),
    );
    metadata.insert(
        "authorization_response_iss_parameter_supported".to_string(),
        json!(true),
    );
    metadata.insert(
        "dpop_signing_alg_values_supported".to_string(),
        if oauth.is_some_and(|o| o.dpop.enabled) {
            json!(["ES256", "EdDSA", "RS256"])
        } else {
            json!([])
        },
    );
    metadata.insert("request_parameter_supported".to_string(), json!(true));
    metadata.insert("request_uri_parameter_supported".to_string(), json!(true));
    metadata.insert(
        "request_object_signing_alg_values_supported".to_string(),
        json!(request_object_alg_values_supported(oidc)),
    );
    metadata.insert(
        "response_modes_supported".to_string(),
        json!(response_modes_supported(oauth, false)),
    );
    Json(Value::Object(metadata)).into_response()
}

fn insert_optional_oauth_endpoints(
    metadata: &mut Map<String, Value>,
    base: &str,
    paths: &ServerPaths,
    oauth: Option<&OAuthProtocolConfig>,
) {
    if oauth.is_some_and(|o| o.par.enabled) {
        metadata.insert(
            "pushed_authorization_request_endpoint".to_string(),
            json!(format!("{}{}", base, paths.par)),
        );
        if oauth.is_some_and(|o| o.require_pushed_authorization_requests) {
            metadata.insert(
                "require_pushed_authorization_requests".to_string(),
                json!(true),
            );
        }
    }
    if oauth.is_some_and(|o| o.device_authorization.enabled) {
        metadata.insert(
            "device_authorization_endpoint".to_string(),
            json!(format!("{}{}", base, paths.device_authorization)),
        );
    }
    if oauth.is_some_and(|o| o.ciba.enabled) {
        metadata.insert(
            "backchannel_authentication_endpoint".to_string(),
            json!(format!("{}{}", base, paths.backchannel_authentication)),
        );
    }
    if oauth.is_some_and(|o| o.dynamic_client_registration.enabled) {
        metadata.insert(
            "registration_endpoint".to_string(),
            json!(format!("{}{}", base, paths.dynamic_client_registration)),
        );
        metadata.insert(
            "registration_management_endpoint".to_string(),
            json!(format!(
                "{}{}",
                base, paths.dynamic_client_registration_management
            )),
        );
    }
}

fn metadata_realm<'a, R: Repository>(
    state: &'a SharedState<R>,
    realm_id: Option<&str>,
) -> QidResult<&'a qid_core::config::RealmConfig> {
    if let Some(realm_id) = realm_id {
        return state
            .config
            .realms
            .iter()
            .find(|realm| realm.id == realm_id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("realm {realm_id}"),
            });
    }
    let mut realms = state.config.realms.iter();
    let Some(first) = realms.next() else {
        return Err(QidError::BadRequest {
            message: "no realm is configured".to_string(),
        });
    };
    if realms.next().is_some() {
        return Err(QidError::BadRequest {
            message: "global OIDC/OAuth metadata is ambiguous for multiple realms; use realm-scoped discovery".to_string(),
        });
    }
    let global_issuer = state.plan.public_base_url.trim_end_matches('/');
    if first.issuer.trim_end_matches('/') != global_issuer {
        return Err(QidError::BadRequest {
            message: "global OIDC/OAuth metadata is only available when the realm issuer matches server.public_base_url; use realm-scoped discovery".to_string(),
        });
    }
    Ok(first)
}

fn realm_by_issuer<'a, R: Repository>(
    state: &'a SharedState<R>,
    issuer: &str,
) -> Option<&'a qid_core::config::RealmConfig> {
    state
        .config
        .realms
        .iter()
        .find(|realm| realm.issuer == issuer)
}

fn grant_types_supported(
    oauth: Option<&OAuthProtocolConfig>,
    oidc: Option<&OidcProtocolConfig>,
) -> Vec<&'static str> {
    let mut grant_types = vec!["client_credentials", "refresh_token"];
    if oidc.is_some_and(|o| o.enabled && o.authorization_code.enabled) {
        grant_types.push("authorization_code");
    }
    if oauth.is_some_and(|o| o.device_authorization.enabled) {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code");
    }
    if oauth.is_some_and(|o| o.ciba.enabled) {
        grant_types.push("urn:openid:params:grant-type:ciba");
    }
    grant_types
}

fn token_endpoint_auth_methods_supported(oauth: Option<&OAuthProtocolConfig>) -> Vec<&'static str> {
    let mut auth_methods = vec!["client_secret_basic", "client_secret_post", "none"];
    if oauth.is_some_and(|o| o.private_key_jwt.enabled) {
        auth_methods.push("private_key_jwt");
    }
    if oauth.is_some_and(|o| o.mtls.enabled) {
        auth_methods.push("tls_client_auth");
        auth_methods.push("self_signed_tls_client_auth");
    }
    auth_methods
}

fn response_modes_supported(
    oauth: Option<&OAuthProtocolConfig>,
    include_form_post: bool,
) -> Vec<&'static str> {
    if oauth.is_some_and(|oauth| oauth.jarm.enabled) {
        return vec!["jwt"];
    }
    let mut modes = vec!["query"];
    if include_form_post {
        modes.push("form_post");
    }
    modes
}

fn request_object_alg_values_supported(oidc: Option<&OidcProtocolConfig>) -> Vec<String> {
    oidc.map(|oidc| {
        oidc.authorization_code
            .request_object_signing_alg_values
            .clone()
    })
    .unwrap_or_default()
}

fn subject_token_types_supported() -> Vec<&'static str> {
    vec![
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:jwt",
        "urn:ietf:params:oauth:token-type:saml2",
    ]
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceQuery {
    resource: Option<String>,
    audience: Option<String>,
}

async fn oauth_protected_resource<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Query(query): Query<ProtectedResourceQuery>,
) -> Response {
    let base = state.plan.public_base_url.trim_end_matches('/');
    let jwks_uri = format!("{}{}", base, state.paths.jwks);
    let Some((realm, resource_server)) = select_realm_resource_server(&state, &query) else {
        return qid_http::error_response(QidError::BadRequest {
            message: "resource or audience must identify a configured protected resource"
                .to_string(),
        });
    };
    Json(json!({
        "resource": resource_server
            .resources
            .first()
            .cloned()
            .unwrap_or_else(|| resource_server.audience.clone()),
        "audience": resource_server.audience.clone(),
        "resource_indicators_supported": resource_server.resources.clone(),
        "authorization_servers": [realm.issuer.clone()],
        "jwks_uri": jwks_uri,
        "bearer_methods_supported": ["header"],
        "scopes_supported": resource_server.scopes.clone(),
        "sender_constrained_access_tokens": resource_server.require_sender_constraint || resource_server.high_risk,
        "resource_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": if realm.protocols.oauth.dpop.enabled { json!(["ES256", "EdDSA", "RS256"]) } else { json!([]) },
        "mtls_endpoint_aliases_supported": realm.protocols.oauth.mtls.enabled,
    }))
    .into_response()
}

fn select_realm_resource_server<'a, R: Repository>(
    state: &'a SharedState<R>,
    query: &ProtectedResourceQuery,
) -> Option<(
    &'a qid_core::config::RealmConfig,
    &'a OAuthResourceServerConfig,
)> {
    let mut found = None;
    for realm in &state.config.realms {
        if let Some(resource_server) =
            select_resource_server(&realm.protocols.oauth.resource_servers, query)
        {
            if found.is_some() {
                return None;
            }
            found = Some((realm, resource_server));
        }
    }
    found
}

fn protected_resource_identifiers(resource_servers: &[OAuthResourceServerConfig]) -> Vec<String> {
    resource_servers
        .iter()
        .flat_map(|server| {
            let mut identifiers = Vec::with_capacity(server.resources.len() + 1);
            identifiers.push(server.audience.clone());
            identifiers.extend(server.resources.iter().cloned());
            identifiers
        })
        .collect()
}

fn select_resource_server<'a>(
    resource_servers: &'a [OAuthResourceServerConfig],
    query: &ProtectedResourceQuery,
) -> Option<&'a OAuthResourceServerConfig> {
    if let Some(audience) = &query.audience {
        return resource_servers
            .iter()
            .find(|server| server.audience == *audience);
    }
    if let Some(resource) = &query.resource {
        return resource_servers.iter().find(|server| {
            server.audience == *resource
                || server
                    .resources
                    .iter()
                    .any(|candidate| candidate == resource)
        });
    }
    if resource_servers.len() == 1 {
        resource_servers.first()
    } else {
        None
    }
}

async fn userinfo<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !state
        .config
        .realms
        .iter()
        .any(|realm| realm.protocols.oidc.enabled && realm.protocols.oidc.userinfo)
    {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC UserInfo is disabled".to_string(),
        });
    }
    let token = match qid_oauth::endpoints::extract_bearer_token(&headers) {
        Ok(token) => token,
        Err(_) => {
            return qid_http::oauth_error_response_with_bearer(
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "missing bearer access token",
            );
        }
    };
    let decoded = match qid_oauth::endpoints::decode_access_token(&state, token).await {
        Ok(data) => data,
        Err(_) => {
            return qid_http::oauth_error_response_with_bearer(
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "failed to verify access token",
            );
        }
    };
    let Some(realm) = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == decoded.realm_id)
    else {
        return qid_http::oauth_error_response_with_bearer(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            "token realm is not configured",
        );
    };
    if !realm.protocols.oidc.enabled || !realm.protocols.oidc.userinfo {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC UserInfo is disabled for token realm".to_string(),
        });
    }
    let htu = format!(
        "{}{}",
        state.plan.public_base_url.trim_end_matches('/'),
        state.paths.userinfo
    );
    if let Err(error) = qid_oauth::endpoints::enforce_sender_constrained_access_token(
        &state,
        &headers,
        &Method::GET,
        &htu,
        token,
        &decoded,
    ) {
        return qid_http::oauth_error_response_with_bearer(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            &error.to_string(),
        );
    }
    let sub = decoded.user_id;
    let scope = decoded.scope;

    let mut result = serde_json::Map::new();
    result.insert("sub".to_string(), serde_json::Value::String(sub.clone()));

    let scopes: Vec<&str> = scope.split(' ').collect();
    if scopes.contains(&"email")
        && let Ok(Some(user)) = state.repo.get_user_by_id(&sub).await
        && let Some(email) = user.email
    {
        result.insert("email".to_string(), serde_json::Value::String(email));
    }
    if scopes.contains(&"profile")
        && let Ok(Some(user)) = state.repo.get_user_by_id(&sub).await
        && let Some(name) = user.display_name
    {
        result.insert("name".to_string(), serde_json::Value::String(name));
    }

    Json(result).into_response()
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    id_token_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BackchannelLogoutRequest {
    logout_token: String,
}

async fn logout<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    OriginalUri(original_uri): OriginalUri,
    headers: axum::http::HeaderMap,
    Form(form): Form<LogoutRequest>,
) -> Response {
    let mut logout_realm_id = None;
    let mut logout_issuer = None;

    let cookie_header = headers.get(header::COOKIE).and_then(|c| c.to_str().ok());

    // RP-Initiated Logout 1.0 §2.4: validate id_token_hint if present
    if let Some(ref hint) = form.id_token_hint {
        match state.signer.decode_signature_only(hint) {
            Ok(data) => {
                let claims = &data.claims;
                let Some(realm) = claims
                    .iss
                    .as_deref()
                    .and_then(|iss| realm_by_issuer(&state, iss))
                else {
                    return qid_http::error_response(QidError::BadRequest {
                        message: "id_token_hint iss does not match a configured realm issuer"
                            .to_string(),
                    });
                };
                logout_realm_id = Some(realm.id.clone());
                logout_issuer = Some(realm.issuer.clone());
                // Validate sub is present
                if claims.sub.is_none() {
                    return qid_http::error_response(QidError::BadRequest {
                        message: "id_token_hint missing sub".to_string(),
                    });
                }
                // Validate aud if client_id is provided
                if let Some(ref client_id) = form.client_id
                    && claims.aud.as_deref() != Some(client_id)
                {
                    return qid_http::error_response(QidError::BadRequest {
                        message: "id_token_hint aud does not match client_id".to_string(),
                    });
                }
                // RP-Initiated Logout 1.0 §2.5: if id_token_hint contains a sid claim,
                // validate it matches the current browser session.
                if let Some(claims_sid) = claims.extra.get("sid").and_then(|v| v.as_str()) {
                    let current_sid = state.realm(&realm.id).and_then(|runtime_realm| {
                        cookie_header.and_then(|cookie| {
                            parse_cookie(cookie, &runtime_realm.browser_session.cookie_name)
                        })
                    });
                    if let Some(current_sid) = current_sid
                        && claims_sid != current_sid
                    {
                        return qid_http::error_response(QidError::BadRequest {
                            message: "id_token_hint sid does not match current session".to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                return qid_http::error_response(QidError::BadRequest {
                    message: format!("id_token_hint signature validation failed: {e}"),
                });
            }
        }
    }
    if logout_realm_id.is_none()
        && let Some(client_id) = form.client_id.as_deref()
    {
        let realm = match logout_client_realm(&state, client_id).await {
            Ok(realm) => realm,
            Err(error) => return qid_http::error_response(error),
        };
        logout_realm_id = Some(realm.id.clone());
        logout_issuer = Some(realm.issuer.clone());
    }
    if logout_realm_id.is_none() {
        return qid_http::error_response(QidError::BadRequest {
            message: "logout requires id_token_hint or client_id to determine realm".to_string(),
        });
    }
    let logout_enabled = state
        .config
        .realms
        .iter()
        .filter(|realm| {
            logout_realm_id
                .as_deref()
                .is_none_or(|realm_id| realm.id == realm_id)
        })
        .any(|realm| {
            realm.protocols.oidc.enabled && {
                let path = original_uri.path();
                if path == state.paths.backchannel_logout {
                    realm.protocols.oidc.logout.backchannel
                } else if path == state.paths.frontchannel_logout {
                    realm.protocols.oidc.logout.frontchannel
                } else {
                    realm.protocols.oidc.logout.backchannel
                        || realm.protocols.oidc.logout.frontchannel
                }
            }
        });
    if !logout_enabled {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC logout is disabled".to_string(),
        });
    }

    let cookie_name = logout_realm_id
        .as_deref()
        .and_then(|realm_id| state.realm(realm_id))
        .map(|realm| realm.browser_session.cookie_name.clone())
        .ok_or_else(|| QidError::BadRequest {
            message: "logout realm is not available at runtime".to_string(),
        });
    let cookie_name = match cookie_name {
        Ok(cookie_name) => cookie_name,
        Err(error) => return qid_http::error_response(error),
    };

    let session_id = cookie_header.and_then(|c| parse_cookie(c, &cookie_name));

    let user_id = if let Some(sid) = session_id {
        if let Ok(Some(session)) = state.repo.get_session(sid).await {
            if state.repo.revoke_session(sid).await.is_ok() {
                state.session_cache_delete(sid);
            }
            Some(session.user_id)
        } else {
            None
        }
    } else {
        None
    };

    // Get all clients with logout URIs for OP-initiated logout
    let mut clients_with_logout_uris = Vec::new();
    for realm in &state.config.realms {
        if logout_realm_id
            .as_deref()
            .is_some_and(|realm_id| realm.id != realm_id)
        {
            continue;
        }
        clients_with_logout_uris.extend(
            state
                .repo
                .list_clients(&RealmId::from(realm.id.clone()))
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|c| {
                    c.backchannel_logout_uri.is_some() || c.frontchannel_logout_uri.is_some()
                }),
        );
    }

    let redirect_uri = match validate_post_logout_redirect_uri(
        &state,
        form.client_id.as_deref(),
        form.post_logout_redirect_uri.as_deref(),
    )
    .await
    {
        Ok(redirect_uri) => redirect_uri,
        Err(err) => return qid_http::error_response(err),
    };

    // If this is RP-initiated logout (has client_id and post_logout_redirect_uri), do redirect
    if let (Some(_), Some(uri)) = (form.client_id.as_ref(), redirect_uri.as_ref()) {
        let mut resp = Redirect::temporary(uri).into_response();
        let clear_cookie = format!(
            "{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
            cookie_name
        );
        let clear_cookie = match HeaderValue::from_str(&clear_cookie) {
            Ok(value) => value,
            Err(err) => {
                return qid_http::error_response(QidError::Internal {
                    message: format!("failed to build logout cookie header: {err}"),
                });
            }
        };
        resp.headers_mut().insert(header::SET_COOKIE, clear_cookie);
        return resp;
    }

    // OP-initiated logout: send backchannel notifications server-to-server and render
    // frontchannel iframes for browser-mediated logout.
    let clear_cookie = format!(
        "{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
        cookie_name
    );

    // Build frontchannel logout iframes
    let mut iframes = String::new();
    let Some(issuer) = logout_issuer else {
        return qid_http::error_response(QidError::BadRequest {
            message: "logout issuer is not determined".to_string(),
        });
    };
    let sid = session_id;
    for client in &clients_with_logout_uris {
        if let Some(uri) = &client.frontchannel_logout_uri {
            let iframe_src = match sid {
                Some(sid) => format!("{}?iss={}&sid={}", uri, issuer, sid),
                None => format!("{}?iss={}", uri, issuer),
            };
            iframes.push_str(&format!(
                r#"<iframe src="{}" style="display:none;"></iframe>"#,
                iframe_src
            ));
        }
    }

    if let Some(ref user_id) = user_id {
        for client in &clients_with_logout_uris {
            if let Some(uri) = &client.backchannel_logout_uri
                && let Some(token) = build_logout_token(&state, &issuer, user_id, sid, client).await
                && let Err(error) = send_backchannel_logout(uri, &token).await
            {
                tracing::warn!(
                    client_id = %client.client_id,
                    error = %error,
                    "backchannel logout delivery failed"
                );
            }
        }
    }

    let html = format!(
        r#"<!doctype html>
<html>
  <body>
    {}
  </body>
</html>"#,
        iframes
    );

    let mut resp = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    let clear_cookie = match HeaderValue::from_str(&clear_cookie) {
        Ok(value) => value,
        Err(err) => {
            return qid_http::error_response(QidError::Internal {
                message: format!("failed to build logout cookie header: {err}"),
            });
        }
    };
    resp.headers_mut().insert(header::SET_COOKIE, clear_cookie);
    resp
}

async fn backchannel_logout<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Form(form): Form<BackchannelLogoutRequest>,
) -> Response {
    // OIDC Back-Channel Logout 1.0 §2.2 mandates signature verification using the
    // issuer's published key material. The decode() call below verifies the
    // signature with the OP's active signer and enforces exp validation
    // (default behaviour of jsonwebtoken::Validation).
    let token_data = match state.signer.decode_signature_only(&form.logout_token) {
        Ok(d) => d,
        Err(e) => {
            return qid_http::oauth_error_response_with_description(
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                &format!("invalid logout_token signature: {e}"),
            );
        }
    };
    let claims = &token_data.claims;

    let iss = match claims.iss.as_deref() {
        Some(v) => v,
        None => {
            return qid_http::oauth_error_response_with_description(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "logout_token missing iss",
            );
        }
    };

    // The logout_token's `iss` MUST identify a realm of this OP.
    let Some(logout_realm) = realm_by_issuer(&state, iss) else {
        return qid_http::oauth_error_response_with_description(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            "logout_token iss does not match any configured realm",
        );
    };
    if !logout_realm.protocols.oidc.enabled || !logout_realm.protocols.oidc.logout.backchannel {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC backchannel logout is disabled".to_string(),
        });
    }

    // The logout_token's `aud` MUST identify a registered client of this OP.
    let mut aud_known = false;
    if let Some(aud) = claims.aud.as_deref() {
        aud_known = state
            .repo
            .get_client_by_client_id(&RealmId::from(logout_realm.id.clone()), aud)
            .await
            .ok()
            .flatten()
            .is_some();
    }
    if !aud_known {
        return qid_http::oauth_error_response_with_description(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            "logout_token aud does not match any registered client",
        );
    }

    // OIDC Back-Channel Logout 1.0 §2.6: logout_token MUST NOT contain a nonce.
    if claims.extra.contains_key("nonce") {
        return qid_http::oauth_error_response_with_description(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout_token must not contain nonce",
        );
    }

    // OIDC Back-Channel Logout 1.0 §2.2: events claim must contain
    // http://schemas.openid.net/event/backchannel-logout.
    let events_valid = claims
        .extra
        .get("events")
        .and_then(|v| v.as_object())
        .map(|events| {
            events
                .keys()
                .any(|k| k == "http://schemas.openid.net/event/backchannel-logout")
        })
        .unwrap_or(false);
    if !events_valid {
        return qid_http::oauth_error_response_with_description(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout_token events claim missing backchannel-logout",
        );
    }

    // Extract sid or sub from the logout_token claims
    let sid = claims.extra.get("sid").and_then(|v| v.as_str());
    let sub = claims.sub.as_deref();

    if sid.is_none() && sub.is_none() {
        return qid_http::error_response(QidError::BadRequest {
            message: "logout_token must contain sid or sub".to_string(),
        });
    }

    // Revoke matching sessions across all realms
    if let Some(sid_val) = sid {
        match state.repo.revoke_session(sid_val).await {
            Ok(()) => state.session_cache_delete(sid_val),
            Err(e) => {
                tracing::warn!(error = %e, "backchannel_logout: failed to revoke session {sid_val}");
            }
        }
    }
    if let Some(sub_val) = sub {
        let sessions = state
            .repo
            .list_sessions(&logout_realm.id, Some(sub_val))
            .await
            .unwrap_or_default();
        for session in &sessions {
            if !session.revoked {
                if let Err(e) = state.repo.revoke_session(&session.id).await {
                    tracing::warn!(error = %e, "backchannel_logout: failed to revoke session {}", session.id);
                } else {
                    state.session_cache_delete(&session.id);
                }
            }
        }
    }

    tracing::info!(
        sid = sid,
        sub = sub,
        iss = iss,
        "backchannel_logout: sessions revoked"
    );

    Json(json!({ "result": "acknowledged" })).into_response()
}

async fn frontchannel_logout<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    OriginalUri(_original_uri): OriginalUri,
    Query(query): Query<FrontchannelLogoutQuery>,
) -> Response {
    let Some(iss) = query.iss.as_deref() else {
        return qid_http::error_response(QidError::BadRequest {
            message: "frontchannel logout requires iss".to_string(),
        });
    };
    let Some(realm) = realm_by_issuer(&state, iss) else {
        return qid_http::error_response(QidError::BadRequest {
            message: "frontchannel logout iss does not match any configured realm".to_string(),
        });
    };
    if !realm.protocols.oidc.enabled || !realm.protocols.oidc.logout.frontchannel {
        return qid_http::error_response(QidError::BadRequest {
            message: "OIDC frontchannel logout is disabled".to_string(),
        });
    }

    // Frontchannel logout endpoint - renders an iframe for the RP
    // The OP redirects the user's browser here for frontchannel logout
    // This is typically called by the OP when user logs out at the OP
    let iss = iss.to_string();
    let sid = query.sid.unwrap_or_default();

    let html = format!(
        r#"<!doctype html>
<html>
  <body>
    <script>
      // Frontchannel logout - notify parent window
      window.parent.postMessage({{
        type: "logout",
        iss: "{}",
        sid: "{}"
      }}, "*");
    </script>
  </body>
</html>"#,
        iss, sid
    );

    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

#[derive(Debug, Deserialize)]
struct FrontchannelLogoutQuery {
    iss: Option<String>,
    sid: Option<String>,
}

async fn validate_post_logout_redirect_uri<R: Repository>(
    state: &SharedState<R>,
    client_id: Option<&str>,
    redirect_uri: Option<&str>,
) -> QidResult<Option<String>> {
    let Some(redirect_uri) = redirect_uri else {
        return Ok(None);
    };
    let client_id = client_id.ok_or_else(|| QidError::BadRequest {
        message: "client_id is required for post_logout_redirect_uri".to_string(),
    })?;
    let mut found = None;
    for realm in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                return Err(QidError::BadRequest {
                    message: "logout client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    let client = found.ok_or_else(|| QidError::BadRequest {
        message: "unknown logout client".to_string(),
    })?;
    if !client
        .post_logout_redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return Err(QidError::BadRequest {
            message: "post_logout_redirect_uri is not registered for client".to_string(),
        });
    }
    Ok(Some(redirect_uri.to_string()))
}

async fn logout_client_realm<'a, R: Repository>(
    state: &'a SharedState<R>,
    client_id: &str,
) -> QidResult<&'a qid_core::config::RealmConfig> {
    let mut found = None;
    for realm in &state.config.realms {
        if state
            .repo
            .get_client_by_client_id(&RealmId::from(realm.id.clone()), client_id)
            .await?
            .is_some()
        {
            if found.is_some() {
                return Err(QidError::BadRequest {
                    message: "logout client realm is ambiguous".to_string(),
                });
            }
            found = Some(realm);
        }
    }
    found.ok_or_else(|| QidError::BadRequest {
        message: "unknown logout client".to_string(),
    })
}

fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{}=", name)) {
            return Some(value.trim().trim_matches('"'));
        }
    }
    None
}

/// WebFinger (RFC 7033) endpoint for OIDC issuer discovery.
/// Supports `resource=acct:user@domain` and
/// `rel=http://openid.net/specs/connect/1.0/issuer`.
#[derive(Debug, Deserialize)]
struct WebFingerQuery {
    resource: Option<String>,
    rel: Option<String>,
}

async fn webfinger<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Query(query): Query<WebFingerQuery>,
) -> Response {
    let resource = match query.resource {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::BadRequest {
                message: "WebFinger requires a resource parameter".to_string(),
            });
        }
    };
    let rel = query.rel.unwrap_or_default();
    let issuer = match issuer_for_webfinger_resource(&state, &resource) {
        Ok(issuer) => issuer,
        Err(error) => return qid_http::error_response(error),
    };
    let mut links: Vec<serde_json::Value> = Vec::new();
    if rel.is_empty() || rel == "http://openid.net/specs/connect/1.0/issuer" {
        links.push(serde_json::json!({
            "rel": "http://openid.net/specs/connect/1.0/issuer",
            "href": issuer,
        }));
    }
    Json(serde_json::json!({
        "subject": resource,
        "links": links,
    }))
    .into_response()
}

fn issuer_for_webfinger_resource<R: Repository>(
    state: &SharedState<R>,
    resource: &str,
) -> QidResult<String> {
    let domain = resource
        .strip_prefix("acct:")
        .and_then(|acct| acct.rsplit_once('@').map(|(_, domain)| domain))
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| QidError::BadRequest {
            message: "WebFinger resource must be acct:user@domain".to_string(),
        })?;
    let mut matched = None;
    for realm in &state.config.realms {
        let issuer_host = issuer_host(&realm.issuer);
        if issuer_host.as_deref() == Some(domain) || realm.id == domain {
            if matched.is_some() {
                return Err(QidError::BadRequest {
                    message: "WebFinger resource domain matches multiple realms".to_string(),
                });
            }
            matched = Some(realm.issuer.clone());
        }
    }
    matched.ok_or_else(|| QidError::NotFound {
        resource: format!("issuer for WebFinger resource {resource}"),
    })
}

fn issuer_host(issuer: &str) -> Option<String> {
    let without_scheme = issuer.split_once("://")?.1;
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| host.split_once(':').map(|(host, _)| host).unwrap_or(host));
    (!host.trim().is_empty()).then(|| host.trim().to_string())
}

async fn check_session_iframe<R: Repository>(State(state): State<Arc<SharedState<R>>>) -> Response {
    let realm = match metadata_realm(&state, None) {
        Ok(realm) => realm,
        Err(error) => return qid_http::error_response(error),
    };
    check_session_iframe_response(&state, &realm.id)
}

async fn check_session_iframe_for_realm<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
) -> Response {
    check_session_iframe_response(&state, &realm)
}

fn check_session_iframe_response<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
) -> Response {
    let cookie_name = match state.realm(realm_id) {
        Some(realm) => realm.browser_session.cookie_name.clone(),
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {realm_id}"),
            });
        }
    };
    let html = format!(
        r#"<!doctype html>
<html>
  <body>
    <script>
      window.addEventListener("message", function(e) {{
        if (typeof e.data !== "object") return;
        switch (e.data.type) {{
          case "op.si.check":
            var sid = readCookie("{cookie_name}");
            setTimeout(function() {{
              if (sid && e.data.sid && sid === e.data.sid) {{
                e.source.postMessage("unchanged", e.origin);
              }} else if (sid && e.data.sid) {{
                e.source.postMessage("changed", e.origin);
              }} else {{
                e.source.postMessage("unchanged", e.origin);
              }}
            }}, 0);
            break;
        }}
      }});
      function readCookie(name) {{
        var match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
        return match ? decodeURIComponent(match[2]) : null;
      }}
    </script>
  </body>
</html>"#
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}
