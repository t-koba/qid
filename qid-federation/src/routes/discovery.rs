use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::{
    EntityStatement, FederationMetadata, HomeRealmDiscoveryRequest, OpenIdProviderMetadata,
    federation_error_code, federation_error_description, sign_entity_statement,
};

use super::providers_from_config;

pub async fn entity_statement<R: Repository>(State(state): State<Arc<SharedState<R>>>) -> Response {
    let issuer = state.plan.public_base_url.trim_end_matches('/').to_string();
    let now = qid_core::util::now_seconds();
    let statement = EntityStatement {
        iss: issuer.clone(),
        sub: issuer.clone(),
        iat: now,
        exp: now + 3600,
        authority_hints: Vec::new(),
        metadata: Some(FederationMetadata {
            openid_provider: Some(OpenIdProviderMetadata {
                issuer,
                jwks_uri: format!("{}/jwks", state.plan.public_base_url.trim_end_matches('/')),
            }),
            openid_relying_party: None,
        }),
        trust_marks: Vec::new(),
    };

    match sign_entity_statement(state.signer.as_ref(), &statement) {
        Ok(jwt) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/entity-statement+jwt")],
            jwt,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "error": "server_error",
                "error_description": federation_error_description(&error)
            })
            .to_string(),
        )
            .into_response(),
    }
}

pub async fn discover_provider<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Json(req): Json<HomeRealmDiscoveryRequest>,
) -> Response {
    let realm_config = match state.config.realms.iter().find(|r| r.id == realm) {
        Some(cfg) => cfg,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm_not_found"})),
            )
                .into_response();
        }
    };
    if !realm_config.protocols.federation.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation_disabled"})),
        )
            .into_response();
    }
    let providers = providers_from_config(&realm_config.protocols.federation.inbound_providers);
    match crate::route_inbound_provider(&providers, &req) {
        Ok(decision) => Json(serde_json::json!({ "decision": decision })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": federation_error_code(&e),
                "error_description": federation_error_description(&e)
            })),
        )
            .into_response(),
    }
}
