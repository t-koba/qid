//! qid-resource fedcm module.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{jwt::JwtClaims, state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use super::not_found_response;
use crate::session_auth;
use qid_core::models::FedCmIdentity;

//
// FedCM
//

#[derive(Debug, Deserialize)]
pub struct ListFedCmAccountsQuery {
    account_id: String,
}

pub async fn list_fedcm_accounts<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Query(query): Query<ListFedCmAccountsQuery>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &query.account_id).await
    {
        return e;
    }
    match state
        .repo
        .get_fedcm_identities(&RealmId(realm), &query.account_id)
        .await
    {
        Ok(identities) => {
            let accounts: Vec<serde_json::Value> = identities
                .into_iter()
                .map(|i| {
                    serde_json::json!({
                        "id": i.id,
                        "account_id": i.account_id,
                        "email": i.email,
                        "name": i.name,
                        "given_name": i.given_name,
                        "picture_url": i.picture_url,
                    })
                })
                .collect();
            Json(serde_json::json!({ "accounts": accounts })).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateFedCmIdentityRequest {
    account_id: String,
    email: String,
    name: Option<String>,
    given_name: Option<String>,
    picture_url: Option<String>,
    #[serde(default)]
    approved_clients: Vec<String>,
}

pub async fn create_fedcm_identity<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<CreateFedCmIdentityRequest>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &req.account_id).await {
        return e;
    }
    let identity = FedCmIdentity {
        id: ulid::Ulid::new().to_string(),
        realm_id: realm,
        account_id: req.account_id,
        email: req.email,
        name: req.name,
        given_name: req.given_name,
        picture_url: req.picture_url,
        approved_clients: req.approved_clients,
    };
    match state.repo.store_fedcm_identity(&identity).await {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!(identity))).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct FedCmTokenRequest {
    account_id: String,
    client_id: String,
}

pub async fn generate_fedcm_token<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<FedCmTokenRequest>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &req.account_id).await {
        return e;
    }
    let identities = match state
        .repo
        .get_fedcm_identities(&RealmId(realm.clone()), &req.account_id)
        .await
    {
        Ok(ids) if ids.is_empty() => {
            return not_found_response("FedCM identity not found");
        }
        Ok(ids) => ids,
        Err(e) => return qid_http::error_response(e),
    };
    let identity = &identities[0];
    if !identity
        .approved_clients
        .iter()
        .any(|client| qid_core::util::constant_time_eq(client, &req.client_id))
    {
        return qid_http::error_response(qid_core::error::QidError::Unauthorized {
            message: "FedCM client is not approved for this account".to_string(),
        });
    }
    let now = qid_core::util::now_seconds();
    let mut extra = HashMap::new();
    extra.insert("email".to_string(), serde_json::json!(identity.email));
    extra.insert("name".to_string(), serde_json::json!(identity.name));
    extra.insert(
        "given_name".to_string(),
        serde_json::json!(identity.given_name),
    );
    extra.insert("client_id".to_string(), serde_json::json!(req.client_id));
    extra.insert("realm_id".to_string(), serde_json::json!(realm));
    extra.insert("typ".to_string(), serde_json::json!("fedcm"));
    let issuer = match state.realm(&realm) {
        Some(realm_config) => realm_config.issuer.clone(),
        None => {
            return qid_http::error_response(qid_core::error::QidError::NotFound {
                resource: format!("realm {realm}"),
            });
        }
    };
    let claims = JwtClaims {
        iss: Some(issuer),
        sub: Some(identity.account_id.clone()),
        aud: Some(req.client_id.clone()),
        exp: Some((now + 3600) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(format!("fedcm_{}", ulid::Ulid::new())),
        extra,
    };
    let token = match state.signer.sign(&claims) {
        Ok(token) => token,
        Err(err) => {
            return qid_http::error_response(qid_core::error::QidError::Internal {
                message: format!("FedCM token signing failed: {err}"),
            });
        }
    };
    Json(serde_json::json!({
        "token": token,
        "token_type": "JWT",
        "expires_in": 3600,
    }))
    .into_response()
}
