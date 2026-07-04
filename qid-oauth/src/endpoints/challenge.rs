use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// RFC 9470 Step-Up Authentication Challenge request.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub access_token: String,
    #[serde(default)]
    pub acr_values: Vec<String>,
    #[serde(default)]
    pub max_age: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub error: String,
    pub error_description: String,
    pub acr_values: Option<Vec<String>>,
    pub max_age: Option<u64>,
    pub claims: Option<ClaimsParameter>,
}

#[derive(Debug, Serialize)]
pub struct ClaimsParameter {
    pub id_token: IdTokenClaimsRequest,
}

#[derive(Debug, Serialize)]
pub struct IdTokenClaimsRequest {
    pub acr: AcrClaim,
}

#[derive(Debug, Serialize)]
pub struct AcrClaim {
    pub essential: bool,
    pub values: Vec<String>,
}

pub async fn challenge<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<ChallengeRequest>,
) -> Response {
    let token_info = match decode_and_inspect_token::<R>(&state, &req.access_token).await {
        Some(info) => info,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ChallengeResponse {
                    error: "invalid_token".to_string(),
                    error_description: "access token is invalid or expired".to_string(),
                    acr_values: None,
                    max_age: None,
                    claims: None,
                }),
            )
                .into_response();
        }
    };

    let current_acr = token_info
        .acr
        .unwrap_or_else(|| "urn:qid:acr:low".to_string());
    let _current_amr: std::collections::BTreeSet<String> = token_info.amr.into_iter().collect();

    let required_acrs = if req.acr_values.is_empty() {
        vec!["urn:qid:acr:phishing-resistant".to_string()]
    } else {
        req.acr_values
    };

    let satisfied = required_acrs.contains(&current_acr);

    if satisfied {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "active": true, "acr": current_acr })),
        )
            .into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(ChallengeResponse {
            error: "insufficient_auth_strength".to_string(),
            error_description: format!(
                "current acr {} does not satisfy required {:?}",
                current_acr, required_acrs
            ),
            acr_values: Some(required_acrs.clone()),
            max_age: req.max_age,
            claims: Some(ClaimsParameter {
                id_token: IdTokenClaimsRequest {
                    acr: AcrClaim {
                        essential: true,
                        values: required_acrs,
                    },
                },
            }),
        }),
    )
        .into_response()
}

struct DecodedTokenInfo {
    acr: Option<String>,
    amr: Vec<String>,
}

async fn decode_and_inspect_token<R: Repository>(
    state: &Arc<SharedState<R>>,
    token: &str,
) -> Option<DecodedTokenInfo> {
    let repo = &state.repo;
    if let Ok(Some(record)) = repo.get_access_token(token).await {
        return Some(DecodedTokenInfo {
            acr: record.acr,
            amr: record.amr,
        });
    }
    None
}
