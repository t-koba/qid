use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    models::VcCredentialStatusRecord,
    state::SharedState,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{bearer_token, error_response};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatus {
    pub credential_id: String,
    pub status_list_uri: String,
    pub revoked: bool,
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRevocationRequest {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatusResponse {
    pub credential_id: String,
    pub subject: String,
    pub issuer: String,
    pub status_list_uri: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    #[serde(default)]
    pub revocation_reason: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

impl From<VcCredentialStatusRecord> for CredentialStatusResponse {
    fn from(status: VcCredentialStatusRecord) -> Self {
        Self {
            credential_id: status.credential_id,
            subject: status.subject,
            issuer: status.issuer,
            status_list_uri: status.status_list_uri,
            issued_at: status.issued_at,
            expires_at: status.expires_at,
            revoked: status.revoked,
            revocation_reason: status.revocation_reason,
            revoked_at: status.revoked_at,
        }
    }
}

pub fn revoke_credential(
    mut status_registry: HashMap<String, CredentialStatus>,
    credential_id: &str,
    reason: impl Into<String>,
) -> QidResult<HashMap<String, CredentialStatus>> {
    let Some(status) = status_registry.get_mut(credential_id) else {
        return Err(QidError::NotFound {
            resource: "Credential status entry".to_string(),
        });
    };
    status.revoked = true;
    status.revocation_reason = Some(reason.into());
    Ok(status_registry)
}

pub async fn revoke_credential_from_bearer<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    credential_id: &str,
    request: CredentialRevocationRequest,
) -> QidResult<VcCredentialStatusRecord> {
    if request.reason.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "credential revocation reason is required".to_string(),
        });
    }
    let token = bearer_token(headers)?;
    let decoded = qid_oauth::endpoints::decode_access_token(state, token)
        .await
        .map_err(|_| QidError::Unauthorized {
            message: "invalid credential revocation access token".to_string(),
        })?;
    let htu = format!(
        "{}/vc/v1/status/{}/revoke",
        state.plan.public_base_url.trim_end_matches('/'),
        credential_id
    );
    qid_oauth::endpoints::enforce_sender_constrained_access_token(
        state,
        headers,
        &Method::POST,
        &htu,
        token,
        &decoded,
    )?;
    let scopes = decoded
        .scope
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .collect::<std::collections::HashSet<_>>();
    if !scopes.contains("qid_identity") {
        return Err(QidError::Unauthorized {
            message: "credential revocation requires qid_identity scope".to_string(),
        });
    }
    let status = state
        .repo
        .get_vc_credential_status(credential_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "VC credential status".to_string(),
        })?;
    if decoded.user_id != status.subject {
        return Err(QidError::Unauthorized {
            message: "credential revocation token subject does not own credential".to_string(),
        });
    }
    if decoded.realm_id != status.realm_id {
        return Err(QidError::Unauthorized {
            message: "credential revocation token realm does not match credential".to_string(),
        });
    }
    if let Some(realm) = state.realm(&status.realm_id)
        && decoded.aud.iter().any(|aud| aud == &realm.issuer)
        && status.issuer != realm.issuer
    {
        return Err(QidError::Unauthorized {
            message: "credential revocation token issuer does not match credential issuer"
                .to_string(),
        });
    }
    let revoked_at = qid_core::util::now_seconds();
    state
        .repo
        .revoke_vc_credential(credential_id, request.reason.trim(), revoked_at)
        .await?;
    state
        .repo
        .get_vc_credential_status(credential_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "VC credential status".to_string(),
        })
}

pub(crate) async fn credential_status<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(credential_id): Path<String>,
) -> Response {
    match state.repo.get_vc_credential_status(&credential_id).await {
        Ok(Some(status)) => Json(CredentialStatusResponse::from(status)).into_response(),
        Ok(None) => error_response(QidError::NotFound {
            resource: "VC credential status".to_string(),
        }),
        Err(error) => error_response(error),
    }
}

pub(crate) async fn revoke_credential_status<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialRevocationRequest>,
) -> Response {
    match revoke_credential_from_bearer(&state, &headers, &credential_id, request).await {
        Ok(status) => Json(CredentialStatusResponse::from(status)).into_response(),
        Err(error) => error_response(error),
    }
}
