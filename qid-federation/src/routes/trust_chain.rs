use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use qid_core::{QidError, models::AuditEvent, state::SharedState};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::{
    TrustAnchor, TrustChainValidation, federation_error_code, federation_error_description,
    validate_signed_trust_chain,
};

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct TrustChainValidationRequest {
    pub subject: String,
    pub signed_trust_chain: Vec<String>,
    pub trust_anchors: Vec<TrustAnchor>,
    #[serde(default)]
    pub now_epoch_seconds: Option<u64>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct TrustChainValidationResponse {
    pub validation: TrustChainValidation,
    pub audit_event_id: String,
}

pub async fn validate_trust_chain_endpoint<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<TrustChainValidationRequest>,
) -> Response {
    let now = qid_core::util::now_seconds();
    let result = validate_signed_trust_chain(
        state.signer.as_ref(),
        &req.subject,
        &req.signed_trust_chain,
        &req.trust_anchors,
        now,
    );
    let action = if result.is_ok() {
        "federation.trust_chain.validate"
    } else {
        "federation.trust_chain.reject"
    };
    let audit_event_id = federation_audit_event_id(&req, action, now);
    let audit_event = federation_audit_event(&audit_event_id, &req, action, now, &result);
    if let Err(error) = state.repo.append_audit_event(&audit_event).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "audit_write_failed",
                "error_description": error.to_string()
            })),
        )
            .into_response();
    }

    match result {
        Ok(validation) => (
            StatusCode::OK,
            Json(TrustChainValidationResponse {
                validation,
                audit_event_id,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": federation_error_code(&error),
                "error_description": federation_error_description(&error),
                "audit_event_id": audit_event_id
            })),
        )
            .into_response(),
    }
}

fn federation_audit_event(
    id: &str,
    req: &TrustChainValidationRequest,
    action: &str,
    now_epoch_seconds: u64,
    result: &Result<TrustChainValidation, QidError>,
) -> AuditEvent {
    let mut metadata = serde_json::json!({
        "subject": req.subject,
        "chain_length": req.signed_trust_chain.len(),
        "trust_anchors": req
            .trust_anchors
            .iter()
            .map(|anchor| anchor.entity_id.clone())
            .collect::<Vec<_>>(),
    });
    match result {
        Ok(validation) => {
            metadata["trust_anchor"] = serde_json::Value::String(validation.trust_anchor.clone());
            metadata["automatic_client_trust"] =
                serde_json::Value::Bool(validation.automatic_client_trust);
            metadata["trust_marks"] =
                serde_json::to_value(&validation.trust_marks).unwrap_or_default();
        }
        Err(error) => {
            metadata["error"] = serde_json::json!({
                "code": federation_error_code(error),
                "message": federation_error_description(error),
            });
        }
    }

    AuditEvent {
        id: id.to_string(),
        realm_id: None,
        actor: "federation-api".to_string(),
        action: action.to_string(),
        target_type: "federation_trust_chain".to_string(),
        target_id: req.subject.clone(),
        reason: "dynamic trust chain resolution".to_string(),
        metadata_json: metadata,
        created_at: now_epoch_seconds,
        previous_hash: None,
        event_hash: None,
    }
}

fn federation_audit_event_id(
    req: &TrustChainValidationRequest,
    action: &str,
    now_epoch_seconds: u64,
) -> String {
    let mut hasher = DefaultHasher::new();
    req.subject.hash(&mut hasher);
    req.signed_trust_chain.hash(&mut hasher);
    for anchor in &req.trust_anchors {
        anchor.entity_id.hash(&mut hasher);
    }
    action.hash(&mut hasher);
    now_epoch_seconds.hash(&mut hasher);
    format!("fed_audit_{:016x}", hasher.finish())
}
