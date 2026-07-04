use crate::session_auth;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{
    models::{AuditEvent, CiamIdentityLink},
    state::SharedState,
    tenant::RealmId,
    util,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalIdentityLookupRequest {
    pub provider: String,
    pub external_subject: String,
}

pub async fn identity_link_create<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<CiamIdentityLink>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &req.user_id).await {
        return e;
    }
    let mut link = req;
    link.realm_id = realm.clone();
    if let Err(err) = state.repo.store_ciam_identity_link(&link).await {
        return qid_http::error_response(err);
    }
    let event =
        ciam_identity_link_audit_event(&realm, &link, "ciam.identity_link.create", "created");
    if let Err(err) = state.repo.append_audit_event(&event).await {
        return qid_http::error_response(err);
    }
    (StatusCode::CREATED, Json(link)).into_response()
}

pub async fn identity_links_list<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &user_id).await {
        return e;
    }
    match state
        .repo
        .list_ciam_identity_links(&RealmId(realm), &user_id)
        .await
    {
        Ok(links) => Json(links).into_response(),
        Err(err) => qid_http::error_response(err),
    }
}

pub async fn identity_link_lookup<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<ExternalIdentityLookupRequest>,
) -> Response {
    if let Err(e) = session_auth::require_any_session(&headers, &state, &realm).await {
        return e;
    }
    let link = match state
        .repo
        .get_ciam_identity_link_by_external_subject(
            &RealmId(realm),
            &req.provider,
            &req.external_subject,
        )
        .await
    {
        Ok(Some(link)) => link,
        Ok(None) => return crate::not_found_response("CIAM identity link not found"),
        Err(err) => return qid_http::error_response(err),
    };
    if let Err(e) =
        session_auth::require_session(&headers, &state, &link.realm_id, &link.user_id).await
    {
        return e;
    }
    Json(link).into_response()
}

pub async fn identity_link_delete<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, link_id)): Path<(String, String)>,
) -> Response {
    let realm_id = RealmId(realm.clone());
    let Some(link) = (match state.repo.get_ciam_identity_link(&realm_id, &link_id).await {
        Ok(link) => link,
        Err(err) => return qid_http::error_response(err),
    }) else {
        return crate::not_found_response("CIAM identity link not found");
    };
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &link.user_id).await {
        return e;
    }
    if let Err(err) = state
        .repo
        .delete_ciam_identity_link(&realm_id, &link_id)
        .await
    {
        return qid_http::error_response(err);
    }
    let event =
        ciam_identity_link_audit_event(&realm, &link, "ciam.identity_link.delete", "deleted");
    if let Err(err) = state.repo.append_audit_event(&event).await {
        return qid_http::error_response(err);
    }
    StatusCode::NO_CONTENT.into_response()
}

fn ciam_identity_link_audit_event(
    realm: &str,
    link: &CiamIdentityLink,
    action: &str,
    verb: &str,
) -> AuditEvent {
    AuditEvent {
        id: format!("ciam_identity_link_{}", ulid::Ulid::new()),
        realm_id: Some(realm.to_string()),
        actor: link.user_id.clone(),
        action: action.to_string(),
        target_type: "ciam_identity_link".to_string(),
        target_id: link.id.clone(),
        reason: format!("CIAM identity link {verb}"),
        metadata_json: serde_json::json!({
            "provider": link.provider,
            "external_subject_hash": util::sha256_base64url(&link.external_subject),
            "external_email_present": link.external_email.is_some(),
            "verified": link.verified,
        }),
        created_at: if verb == "deleted" {
            util::now_seconds()
        } else {
            link.linked_at_epoch_seconds
        },
        previous_hash: None,
        event_hash: None,
    }
}
