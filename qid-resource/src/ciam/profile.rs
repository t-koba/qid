use crate::session_auth;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{
    models::{CiamConsentGrant, CiamProgressiveProfile},
    state::SharedState,
    tenant::RealmId,
    util,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::VerificationChannel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgressiveProfileRequest {
    pub user_id: String,
    #[serde(default)]
    pub profile: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub phone_verified: bool,
    #[serde(default)]
    pub accepted_terms_version: Option<String>,
    #[serde(default)]
    pub required_terms_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgressiveProfilePlan {
    pub user_id: String,
    pub missing_fields: Vec<String>,
    pub verification_required: Vec<VerificationChannel>,
    pub terms_acceptance_required: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentEvaluationRequest {
    #[serde(default)]
    pub user_id: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub requested_claims: Vec<String>,
    #[serde(default)]
    pub granted_claims: Vec<String>,
    #[serde(default)]
    pub sensitive_claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentEvaluation {
    pub client_id: String,
    pub released_claims: Vec<String>,
    pub denied_claims: Vec<String>,
    pub consent_required: bool,
    pub privacy_dashboard_path: String,
}

#[derive(Debug, Deserialize)]
pub struct ProgressiveProfileSubmit {
    pub user_id: String,
    #[serde(default)]
    pub profile: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub accepted_terms_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProgressiveProfileSubmitResponse {
    pub status: String,
    pub complete: bool,
    pub plan: ProgressiveProfilePlan,
}

#[derive(Debug, Serialize)]
pub struct PasswordlessCampaignStats {
    pub total_migrated: usize,
    pub migrated_user_ids: Vec<String>,
}

pub async fn profile_plan(
    Path(realm): Path<String>,
    Json(req): Json<ProgressiveProfileRequest>,
) -> Response {
    Json(serde_json::json!({
        "realm": realm,
        "plan": progressive_profile_plan(&req),
    }))
    .into_response()
}

pub async fn profile_submit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<ProgressiveProfileSubmit>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &req.user_id).await {
        return e;
    }
    if req.user_id.trim().is_empty() {
        return qid_http::error_response(qid_core::error::QidError::BadRequest {
            message: "user_id must not be empty".to_string(),
        });
    }

    let realm_id = RealmId(realm);
    let now = util::now_seconds();

    let (_stored, plan) = {
        let existing = match state
            .repo
            .get_ciam_progressive_profile(&realm_id, &req.user_id)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => CiamProgressiveProfile {
                id: format!("{}_{}", realm_id.as_str(), req.user_id),
                realm_id: realm_id.0.clone(),
                user_id: req.user_id.clone(),
                profile_json: serde_json::json!({}),
                passwordless_migrated_at: None,
                created_at: now,
                updated_at: now,
            },
            Err(e) => return qid_http::error_response(e),
        };

        let mut stored_map: BTreeMap<String, serde_json::Value> =
            serde_json::from_value(existing.profile_json.clone()).unwrap_or_default();
        for (key, value) in req.profile {
            stored_map.insert(key, value);
        }

        let plan = progressive_profile_plan(&ProgressiveProfileRequest {
            user_id: req.user_id.clone(),
            profile: stored_map.clone(),
            required_fields: Vec::new(),
            email_verified: false,
            phone_verified: false,
            accepted_terms_version: req.accepted_terms_version,
            required_terms_version: None,
        });

        let updated = CiamProgressiveProfile {
            profile_json: serde_json::to_value(&stored_map).unwrap_or_default(),
            updated_at: now,
            ..existing
        };

        if let Err(e) = state.repo.store_ciam_progressive_profile(&updated).await {
            return qid_http::error_response(e);
        }

        (stored_map, plan)
    };

    let status = if plan.complete {
        "complete".to_string()
    } else {
        "incomplete".to_string()
    };
    Json(ProgressiveProfileSubmitResponse {
        status,
        complete: plan.complete,
        plan,
    })
    .into_response()
}

pub fn progressive_profile_plan(req: &ProgressiveProfileRequest) -> ProgressiveProfilePlan {
    let mut missing_fields = req
        .required_fields
        .iter()
        .filter(|field| {
            req.profile
                .get(*field)
                .is_none_or(|value| value.is_null() || value.as_str() == Some(""))
        })
        .cloned()
        .collect::<Vec<_>>();
    missing_fields.sort();
    missing_fields.dedup();

    let mut verification_required = BTreeSet::new();
    if req.profile.contains_key("email") && !req.email_verified {
        verification_required.insert(VerificationChannel::Email);
    }
    if req.profile.contains_key("phone") && !req.phone_verified {
        verification_required.insert(VerificationChannel::Phone);
    }

    let terms_acceptance_required = req
        .required_terms_version
        .as_ref()
        .is_some_and(|required| req.accepted_terms_version.as_ref() != Some(required));
    let verification_required = verification_required.into_iter().collect::<Vec<_>>();
    let complete =
        missing_fields.is_empty() && verification_required.is_empty() && !terms_acceptance_required;
    ProgressiveProfilePlan {
        user_id: req.user_id.clone(),
        missing_fields,
        verification_required,
        terms_acceptance_required,
        complete,
    }
}

pub async fn consent_evaluate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<ConsentEvaluationRequest>,
) -> Response {
    if let Some(user_id) = &req.user_id
        && let Err(e) = session_auth::require_session(&headers, &state, &realm, user_id).await
    {
        return e;
    }
    let mut effective = req.clone();
    if let Some(user_id) = &req.user_id {
        match state
            .repo
            .list_ciam_consent_grants(&RealmId(realm.clone()), user_id, Some(&req.client_id))
            .await
        {
            Ok(grants) => {
                let granted = grants
                    .into_iter()
                    .filter(|grant| !grant.revoked)
                    .flat_map(|grant| grant.granted_claims)
                    .collect::<BTreeSet<_>>();
                effective.granted_claims.extend(granted);
            }
            Err(err) => return qid_http::error_response(err),
        }
    }
    Json(serde_json::json!({
        "realm": realm,
        "evaluation": evaluate_consent(&effective),
    }))
    .into_response()
}

pub fn evaluate_consent(req: &ConsentEvaluationRequest) -> ConsentEvaluation {
    let granted = req.granted_claims.iter().collect::<BTreeSet<_>>();
    let sensitive = req.sensitive_claims.iter().collect::<BTreeSet<_>>();
    let mut released_claims = Vec::new();
    let mut denied_claims = Vec::new();
    for claim in &req.requested_claims {
        if sensitive.contains(claim) && !granted.contains(claim) {
            denied_claims.push(claim.clone());
        } else {
            released_claims.push(claim.clone());
        }
    }
    released_claims.sort();
    released_claims.dedup();
    denied_claims.sort();
    denied_claims.dedup();
    ConsentEvaluation {
        client_id: req.client_id.clone(),
        consent_required: !denied_claims.is_empty(),
        released_claims,
        denied_claims,
        privacy_dashboard_path: format!("/privacy/clients/{}", req.client_id),
    }
}

pub async fn consent_grant<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<CiamConsentGrant>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &req.user_id).await {
        return e;
    }
    let mut grant = req;
    grant.realm_id = realm;
    match state.repo.store_ciam_consent_grant(&grant).await {
        Ok(()) => (StatusCode::CREATED, Json(grant)).into_response(),
        Err(err) => qid_http::error_response(err),
    }
}

pub async fn privacy_dashboard<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, &user_id).await {
        return e;
    }
    let grants = match state
        .repo
        .list_ciam_consent_grants(&RealmId(realm.clone()), &user_id, None)
        .await
    {
        Ok(grants) => grants,
        Err(err) => return qid_http::error_response(err),
    };
    let identity_links = match state
        .repo
        .list_ciam_identity_links(&RealmId(realm.clone()), &user_id)
        .await
    {
        Ok(identity_links) => identity_links,
        Err(err) => return qid_http::error_response(err),
    };
    Json(serde_json::json!({
            "realm": realm,
            "user_id": user_id,
            "consents": grants,
            "identity_links": identity_links,
    }))
    .into_response()
}

pub async fn passwordless_migrate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let user_id = req.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if let Err(e) = session_auth::require_session(&headers, &state, &realm, user_id).await {
        return e;
    }
    if user_id.is_empty() {
        return qid_http::error_response(qid_core::error::QidError::BadRequest {
            message: "user_id required".to_string(),
        });
    }

    let realm_id = RealmId(realm);
    let now = util::now_seconds();

    let profile = match state
        .repo
        .get_ciam_progressive_profile(&realm_id, user_id)
        .await
    {
        Ok(Some(p)) => CiamProgressiveProfile {
            passwordless_migrated_at: Some(now),
            updated_at: now,
            ..p
        },
        Ok(None) => CiamProgressiveProfile {
            id: format!("{}_{}", realm_id.as_str(), user_id),
            realm_id: realm_id.0,
            user_id: user_id.to_string(),
            profile_json: serde_json::json!({}),
            passwordless_migrated_at: Some(now),
            created_at: now,
            updated_at: now,
        },
        Err(e) => return qid_http::error_response(e),
    };

    if let Err(e) = state.repo.store_ciam_progressive_profile(&profile).await {
        return qid_http::error_response(e);
    }

    Json(serde_json::json!({"status": "migrated", "user_id": user_id})).into_response()
}

pub async fn passwordless_campaign<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
) -> Response {
    let user_id = match session_auth::require_any_session(&headers, &state, &realm).await {
        Ok(user_id) => user_id,
        Err(e) => return e,
    };
    let realm_id = RealmId(realm);
    let profile = match state
        .repo
        .get_ciam_progressive_profile(&realm_id, &user_id)
        .await
    {
        Ok(profile) => profile,
        Err(e) => return qid_http::error_response(e),
    };
    Json(serde_json::json!({
        "user_id": user_id,
        "passwordless_migrated": profile
            .and_then(|profile| profile.passwordless_migrated_at)
            .is_some(),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progressive_profile_requires_missing_fields_verification_and_terms() {
        let plan = progressive_profile_plan(&ProgressiveProfileRequest {
            user_id: "user-1".to_string(),
            profile: BTreeMap::from([
                (
                    "email".to_string(),
                    serde_json::Value::String("alice@example.com".to_string()),
                ),
                (
                    "phone".to_string(),
                    serde_json::Value::String(String::new()),
                ),
            ]),
            required_fields: vec![
                "email".to_string(),
                "phone".to_string(),
                "given_name".to_string(),
            ],
            email_verified: false,
            phone_verified: false,
            accepted_terms_version: Some("2026-01".to_string()),
            required_terms_version: Some("2026-06".to_string()),
        });

        assert_eq!(plan.missing_fields, vec!["given_name", "phone"]);
        assert_eq!(
            plan.verification_required,
            vec![VerificationChannel::Email, VerificationChannel::Phone]
        );
        assert!(plan.terms_acceptance_required);
        assert!(!plan.complete);
    }

    #[test]
    fn consent_evaluation_releases_only_consented_sensitive_claims() {
        let evaluation = evaluate_consent(&ConsentEvaluationRequest {
            user_id: Some("user-1".to_string()),
            client_id: "mobile-app".to_string(),
            requested_claims: vec!["sub".to_string(), "email".to_string(), "phone".to_string()],
            granted_claims: vec!["email".to_string()],
            sensitive_claims: vec!["email".to_string(), "phone".to_string()],
        });

        assert_eq!(evaluation.released_claims, vec!["email", "sub"]);
        assert_eq!(evaluation.denied_claims, vec!["phone"]);
        assert!(evaluation.consent_required);
    }
}
