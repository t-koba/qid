//! SPIFFE Workload API endpoints.
//!
//! Implements the HTTP/JSON equivalent of the SPIFFE Workload API
//! (gRPC `FetchX509SVID` / `FetchJWTSVID`). Each endpoint returns a
//! signed SVID document that the caller can use to authenticate to
//! other workloads in the same trust domain.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use qid_core::{error::QidResult, state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::eat::{SpiffeJwtSvid, SpiffeX509Svid};
use crate::{workload, workload_auth};

#[derive(Debug, Deserialize)]
pub struct FetchX509SvidQuery {
    pub spiffe_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FetchX509SvidResponse {
    pub svids: Vec<SpiffeX509Svid>,
    pub federation_bundle: Vec<String>,
    pub rotated_at: u64,
}

pub async fn fetch_x509_svid<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    axum::extract::Query(query): axum::extract::Query<FetchX509SvidQuery>,
) -> Response {
    let caller = match workload_auth::authenticate_workload(&headers, &state, &realm).await {
        Ok(caller) => caller,
        Err(e) => return e,
    };
    if let Some(requested) = &query.spiffe_id
        && requested != &caller.spiffe_id
    {
        return qid_http::error_response(qid_core::error::QidError::Unauthorized {
            message: "caller workload does not match requested SPIFFE ID".to_string(),
        });
    }
    let mut svids = Vec::new();
    let now = qid_core::util::now_seconds();
    let issued =
        match workload::issue_qid_controlled_workload_certificate(&state, &realm, &caller, None) {
            Ok(issued) => issued,
            Err(err) => return qid_http::error_response(err),
        };
    if let Err(err) = state
        .repo
        .store_workload_certificate(&issued.certificate)
        .await
    {
        return qid_http::error_response(err);
    }
    svids.push(SpiffeX509Svid {
        spiffe_id: caller.spiffe_id.clone(),
        certificate_chain: vec![issued.certificate.certificate_pem],
        private_key: Some(issued.private_key_pem),
        federation_chain: Vec::new(),
        ttl_seconds: issued.certificate.not_after.saturating_sub(now),
        issued_at: now,
    });
    Json(FetchX509SvidResponse {
        svids,
        federation_bundle: Vec::new(),
        rotated_at: now,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct FetchJwtSvidQuery {
    pub spiffe_id: String,
    pub audience: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

pub async fn fetch_jwt_svid<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    axum::extract::Query(query): axum::extract::Query<FetchJwtSvidQuery>,
) -> Response {
    if let Err(e) =
        workload_auth::require_workload_for_spiffe(&headers, &state, &realm, &query.spiffe_id).await
    {
        return e;
    }
    match issue_jwt_svid(state, realm, query).await {
        Ok(response) => response,
        Err(err) => qid_http::error_response(err),
    }
}

async fn issue_jwt_svid<R: Repository>(
    state: Arc<SharedState<R>>,
    realm: String,
    query: FetchJwtSvidQuery,
) -> QidResult<Response> {
    validate_spiffe_id(&query.spiffe_id)?;
    if query.audience.is_empty() {
        return Err(qid_core::error::QidError::BadRequest {
            message: "JWT-SVID request must include at least one audience".to_string(),
        });
    }
    let identities = state
        .repo
        .list_workload_identities(&RealmId(realm.clone()))
        .await?;
    let identity = identities
        .iter()
        .find(|identity| identity.spiffe_id == query.spiffe_id)
        .ok_or_else(|| qid_core::error::QidError::NotFound {
            resource: format!("workload identity {}", query.spiffe_id),
        })?;
    if !identity.approved() {
        return Err(qid_core::error::QidError::Unauthorized {
            message: "workload identity is not approved".to_string(),
        });
    }
    let now = qid_core::util::now_seconds();
    let ttl = query.ttl_seconds.unwrap_or(3600).min(24 * 3600);
    let issuer = state
        .realm(&realm)
        .map(|realm_config| realm_config.issuer.clone())
        .ok_or_else(|| qid_core::error::QidError::NotFound {
            resource: format!("realm {realm}"),
        })?;
    let claims = qid_core::jwt::JwtClaims {
        iss: Some(issuer),
        sub: Some(query.spiffe_id.clone()),
        aud: Some(query.audience.clone()),
        exp: Some((now + ttl) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(format!("svid_{}", ulid::Ulid::new())),
        extra: std::iter::once((
            "spiffe_id".to_string(),
            serde_json::Value::String(query.spiffe_id.clone()),
        ))
        .collect(),
    };
    let token = state
        .signer
        .sign(&claims)
        .map_err(|err| qid_core::error::QidError::Internal {
            message: format!("JWT-SVID signing failed: {err}"),
        })?;
    let svid = SpiffeJwtSvid {
        spiffe_id: query.spiffe_id,
        token,
        ttl_seconds: ttl,
        issued_at: now,
    };
    Ok(Json(svid).into_response())
}

pub async fn spiffe_bundle_endpoint<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
) -> Response {
    let mut bundle: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for realm in &state.config.realms {
        if let Some(trust_domain) = realm.trust_domain() {
            let certificates = state
                .workload_ca_certificate_pem
                .as_ref()
                .map(|certificate| vec![certificate.clone()])
                .unwrap_or_default();
            bundle.insert(trust_domain, certificates);
        }
    }
    Json(serde_json::json!({ "bundles": bundle })).into_response()
}

trait WorkloadApproval {
    fn approved(&self) -> bool;
}

impl WorkloadApproval for qid_core::models::WorkloadIdentity {
    fn approved(&self) -> bool {
        // The `WorkloadIdentity` model currently has no approval field;
        // we treat any registered identity as approved. Operators that
        // need a stricter workflow can extend the storage layer with an
        // explicit `approved` boolean and update this predicate.
        true
    }
}

fn validate_spiffe_id(spiffe_id: &str) -> QidResult<()> {
    crate::eat::validate_spiffe_id(spiffe_id)
}

trait RealmTrustDomain {
    fn trust_domain(&self) -> Option<String>;
}

impl RealmTrustDomain for qid_core::config::RealmConfig {
    fn trust_domain(&self) -> Option<String> {
        // A realm's trust domain is the host portion of its issuer. We
        // do not require an explicit field because every qid realm
        // already has an `issuer` URL; the SPIFFE trust domain is the
        // first DNS label after the scheme.
        url::Url::parse(&self.issuer)
            .ok()
            .and_then(|parsed| parsed.host_str().map(|host| host.to_string()))
    }
}
