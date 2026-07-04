use axum::http::{HeaderMap, header};
use qid_core::{error::QidError, models::WorkloadIdentity, state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;

const WORKLOAD_API_AUDIENCE: &str = "qid-workload-api";
const WORKLOAD_PROVISIONING_AUDIENCE: &str = "qid-workload-provisioning";

pub(crate) async fn require_workload_for_spiffe<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm: &str,
    target_spiffe_id: &str,
) -> Result<WorkloadIdentity, axum::response::Response> {
    let caller = authenticate_workload(headers, state, realm).await?;
    if caller.spiffe_id != target_spiffe_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "caller workload does not match target SPIFFE ID".to_string(),
        }));
    }
    Ok(caller)
}

pub(crate) async fn authenticate_workload<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm: &str,
) -> Result<WorkloadIdentity, axum::response::Response> {
    if let Some(identity) = authenticate_jwt_svid(headers, state, realm).await? {
        return Ok(identity);
    }
    Err(qid_http::error_response(QidError::Unauthorized {
        message: "workload authentication required: present a qid-workload-api SVID".to_string(),
    }))
}

pub(crate) async fn require_workload_provisioning_for_spiffe<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm: &str,
    target_spiffe_id: &str,
) -> Result<(), axum::response::Response> {
    let token = bearer_token(headers).ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "workload provisioning token is required".to_string(),
        })
    })?;
    let decoded = state
        .signer
        .decode_with_aud(token, WORKLOAD_PROVISIONING_AUDIENCE)
        .map_err(|_| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid workload provisioning token".to_string(),
            })
        })?;
    let subject = decoded.claims.sub.as_deref().ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "workload provisioning token is missing a SPIFFE subject".to_string(),
        })
    })?;
    if subject != target_spiffe_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "workload provisioning token does not match target SPIFFE ID".to_string(),
        }));
    }

    let tenant_id = state
        .repo
        .get_realm_tenant(&RealmId(realm.to_string()))
        .await
        .map_err(qid_http::error_response)?
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload provisioning realm is not registered".to_string(),
            })
        })?;
    let token_realm =
        claim_str(&decoded.claims.extra, &["realm_id", "realm"]).ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload provisioning token is missing realm binding".to_string(),
            })
        })?;
    if token_realm != realm {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "workload provisioning token realm does not match target realm".to_string(),
        }));
    }
    let token_tenant =
        claim_str(&decoded.claims.extra, &["tenant_id", "tenant"]).ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload provisioning token is missing tenant binding".to_string(),
            })
        })?;
    if token_tenant != tenant_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "workload provisioning token tenant does not match target tenant".to_string(),
        }));
    }
    Ok(())
}

fn claim_str<'a>(
    extra: &'a std::collections::HashMap<String, serde_json::Value>,
    names: &[&str],
) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| extra.get(*name).and_then(|value| value.as_str()))
}

async fn authenticate_jwt_svid<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm: &str,
) -> Result<Option<WorkloadIdentity>, axum::response::Response> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    let decoded = state
        .signer
        .decode_with_aud(token, WORKLOAD_API_AUDIENCE)
        .map_err(|_| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid workload JWT-SVID".to_string(),
            })
        })?;
    let expected_issuer = state
        .realm(realm)
        .map(|realm_config| realm_config.issuer.as_str())
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload JWT-SVID realm is not configured".to_string(),
            })
        })?;
    if decoded.claims.iss.as_deref() != Some(expected_issuer) {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "workload JWT-SVID issuer does not match target realm".to_string(),
        }));
    }
    let spiffe_id = decoded
        .claims
        .sub
        .or_else(|| {
            decoded
                .claims
                .extra
                .get("spiffe_id")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        })
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload JWT-SVID is missing a SPIFFE subject".to_string(),
            })
        })?;
    load_workload_identity(state, realm, &spiffe_id)
        .await
        .map(Some)
}

async fn load_workload_identity<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    spiffe_id: &str,
) -> Result<WorkloadIdentity, axum::response::Response> {
    crate::eat::validate_spiffe_id(spiffe_id).map_err(qid_http::error_response)?;
    state
        .repo
        .get_workload_identity_by_spiffe(&RealmId(realm.to_string()), spiffe_id)
        .await
        .map_err(qid_http::error_response)?
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "workload identity is not registered in this realm".to_string(),
            })
        })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.contains(' ')).then_some(token)
}
