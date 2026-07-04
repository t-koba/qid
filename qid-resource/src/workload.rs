//! qid-resource workload module.

use crate::workload_auth;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::not_found_response;
use qid_core::models::{WorkloadCertificate, WorkloadIdentity};

//
// Workload identity
//

#[derive(Debug, Deserialize)]
pub struct CreateWorkloadIdentityRequest {
    spiffe_id: String,
    trust_domain: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IssueWorkloadCertificateRequest {
    workload_id: String,
    spiffe_id: String,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeWorkloadCertificateRequest {
    revoked_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct WorkloadCertificateQuery {
    workload_id: Option<String>,
}

pub(crate) struct IssuedWorkloadCertificate {
    pub(crate) certificate: WorkloadCertificate,
    pub(crate) private_key_pem: String,
}

pub async fn create_workload_identity<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<CreateWorkloadIdentityRequest>,
) -> Response {
    if let Err(e) = workload_auth::require_workload_provisioning_for_spiffe(
        &headers,
        &state,
        &realm,
        &req.spiffe_id,
    )
    .await
    {
        return e;
    }
    let wi = WorkloadIdentity {
        id: ulid::Ulid::new().to_string(),
        realm_id: realm,
        spiffe_id: req.spiffe_id,
        trust_domain: req.trust_domain,
        description: req.description,
        authorities_json: serde_json::Value::Null,
    };
    match state.repo.create_workload_identity(&wi).await {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!(wi))).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn get_workload_identity<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, spiffe_id)): Path<(String, String)>,
) -> Response {
    if let Err(e) =
        workload_auth::require_workload_for_spiffe(&headers, &state, &realm, &spiffe_id).await
    {
        return e;
    }
    match state
        .repo
        .get_workload_identity_by_spiffe(&RealmId(realm), &spiffe_id)
        .await
    {
        Ok(Some(wi)) => Json(serde_json::json!(wi)).into_response(),
        Ok(None) => not_found_response(&format!("workload identity {spiffe_id} not found")),
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn issue_workload_certificate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Json(req): Json<IssueWorkloadCertificateRequest>,
) -> Response {
    let realm_id = RealmId(realm.clone());
    let workload = match state
        .repo
        .get_workload_identity_by_spiffe(&realm_id, &req.spiffe_id)
        .await
    {
        Ok(Some(workload)) => workload,
        Ok(None) => {
            return not_found_response(&format!("workload identity {} not found", req.spiffe_id));
        }
        Err(e) => return qid_http::error_response(e),
    };
    if workload.id != req.workload_id {
        return qid_http::error_response(qid_core::error::QidError::BadRequest {
            message: "workload certificate workload_id does not match SPIFFE identity".to_string(),
        });
    }
    if let Err(e) =
        workload_auth::require_workload_for_spiffe(&headers, &state, &realm, &workload.spiffe_id)
            .await
    {
        return e;
    }
    match issue_qid_controlled_workload_certificate(&state, &realm, &workload, req.ttl_seconds) {
        Ok(issued) => match state
            .repo
            .store_workload_certificate(&issued.certificate)
            .await
        {
            Ok(()) => (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "certificate": issued.certificate,
                    "private_key_pem": issued.private_key_pem,
                })),
            )
                .into_response(),
            Err(e) => qid_http::error_response(e),
        },
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) fn issue_qid_controlled_workload_certificate(
    state: &SharedState<impl Repository>,
    realm: &str,
    workload: &WorkloadIdentity,
    ttl_seconds: Option<u64>,
) -> qid_core::error::QidResult<IssuedWorkloadCertificate> {
    crate::eat::validate_spiffe_id(&workload.spiffe_id)?;
    let now = qid_core::util::now_seconds();
    let ttl = ttl_seconds.unwrap_or(3600).clamp(60, 3600);
    let not_after = now + ttl;
    let ca_certificate_pem = state
        .workload_ca_certificate_pem
        .as_deref()
        .ok_or_else(|| qid_core::error::QidError::Config {
            message: "workload certificate issuance requires configured workload CA certificate"
                .to_string(),
        })?;
    let ca_private_key_pem = state
        .workload_ca_private_key_pem
        .as_deref()
        .ok_or_else(|| qid_core::error::QidError::Config {
            message: "workload certificate issuance requires configured workload CA private key"
                .to_string(),
        })?;
    let ca_key = rcgen::KeyPair::from_pem(ca_private_key_pem).map_err(|error| {
        qid_core::error::QidError::Crypto {
            message: format!("workload CA private key is invalid: {error}"),
        }
    })?;
    let ca_params =
        rcgen::CertificateParams::from_ca_cert_pem(ca_certificate_pem).map_err(|error| {
            qid_core::error::QidError::Crypto {
                message: format!("workload CA certificate is invalid: {error}"),
            }
        })?;
    let ca_cert =
        ca_params
            .self_signed(&ca_key)
            .map_err(|error| qid_core::error::QidError::Crypto {
                message: format!("workload CA certificate reconstruction failed: {error}"),
            })?;

    let leaf_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|error| {
            qid_core::error::QidError::Crypto {
                message: format!("workload SVID key generation failed: {error}"),
            }
        })?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, workload.spiffe_id.clone());
        dn
    };
    params.subject_alt_names = vec![rcgen::SanType::URI(
        workload.spiffe_id.clone().try_into().map_err(|error| {
            qid_core::error::QidError::BadRequest {
                message: format!("SPIFFE ID cannot be encoded as URI SAN: {error}"),
            }
        })?,
    )];
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = epoch_to_offset(now)?;
    params.not_after = epoch_to_offset(not_after)?;
    let cert = params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|error| qid_core::error::QidError::Crypto {
            message: format!("workload SVID certificate signing failed: {error}"),
        })?;
    let cert_der = cert.der().as_ref();
    let x5t_s256 = hex::encode(Sha256::digest(cert_der));
    let csr_sha256 = hex::encode(Sha256::digest(leaf_key.public_key_der()));
    let serial_number = ulid::Ulid::new().to_string();
    let certificate_pem = format!("{}{}", cert.pem(), ca_cert.pem());
    let certificate = WorkloadCertificate {
        id: format!("wcert_{serial_number}"),
        realm_id: realm.to_string(),
        workload_id: workload.id.clone(),
        spiffe_id: workload.spiffe_id.clone(),
        serial_number,
        x5t_s256,
        csr_sha256,
        certificate_pem,
        issuer_key_ref: format!("qid-workload-ca:{realm}"),
        issued_at: now,
        not_before: now,
        not_after,
        revoked_at: None,
    };
    certificate.validate()?;
    Ok(IssuedWorkloadCertificate {
        certificate,
        private_key_pem: leaf_key.serialize_pem(),
    })
}

fn epoch_to_offset(epoch_seconds: u64) -> qid_core::error::QidResult<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(epoch_seconds as i64).map_err(|error| {
        qid_core::error::QidError::BadRequest {
            message: format!("certificate timestamp is invalid: {error}"),
        }
    })
}

pub async fn list_workload_certificates<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(realm): Path<String>,
    Query(query): Query<WorkloadCertificateQuery>,
) -> Response {
    let caller = match workload_auth::authenticate_workload(&headers, &state, &realm).await {
        Ok(caller) => caller,
        Err(e) => return e,
    };
    if let Some(workload_id) = query.workload_id.as_deref()
        && workload_id != caller.id
    {
        return qid_http::error_response(qid_core::error::QidError::Unauthorized {
            message: "caller workload cannot list certificates for another workload".to_string(),
        });
    }
    match state
        .repo
        .list_workload_certificates(&RealmId(realm), Some(&caller.id))
        .await
    {
        Ok(certificates) => {
            Json(serde_json::json!({ "certificates": certificates })).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn revoke_workload_certificate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path((realm, certificate_id)): Path<(String, String)>,
    Json(req): Json<RevokeWorkloadCertificateRequest>,
) -> Response {
    let caller = match workload_auth::authenticate_workload(&headers, &state, &realm).await {
        Ok(caller) => caller,
        Err(e) => return e,
    };
    let caller_certificates = match state
        .repo
        .list_workload_certificates(&RealmId(realm.clone()), Some(&caller.id))
        .await
    {
        Ok(certificates) => certificates,
        Err(e) => return qid_http::error_response(e),
    };
    if !caller_certificates
        .iter()
        .any(|certificate| certificate.id == certificate_id)
    {
        return qid_http::error_response(qid_core::error::QidError::Unauthorized {
            message: "caller workload cannot revoke a certificate for another workload".to_string(),
        });
    }
    match state
        .repo
        .revoke_workload_certificate(&RealmId(realm), &certificate_id, req.revoked_at)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => qid_http::error_response(e),
    }
}
