//! Opt-in workload-JWT EST subset. Transport TLS is the deployment's responsibility.
use axum::{
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use cms::{cert::x509::Certificate, content_info::ContentInfo};
use der::{Decode, Encode};
use qid_core::{
    error::{QidError, QidResult},
    models::WorkloadIdentity,
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use std::sync::Arc;

async fn authenticate<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<WorkloadIdentity, Response> {
    let Some(config) = state.config.realms.iter().find(|r| r.id == realm) else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let policy = &config.protocols.workload;
    // JWT issuer must unambiguously bind the path realm, including when realms share SPIFFE IDs.
    if !policy.est
        || !policy.jwt_svid
        || !policy.x509_svid
        || !state.workload_cas.contains_key(realm)
        || state
            .config
            .realms
            .iter()
            .any(|r| r.id != realm && r.issuer == config.issuer)
    {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    crate::workload_auth::authenticate_workload(headers, state, realm).await
}

fn invalid() -> QidError {
    QidError::BadRequest {
        message: "invalid EST PKCS#10 body".into(),
    }
}

// No MIME parameters or other transfer encodings in this deliberately narrow profile.
fn exact_header(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(expected.as_bytes()))
        && values.next().is_none()
}

const MIME_BASE64_LINE_LENGTH: usize = 76;

fn decode_csr(body: &[u8]) -> QidResult<Vec<u8>> {
    // MIME base64 uses CRLF-only folds of at most 76 characters per line.
    let mut compact = Vec::with_capacity(body.len());
    let mut line_len = 0;
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'\r' if body.get(i + 1) == Some(&b'\n') && line_len > 0 => {
                i += 2;
                line_len = 0;
            }
            b'\r' | b'\n' => return Err(invalid()),
            byte => {
                line_len += 1;
                if line_len > MIME_BASE64_LINE_LENGTH {
                    return Err(invalid());
                }
                compact.push(byte);
                i += 1;
            }
        }
    }
    STANDARD.decode(compact).map_err(|_| invalid())
}

fn encode_base64(body: &[u8]) -> String {
    let encoded = STANDARD.encode(body);
    let mut folded =
        String::with_capacity(encoded.len() + encoded.len().div_ceil(MIME_BASE64_LINE_LENGTH) * 2);
    for start in (0..encoded.len()).step_by(MIME_BASE64_LINE_LENGTH) {
        let end = (start + MIME_BASE64_LINE_LENGTH).min(encoded.len());
        folded.push_str(&encoded[start..end]);
        folded.push_str("\r\n");
    }
    folded
}

fn cms_response(pem: &str, leaf_only: bool) -> QidResult<Response> {
    let crypto = || QidError::Crypto {
        message: "EST certificate encoding failed".into(),
    };
    let mut certificates = Vec::new();
    for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
        certificates.push(
            Certificate::from_der(cert.map_err(|_| crypto())?.as_ref()).map_err(|_| crypto())?,
        );
        if leaf_only {
            break;
        }
    }
    if certificates.is_empty() {
        return Err(crypto());
    }
    // cms's existing helper produces degenerate SignedData, not a signed/encrypted payload.
    let cms = ContentInfo::try_from(certificates).map_err(|_| crypto())?;
    let body = encode_base64(&cms.to_der().map_err(|_| crypto())?);
    Ok((
        StatusCode::OK,
        [
            (
                "content-type",
                "application/pkcs7-mime; smime-type=certs-only",
            ),
            ("content-transfer-encoding", "base64"),
        ],
        body,
    )
        .into_response())
}

pub async fn cacerts<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate(&state, &realm, &headers).await {
        return e;
    }
    match cms_response(&state.workload_cas[&realm].certificate_pem, false) {
        Ok(response) => response,
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn simpleenroll<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    enroll(&state, &realm, &headers, body, false).await
}
pub async fn simplereenroll<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    enroll(&state, &realm, &headers, body, true).await
}
async fn enroll<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    headers: &HeaderMap,
    body: Body,
    renew: bool,
) -> Response {
    let workload = match authenticate(state, realm, headers).await {
        Ok(w) => w,
        Err(e) => return e,
    };
    if !exact_header(headers, "content-type", "application/pkcs10")
        || !exact_header(headers, "content-transfer-encoding", "base64")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let limit = state
        .config
        .realms
        .iter()
        .find(|r| r.id == realm)
        .map_or(0, |r| r.protocols.workload.max_csr_bytes);
    let bytes = match to_bytes(body, limit).await {
        Ok(bytes) if limit != 0 => bytes,
        _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let result = async {
        let der = decode_csr(&bytes)?;
        let csr = crate::workload::parse_workload_csr_der(&der)?;
        if renew {
            let now = qid_core::util::now_seconds();
            let prior = state
                .repo
                .list_workload_certificates(&RealmId(realm.into()), Some(&workload.id))
                .await?;
            if !prior.iter().any(|c| {
                c.realm_id == realm
                    && c.workload_id == workload.id
                    && c.spiffe_id == workload.spiffe_id
                    && c.revoked_at.is_none()
                    && c.not_before <= now
                    && now < c.not_after
            }) {
                return Err(QidError::Unauthorized {
                    message: "EST reenrollment requires a currently valid owned certificate".into(),
                });
            }
        }
        let action = if renew {
            "workload.certificate.est.simplereenroll"
        } else {
            "workload.certificate.est.simpleenroll"
        };
        let certificate = crate::workload::issue_verified_csr(
            state,
            realm,
            &workload,
            csr,
            qid_core::util::sha256_hex(&der),
            action,
        )
        .await?;
        cms_response(&certificate.certificate_pem, true)
    }
    .await;
    result.unwrap_or_else(qid_http::error_response)
}
