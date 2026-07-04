use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    models::VcCredentialStatusRecord,
    state::SharedState,
};
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::issuer::{CredentialHolderBinding, SdJwtCredential, jwk_thumbprint};
use crate::{bad_request, decode_base64url_json, error_response, internal_error};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationVerification {
    pub issuer: String,
    pub subject: String,
    pub credential_id: String,
    pub expires_at: u64,
    pub status_list_uri: String,
    pub verified_claims: BTreeMap<String, Value>,
    pub visible_claim_names: Vec<String>,
    pub disclosed_claim_names: Vec<String>,
    #[serde(default)]
    pub holder_binding: Option<CredentialHolderBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationVerificationRequest {
    /// Issuer-signed JWT (compact serialization) containing the credential payload
    /// in the `vc` claim.
    pub credential: String,
    #[serde(default)]
    pub disclosed_claims: BTreeMap<String, Value>,
    #[serde(default)]
    pub required_claims: Vec<String>,
    #[serde(default)]
    pub now_epoch_seconds: Option<u64>,
    #[serde(default)]
    pub presentation_proof: Option<PresentationProof>,
    #[serde(default)]
    pub expected_audience: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentationProof {
    pub jwt: String,
}

pub fn verify_presentation_claims(
    credential: &SdJwtCredential,
    disclosed_claims: &BTreeMap<String, Value>,
    required_claims: &[String],
    now_epoch_seconds: u64,
) -> QidResult<()> {
    verify_presentation(
        credential,
        disclosed_claims,
        required_claims,
        now_epoch_seconds,
    )
    .map(|_| ())
}

pub fn verify_presentation(
    credential: &SdJwtCredential,
    disclosed_claims: &BTreeMap<String, Value>,
    required_claims: &[String],
    now_epoch_seconds: u64,
) -> QidResult<PresentationVerification> {
    if credential.status.revoked {
        return Err(bad_request("Credential has been revoked"));
    }
    if credential.expires_at <= now_epoch_seconds {
        return Err(bad_request("Credential has expired"));
    }

    let mut verified_claims = BTreeMap::new();
    let mut visible_claim_names = Vec::new();
    let mut disclosed_claim_names = Vec::new();
    for required in required_claims {
        if let Some(value) = credential.visible_claims.get(required) {
            verified_claims.insert(required.clone(), value.clone());
            visible_claim_names.push(required.clone());
            continue;
        }
        let Some(disclosed) = disclosed_claims.get(required) else {
            return Err(bad_request(format!(
                "Required claim is missing: {required}"
            )));
        };
        let disclosure = serde_json::json!([required, disclosed]);
        let encoded = serde_json::to_vec(&disclosure)
            .map_err(|err| internal_error(format!("Failed to encode SD-JWT disclosure: {err}")))?;
        let disclosed_hash = qid_core::util::sha256_base64url(encoded);
        let matches_disclosure = credential.disclosures.iter().any(|disclosure| {
            disclosure.claim_name == *required && disclosure.claim_value_hash == disclosed_hash
        });
        if !matches_disclosure {
            return Err(bad_request(format!(
                "Required claim disclosure does not match credential: {required}"
            )));
        }
        verified_claims.insert(required.clone(), disclosed.clone());
        disclosed_claim_names.push(required.clone());
    }

    visible_claim_names.sort();
    visible_claim_names.dedup();
    disclosed_claim_names.sort();
    disclosed_claim_names.dedup();

    Ok(PresentationVerification {
        issuer: credential.issuer.clone(),
        subject: credential.subject.clone(),
        credential_id: credential.status.credential_id.clone(),
        expires_at: credential.expires_at,
        status_list_uri: credential.status.status_list_uri.clone(),
        verified_claims,
        visible_claim_names,
        disclosed_claim_names,
        holder_binding: credential.holder_binding.clone(),
    })
}

pub async fn verify_presentation_with_status<R: Repository>(
    state: &Arc<SharedState<R>>,
    request: PresentationVerificationRequest,
) -> QidResult<PresentationVerification> {
    let token_data = state
        .signer
        .decode_signature_only(&request.credential)
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid credential JWT: {e}"),
        })?;
    let credential_value =
        token_data
            .claims
            .extra
            .get("vc")
            .ok_or_else(|| QidError::BadRequest {
                message: "credential JWT is missing vc claim".to_string(),
            })?;
    let credential: SdJwtCredential =
        serde_json::from_value(credential_value.clone()).map_err(|e| QidError::BadRequest {
            message: format!("invalid credential payload in JWT: {e}"),
        })?;
    if token_data.claims.iss.as_deref() != Some(&credential.issuer)
        || token_data.claims.iat != Some(credential.issued_at as usize)
        || token_data.claims.exp != Some(credential.expires_at as usize)
    {
        return Err(QidError::BadRequest {
            message: "credential JWT claims do not match credential payload".to_string(),
        });
    }

    let status = state
        .repo
        .get_vc_credential_status(&credential.status.credential_id)
        .await?
        .ok_or_else(|| QidError::BadRequest {
            message: "Credential status is not known to this issuer".to_string(),
        })?;
    validate_status_matches_credential(&credential, &status)?;
    if status.revoked {
        return Err(QidError::BadRequest {
            message: "Credential has been revoked".to_string(),
        });
    }
    let now_epoch_seconds = request
        .now_epoch_seconds
        .unwrap_or_else(qid_core::util::now_seconds);
    if let Some(binding) = credential.holder_binding.as_ref() {
        let proof = request
            .presentation_proof
            .as_ref()
            .ok_or_else(|| QidError::BadRequest {
                message: "Holder-bound credential requires a presentation proof".to_string(),
            })?;
        let audience =
            request
                .expected_audience
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "Holder-bound presentation requires an expected audience".to_string(),
                })?;
        let nonce = request
            .nonce
            .as_deref()
            .ok_or_else(|| QidError::BadRequest {
                message: "Holder-bound presentation requires a nonce".to_string(),
            })?;
        verify_presentation_proof(
            &credential,
            binding,
            proof,
            audience,
            nonce,
            now_epoch_seconds,
        )?;
    }
    verify_presentation(
        &credential,
        &request.disclosed_claims,
        &request.required_claims,
        now_epoch_seconds,
    )
}

pub fn verify_presentation_proof(
    credential: &SdJwtCredential,
    binding: &CredentialHolderBinding,
    proof: &PresentationProof,
    expected_audience: &str,
    nonce: &str,
    now_epoch_seconds: u64,
) -> QidResult<()> {
    let (header, claims) = decode_presentation_proof(&proof.jwt)?;
    let jwk = header.jwk.ok_or_else(|| QidError::BadRequest {
        message: "Presentation proof JWT header must include holder JWK".to_string(),
    })?;
    let alg = header.alg.as_deref().ok_or_else(|| QidError::BadRequest {
        message: "Presentation proof JWT header must include alg".to_string(),
    })?;
    if alg != binding.alg {
        return Err(QidError::BadRequest {
            message: "Presentation proof alg does not match credential holder binding".to_string(),
        });
    }
    let thumbprint = jwk_thumbprint(&jwk)?;
    if !qid_core::util::constant_time_eq(&thumbprint, &binding.jwk_thumbprint) {
        return Err(QidError::BadRequest {
            message: "Presentation proof holder key does not match credential binding".to_string(),
        });
    }
    verify_jwt_signature_with_jwk(&proof.jwt, &jwk, alg).map_err(|_| QidError::BadRequest {
        message: "Presentation proof signature is invalid".to_string(),
    })?;
    if !qid_core::util::constant_time_eq(&claims.credential_id, &credential.status.credential_id) {
        return Err(QidError::BadRequest {
            message: "Presentation proof credential id does not match".to_string(),
        });
    }
    if !qid_core::util::constant_time_eq(&claims.cnf.jkt, &binding.jwk_thumbprint) {
        return Err(QidError::BadRequest {
            message: "Presentation proof cnf does not match credential binding".to_string(),
        });
    }
    if !qid_core::util::constant_time_eq(&claims.iss, &binding.jwk_thumbprint) {
        return Err(QidError::BadRequest {
            message: "Presentation proof issuer must be the holder key thumbprint".to_string(),
        });
    }
    if claims.aud != expected_audience {
        return Err(QidError::BadRequest {
            message: "Presentation proof audience does not match".to_string(),
        });
    }
    if !qid_core::util::constant_time_eq(&claims.nonce, nonce) {
        return Err(QidError::BadRequest {
            message: "Presentation proof nonce does not match".to_string(),
        });
    }
    if claims.jti.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "Presentation proof jti is required".to_string(),
        });
    }
    if claims.iat > now_epoch_seconds + 60 || claims.iat + 300 < now_epoch_seconds {
        return Err(QidError::BadRequest {
            message: "Presentation proof is outside the accepted time window".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct PresentationProofHeader {
    alg: Option<String>,
    jwk: Option<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct PresentationProofClaims {
    iss: String,
    aud: String,
    nonce: String,
    iat: u64,
    jti: String,
    credential_id: String,
    cnf: PresentationProofConfirmation,
}

#[derive(Debug, Clone, Deserialize)]
struct PresentationProofConfirmation {
    jkt: String,
}

fn decode_presentation_proof(
    jwt: &str,
) -> QidResult<(PresentationProofHeader, PresentationProofClaims)> {
    let mut parts = jwt.split('.');
    let Some(header) = parts.next() else {
        return Err(bad_request("Presentation proof JWT is malformed"));
    };
    let Some(payload) = parts.next() else {
        return Err(bad_request("Presentation proof JWT is malformed"));
    };
    if parts.next().is_none() {
        return Err(bad_request("Presentation proof JWT is malformed"));
    }
    if parts.next().is_some() {
        return Err(bad_request("Presentation proof JWT is malformed"));
    }
    let header = decode_base64url_json(header, "presentation proof header")?;
    let claims = decode_base64url_json(payload, "presentation proof claims")?;
    Ok((header, claims))
}

fn validate_status_matches_credential(
    credential: &SdJwtCredential,
    status: &VcCredentialStatusRecord,
) -> QidResult<()> {
    if status.subject != credential.subject
        || status.issuer != credential.issuer
        || status.status_list_uri != credential.status.status_list_uri
        || status.issued_at != credential.issued_at
        || status.expires_at != credential.expires_at
    {
        return Err(QidError::BadRequest {
            message: "Credential status does not match presented credential".to_string(),
        });
    }
    // Recompute credential_id from visible_claims to detect tampering.
    let visible_claims_json = serde_json::to_value(&credential.visible_claims)
        .map_err(|e| internal_error(format!("visible_claims serialization: {e}")))?;
    let claims_hash = qid_core::util::sha256_base64url(visible_claims_json.to_string());
    let expected_credential_id = qid_core::util::sha256_base64url(format!(
        "{}:{}:{}:{}",
        credential.issuer, credential.subject, credential.issued_at, claims_hash
    ));
    if expected_credential_id != status.credential_id {
        return Err(QidError::BadRequest {
            message: "Credential visible_claims integrity check failed".to_string(),
        });
    }
    Ok(())
}

pub(crate) async fn verify_presentation_endpoint<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Json(mut request): Json<PresentationVerificationRequest>,
) -> Response {
    request.now_epoch_seconds = None;
    match verify_presentation_with_status(&state, request).await {
        Ok(verification) => Json(verification).into_response(),
        Err(error) => error_response(error),
    }
}
