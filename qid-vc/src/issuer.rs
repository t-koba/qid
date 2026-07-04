use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::{User, VcCredentialStatusRecord},
    state::SharedState,
};
use qid_crypto::Jwk;
use qid_crypto::jwt::verify_jwt_signature_with_jwk;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::status::CredentialStatus;
use crate::{
    CredentialFormat, bad_request, bearer_token, decode_base64url_json,
    default_credential_configurations, error_response, internal_error,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
    #[serde(default)]
    pub format: Option<CredentialFormat>,
    #[serde(default)]
    pub claims: Vec<String>,
    #[serde(default)]
    pub selectively_disclosed_claims: Vec<String>,
    #[serde(default)]
    pub lifetime_seconds: Option<u64>,
    #[serde(default)]
    pub status_list_uri: Option<String>,
    #[serde(default)]
    pub holder_jwk: Option<Jwk>,
    #[serde(default)]
    pub proof: Option<CredentialProof>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    pub jwt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdJwtCredential {
    pub issuer: String,
    pub subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub visible_claims: BTreeMap<String, Value>,
    pub disclosures: Vec<SdJwtDisclosure>,
    pub status: CredentialStatus,
    #[serde(default)]
    pub holder_binding: Option<CredentialHolderBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdJwtDisclosure {
    pub claim_name: String,
    pub claim_value_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialHolderBinding {
    pub method: String,
    pub jwk_thumbprint: String,
    pub alg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialResponse {
    pub format: CredentialFormat,
    /// Issuer-signed JWT containing the credential payload in the `vc` claim.
    pub credential: String,
}

pub async fn issue_credential_from_bearer<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    request: CredentialRequest,
) -> QidResult<CredentialResponse> {
    let token = bearer_token(headers)?;
    let decoded = qid_oauth::endpoints::decode_access_token(state, token)
        .await
        .map_err(|_| QidError::Unauthorized {
            message: "invalid credential access token".to_string(),
        })?;
    let htu = format!(
        "{}/vc/v1/credential",
        state.plan.public_base_url.trim_end_matches('/')
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
        .collect::<HashSet<_>>();
    if !scopes.contains("qid_identity") {
        return Err(QidError::Unauthorized {
            message: "credential issuance requires qid_identity scope".to_string(),
        });
    }

    let configuration_id = request
        .credential_configuration_id
        .as_deref()
        .unwrap_or("qid_identity_sd_jwt");
    let configuration = default_credential_configurations()
        .into_iter()
        .find(|configuration| configuration.id == configuration_id)
        .ok_or_else(|| QidError::BadRequest {
            message: format!("unsupported credential configuration: {configuration_id}"),
        })?;
    let format = request.format.unwrap_or(configuration.format.clone());
    if format != configuration.format {
        return Err(QidError::BadRequest {
            message: "credential format does not match configuration".to_string(),
        });
    }
    let holder_jwk = request
        .holder_jwk
        .as_ref()
        .ok_or_else(|| QidError::BadRequest {
            message: "credential issuance requires holder_jwk".to_string(),
        })?;
    let holder_binding = holder_binding_from_jwk(holder_jwk)?;
    let proof = request.proof.as_ref().ok_or_else(|| QidError::BadRequest {
        message: "credential issuance requires holder proof".to_string(),
    })?;
    let nonce = request
        .nonce
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| QidError::BadRequest {
            message: "credential issuance requires nonce".to_string(),
        })?;
    verify_credential_issuance_proof(
        proof,
        holder_jwk,
        &holder_binding,
        state.plan.public_base_url.trim_end_matches('/'),
        nonce,
        qid_core::util::now_seconds(),
    )?;

    let user = state
        .repo
        .get_user_by_id(&decoded.user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "credential subject".to_string(),
        })?;
    let claim_names = if request.claims.is_empty() {
        configuration.claim_names
    } else {
        request.claims
    };
    let claims = credential_claims_for_user(&user, &claim_names)?;
    let default_status_list_uri = request.status_list_uri.is_none();
    let status_list_uri = request
        .status_list_uri
        .unwrap_or_else(|| state.plan.public_base_url.trim_end_matches('/').to_string());
    let mut credential = issue_sd_jwt_credential(
        &state.plan.public_base_url,
        &decoded.user_id,
        claims,
        &request.selectively_disclosed_claims,
        request.lifetime_seconds.unwrap_or(3600),
        &status_list_uri,
    )?;
    if default_status_list_uri {
        credential.status.status_list_uri = format!(
            "{}/vc/v1/status/{}",
            state.plan.public_base_url.trim_end_matches('/'),
            credential.status.credential_id
        );
    }
    credential.holder_binding = Some(holder_binding);
    let status = credential_status_record(&user.realm_id, &credential);
    state.repo.store_vc_credential_status(&status).await?;

    let credential_json = serde_json::to_value(&credential)
        .map_err(|e| internal_error(format!("credential serialization: {e}")))?;
    let mut extra = std::collections::HashMap::new();
    extra.insert("vc".to_string(), credential_json);
    let claims = JwtClaims {
        iss: Some(credential.issuer.clone()),
        sub: Some(credential.subject.clone()),
        aud: None,
        exp: Some(credential.expires_at as usize),
        nbf: None,
        iat: Some(credential.issued_at as usize),
        jti: None,
        extra,
    };
    let jwt = state
        .signer
        .sign(&claims)
        .map_err(|e| internal_error(format!("credential JWT signing: {e}")))?;

    Ok(CredentialResponse {
        format,
        credential: jwt,
    })
}

pub fn credential_status_record(
    realm_id: &str,
    credential: &SdJwtCredential,
) -> VcCredentialStatusRecord {
    VcCredentialStatusRecord {
        credential_id: credential.status.credential_id.clone(),
        realm_id: realm_id.to_string(),
        subject: credential.subject.clone(),
        issuer: credential.issuer.clone(),
        status_list_uri: credential.status.status_list_uri.clone(),
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
        revoked: credential.status.revoked,
        revocation_reason: credential.status.revocation_reason.clone(),
        revoked_at: None,
    }
}

pub fn credential_claims_for_user(
    user: &User,
    requested_claims: &[String],
) -> QidResult<BTreeMap<String, Value>> {
    let mut claims = BTreeMap::new();
    for claim in requested_claims {
        match claim.as_str() {
            "sub" => {
                claims.insert("sub".to_string(), Value::String(user.id.clone()));
            }
            "email" => {
                if let Some(email) = &user.email {
                    claims.insert("email".to_string(), Value::String(email.clone()));
                    claims.insert(
                        "email_verified".to_string(),
                        Value::Bool(user.email_verified),
                    );
                }
            }
            "name" => {
                if let Some(name) = &user.display_name {
                    claims.insert("name".to_string(), Value::String(name.clone()));
                }
            }
            "groups" | "roles" => {
                claims.insert(claim.clone(), Value::Array(Vec::new()));
            }
            unsupported => {
                return Err(QidError::BadRequest {
                    message: format!("unsupported credential claim: {unsupported}"),
                });
            }
        }
    }
    Ok(claims)
}

pub fn issue_sd_jwt_credential(
    issuer: &str,
    subject: &str,
    claims: BTreeMap<String, Value>,
    selectively_disclosed_claims: &[String],
    lifetime_seconds: u64,
    status_list_uri: &str,
) -> QidResult<SdJwtCredential> {
    if lifetime_seconds == 0 {
        return Err(bad_request("Credential lifetime must be greater than zero"));
    }

    let disclosure_set: HashSet<&str> = selectively_disclosed_claims
        .iter()
        .map(String::as_str)
        .collect();
    let mut visible_claims = BTreeMap::new();
    let mut disclosures = Vec::new();
    for (claim_name, claim_value) in claims {
        if disclosure_set.contains(claim_name.as_str()) {
            let disclosure = serde_json::json!([claim_name, claim_value]);
            let encoded = serde_json::to_vec(&disclosure).map_err(|err| {
                internal_error(format!("Failed to encode SD-JWT disclosure: {err}"))
            })?;
            disclosures.push(SdJwtDisclosure {
                claim_name,
                claim_value_hash: qid_core::util::sha256_base64url(encoded),
            });
        } else {
            visible_claims.insert(claim_name, claim_value);
        }
    }
    disclosures.sort_by(|a, b| a.claim_name.cmp(&b.claim_name));

    let issued_at = qid_core::util::now_seconds();
    let visible_claims_json = serde_json::to_value(&visible_claims)
        .map_err(|e| internal_error(format!("visible_claims serialization: {e}")))?;
    let claims_hash = qid_core::util::sha256_base64url(visible_claims_json.to_string());
    let credential_id =
        qid_core::util::sha256_base64url(format!("{issuer}:{subject}:{issued_at}:{claims_hash}"));
    Ok(SdJwtCredential {
        issuer: issuer.trim_end_matches('/').to_string(),
        subject: subject.to_string(),
        issued_at,
        expires_at: issued_at + lifetime_seconds,
        visible_claims,
        disclosures,
        status: CredentialStatus {
            credential_id,
            status_list_uri: status_list_uri.to_string(),
            revoked: false,
            revocation_reason: None,
        },
        holder_binding: None,
    })
}

pub fn holder_binding_from_jwk(jwk: &Jwk) -> QidResult<CredentialHolderBinding> {
    let alg = jwk.alg.clone().ok_or_else(|| QidError::BadRequest {
        message: "Holder JWK must include an alg".to_string(),
    })?;
    if !matches!(alg.as_str(), "ES256" | "EdDSA" | "RS256") {
        return Err(QidError::BadRequest {
            message: "Holder JWK alg is not supported".to_string(),
        });
    }
    Ok(CredentialHolderBinding {
        method: "jwk".to_string(),
        jwk_thumbprint: jwk_thumbprint(jwk)?,
        alg,
    })
}

fn verify_credential_issuance_proof(
    proof: &CredentialProof,
    holder_jwk: &Jwk,
    binding: &CredentialHolderBinding,
    expected_audience: &str,
    nonce: &str,
    now_epoch_seconds: u64,
) -> QidResult<()> {
    let (header, claims) = decode_credential_proof(&proof.jwt)?;
    let proof_jwk = header.jwk.ok_or_else(|| QidError::BadRequest {
        message: "Credential proof JWT header must include holder JWK".to_string(),
    })?;
    let alg = header.alg.as_deref().ok_or_else(|| QidError::BadRequest {
        message: "Credential proof JWT header must include alg".to_string(),
    })?;
    if alg != binding.alg {
        return Err(QidError::BadRequest {
            message: "Credential proof alg does not match holder binding".to_string(),
        });
    }
    let header_thumbprint = jwk_thumbprint(&proof_jwk)?;
    let request_thumbprint = jwk_thumbprint(holder_jwk)?;
    if !qid_core::util::constant_time_eq(&header_thumbprint, &request_thumbprint)
        || !qid_core::util::constant_time_eq(&header_thumbprint, &binding.jwk_thumbprint)
    {
        return Err(QidError::BadRequest {
            message: "Credential proof holder key does not match holder_jwk".to_string(),
        });
    }
    verify_jwt_signature_with_jwk(&proof.jwt, &proof_jwk, alg).map_err(|_| {
        QidError::BadRequest {
            message: "Credential proof signature is invalid".to_string(),
        }
    })?;
    if !qid_core::util::constant_time_eq(&claims.iss, &binding.jwk_thumbprint) {
        return Err(QidError::BadRequest {
            message: "Credential proof issuer must be the holder key thumbprint".to_string(),
        });
    }
    if claims.aud != expected_audience {
        return Err(QidError::BadRequest {
            message: "Credential proof audience does not match issuer".to_string(),
        });
    }
    if !qid_core::util::constant_time_eq(&claims.nonce, nonce) {
        return Err(QidError::BadRequest {
            message: "Credential proof nonce does not match".to_string(),
        });
    }
    if claims.jti.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "Credential proof jti is required".to_string(),
        });
    }
    if !qid_core::util::constant_time_eq(&claims.cnf.jkt, &binding.jwk_thumbprint) {
        return Err(QidError::BadRequest {
            message: "Credential proof cnf does not match holder binding".to_string(),
        });
    }
    if claims.iat > now_epoch_seconds + 60 || claims.iat + 300 < now_epoch_seconds {
        return Err(QidError::BadRequest {
            message: "Credential proof is outside the accepted time window".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialProofHeader {
    alg: Option<String>,
    jwk: Option<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialProofClaims {
    iss: String,
    aud: String,
    nonce: String,
    iat: u64,
    jti: String,
    cnf: CredentialProofConfirmation,
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialProofConfirmation {
    jkt: String,
}

fn decode_credential_proof(jwt: &str) -> QidResult<(CredentialProofHeader, CredentialProofClaims)> {
    let mut parts = jwt.split('.');
    let Some(header) = parts.next() else {
        return Err(bad_request("Credential proof JWT is malformed"));
    };
    let Some(payload) = parts.next() else {
        return Err(bad_request("Credential proof JWT is malformed"));
    };
    if parts.next().is_none() {
        return Err(bad_request("Credential proof JWT is malformed"));
    }
    if parts.next().is_some() {
        return Err(bad_request("Credential proof JWT is malformed"));
    }
    let header = decode_base64url_json(header, "credential proof header")?;
    let claims = decode_base64url_json(payload, "credential proof claims")?;
    Ok((header, claims))
}

pub(crate) fn jwk_thumbprint(jwk: &Jwk) -> QidResult<String> {
    let mut members = BTreeMap::new();
    match jwk.kty.as_str() {
        "EC" => {
            members.insert("crv", required_jwk_member(jwk.crv.as_deref(), "crv")?);
            members.insert("kty", jwk.kty.clone());
            members.insert("x", required_jwk_member(jwk.x.as_deref(), "x")?);
            members.insert("y", required_jwk_member(jwk.y.as_deref(), "y")?);
        }
        "OKP" => {
            members.insert("crv", required_jwk_member(jwk.crv.as_deref(), "crv")?);
            members.insert("kty", jwk.kty.clone());
            members.insert("x", required_jwk_member(jwk.x.as_deref(), "x")?);
        }
        "RSA" => {
            members.insert("e", required_jwk_member(jwk.e.as_deref(), "e")?);
            members.insert("kty", jwk.kty.clone());
            members.insert("n", required_jwk_member(jwk.n.as_deref(), "n")?);
        }
        _ => {
            return Err(QidError::BadRequest {
                message: "Holder JWK kty is not supported".to_string(),
            });
        }
    }
    let json = serde_json::to_string(&members).map_err(|err| QidError::BadRequest {
        message: format!("Failed to serialize holder JWK thumbprint input: {err}"),
    })?;
    Ok(qid_core::util::sha256_base64url(json))
}

pub(crate) fn required_jwk_member(value: Option<&str>, name: &str) -> QidResult<String> {
    value
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| QidError::BadRequest {
            message: format!("Holder JWK must include {name}"),
        })
}

pub(crate) async fn credential_issuer_metadata<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
) -> impl IntoResponse {
    let base = state.plan.public_base_url.trim_end_matches('/');
    let credential_configurations_supported = default_credential_configurations()
        .into_iter()
        .map(|configuration| (configuration.id.clone(), configuration))
        .collect::<BTreeMap<_, _>>();
    Json(serde_json::json!({
        "credential_issuer": base,
        "credential_endpoint": format!("{base}/vc/v1/credential"),
        "credential_configurations_supported": credential_configurations_supported,
        "display": [{ "name": "qid" }]
    }))
}

pub(crate) async fn credential_endpoint<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Response {
    match issue_credential_from_bearer(&state, &headers, request).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error_response(error),
    }
}
