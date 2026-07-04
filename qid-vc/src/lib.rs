#![forbid(unsafe_code)]
#![allow(dead_code)]

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    error::{QidError, QidResult},
    state::SharedState,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod bitstring_status_list;
pub mod haip;
pub mod issuer;
pub mod mdoc;
pub mod oid4vp;
pub mod status;
pub mod verifier;

pub use bitstring_status_list::{
    BitstringStatusListCredential, decode_bitstring_status_entry, encode_bitstring_status_list,
    next_bitstring_index, set_bitstring_status_entry,
};
pub use haip::{
    HaipReaderRegistration, HaipTransactionData, build_haip_reader_registration,
    validate_haip_transaction_data,
};
pub use issuer::{
    CredentialHolderBinding, CredentialRequest, CredentialResponse, SdJwtCredential,
    SdJwtDisclosure, credential_claims_for_user, credential_status_record, holder_binding_from_jwk,
    issue_credential_from_bearer, issue_sd_jwt_credential,
};
pub use mdoc::{
    DataElementIdentifier, MdocCertificate, MdocCertificateUsage, MdocDataElement,
    MdocDataElementValue, MdocDocument, MdocIssuerSigned, MdocNamespace, Namespace,
    build_mdoc_document, decode_mdoc_document, encode_mdoc_document, require_mdoc_element,
};
pub use oid4vp::{
    Oid4VpPresentationDefinition, Oid4VpPresentationSubmission, Oid4VpRequest,
    build_oid4vp_presentation_submission, decode_oid4vp_request_uri, encode_oid4vp_request_uri,
};
pub use status::{
    CredentialRevocationRequest, CredentialStatus, CredentialStatusResponse, revoke_credential,
    revoke_credential_from_bearer,
};
pub use verifier::{
    PresentationProof, PresentationVerification, PresentationVerificationRequest,
    verify_presentation, verify_presentation_claims, verify_presentation_proof,
    verify_presentation_with_status,
};

pub fn vc_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer::credential_issuer_metadata::<R>),
        )
        .route("/vc/v1/credential", post(issuer::credential_endpoint::<R>))
        .route(
            "/vc/v1/status/:credential_id",
            get(status::credential_status::<R>),
        )
        .route(
            "/vc/v1/status/:credential_id/revoke",
            post(status::revoke_credential_status::<R>),
        )
        .route(
            "/vc/v1/presentation/verify",
            post(verifier::verify_presentation_endpoint::<R>),
        )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialConfiguration {
    pub id: String,
    pub format: CredentialFormat,
    pub scope: String,
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<String>,
    pub claim_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    JwtVcJson,
    SdJwtVc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialOfferGrants {
    #[serde(default)]
    pub authorization_code: Option<AuthorizationCodeGrant>,
    #[serde(default)]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    pub pre_authorized_code: String,
    pub tx_code_required: bool,
}

pub fn default_credential_configurations() -> Vec<CredentialConfiguration> {
    vec![CredentialConfiguration {
        id: "qid_identity_sd_jwt".to_string(),
        format: CredentialFormat::SdJwtVc,
        scope: "openid qid_identity".to_string(),
        cryptographic_binding_methods_supported: vec!["jwk".to_string()],
        credential_signing_alg_values_supported: vec!["ES256".to_string(), "EdDSA".to_string()],
        claim_names: vec![
            "sub".to_string(),
            "email".to_string(),
            "name".to_string(),
            "groups".to_string(),
            "roles".to_string(),
        ],
    }]
}

pub fn build_credential_offer(
    issuer: &str,
    configuration_ids: Vec<String>,
    issuer_state: Option<String>,
    pre_authorized_code: Option<String>,
    tx_code_required: bool,
) -> QidResult<CredentialOffer> {
    if configuration_ids.is_empty() {
        return Err(bad_request(
            "Credential offer must include at least one credential configuration",
        ));
    }
    if issuer_state.is_none() && pre_authorized_code.is_none() {
        return Err(bad_request(
            "Credential offer must include an authorization grant",
        ));
    }
    Ok(CredentialOffer {
        credential_issuer: issuer.trim_end_matches('/').to_string(),
        credential_configuration_ids: configuration_ids,
        grants: CredentialOfferGrants {
            authorization_code: issuer_state.map(|state| AuthorizationCodeGrant {
                issuer_state: state,
            }),
            pre_authorized_code: pre_authorized_code.map(|code| PreAuthorizedCodeGrant {
                pre_authorized_code: code,
                tx_code_required,
            }),
        },
    })
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> QidResult<&str> {
    qid_oauth::endpoints::extract_bearer_token(headers).map_err(|_| QidError::Unauthorized {
        message: "credential endpoint requires a bearer token".to_string(),
    })
}

pub(crate) fn error_response(error: QidError) -> Response {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(serde_json::json!({
            "error": oauth_error_code(&error),
            "error_description": error.message()
        })),
    )
        .into_response()
}

pub(crate) fn oauth_error_code(error: &QidError) -> &'static str {
    match error {
        QidError::Unauthorized { .. } => "invalid_token",
        QidError::BadRequest { .. } => "invalid_request",
        QidError::NotFound { .. } => "invalid_request",
        QidError::Config { .. }
        | QidError::Crypto { .. }
        | QidError::Storage { .. }
        | QidError::Internal { .. }
        | QidError::TooManyRequests { .. }
        | QidError::Conflict { .. } => "server_error",
    }
}

pub(crate) fn bad_request(message: impl Into<String>) -> QidError {
    QidError::BadRequest {
        message: message.into(),
    }
}

pub(crate) fn internal_error(message: impl Into<String>) -> QidError {
    QidError::Internal {
        message: message.into(),
    }
}

pub(crate) fn decode_base64url_json<T: for<'de> Deserialize<'de>>(
    value: &str,
    context: &str,
) -> QidResult<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| QidError::BadRequest {
            message: format!("Failed to decode {context}: {err}"),
        })?;
    serde_json::from_slice(&bytes).map_err(|err| QidError::BadRequest {
        message: format!("Failed to parse {context}: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::models::User;
    use qid_crypto::{jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn credential_offer_requires_configuration_and_grant() {
        assert!(
            build_credential_offer("https://issuer.example", Vec::new(), None, None, false)
                .is_err()
        );
        assert!(
            build_credential_offer(
                "https://issuer.example",
                vec!["qid_identity_sd_jwt".to_string()],
                None,
                None,
                false,
            )
            .is_err()
        );

        let offer = build_credential_offer(
            "https://issuer.example/",
            vec!["qid_identity_sd_jwt".to_string()],
            Some("issuer-state".to_string()),
            None,
            false,
        )
        .unwrap();

        assert_eq!(offer.credential_issuer, "https://issuer.example");
        assert!(offer.grants.authorization_code.is_some());
    }

    #[test]
    fn credential_claims_for_user_releases_supported_claims_only() {
        let user = User {
            id: "user-1".to_string(),
            realm_id: "test".to_string(),
            email: Some("user@example.com".to_string()),
            email_verified: true,
            display_name: Some("Test User".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };

        let claims = credential_claims_for_user(
            &user,
            &[
                "sub".to_string(),
                "email".to_string(),
                "name".to_string(),
                "groups".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(claims["sub"], json!("user-1"));
        assert_eq!(claims["email"], json!("user@example.com"));
        assert_eq!(claims["email_verified"], json!(true));
        assert_eq!(claims["name"], json!("Test User"));
        assert_eq!(claims["groups"], json!([]));

        let err = credential_claims_for_user(&user, &["phone_number".to_string()]).unwrap_err();
        assert!(err.to_string().contains("unsupported credential claim"));
    }

    #[test]
    fn sd_jwt_credential_hides_selective_claims_and_verifies_disclosure() {
        let claims = BTreeMap::from([
            ("sub".to_string(), json!("user-1")),
            ("email".to_string(), json!("user@example.com")),
            ("groups".to_string(), json!(["engineering"])),
        ]);
        let credential = issue_sd_jwt_credential(
            "https://issuer.example",
            "user-1",
            claims,
            &["email".to_string()],
            3600,
            "https://issuer.example/status/1",
        )
        .unwrap();

        assert!(credential.visible_claims.contains_key("sub"));
        assert!(!credential.visible_claims.contains_key("email"));
        assert_eq!(credential.disclosures.len(), 1);

        let disclosed = BTreeMap::from([("email".to_string(), json!("user@example.com"))]);
        let verification = verify_presentation(
            &credential,
            &disclosed,
            &["sub".to_string(), "email".to_string()],
            credential.issued_at,
        )
        .unwrap();

        assert_eq!(verification.subject, "user-1");
        assert_eq!(verification.issuer, "https://issuer.example");
        assert_eq!(verification.visible_claim_names, vec!["sub".to_string()]);
        assert_eq!(
            verification.disclosed_claim_names,
            vec!["email".to_string()]
        );
        assert_eq!(verification.verified_claims["sub"], json!("user-1"));
        assert_eq!(
            verification.verified_claims["email"],
            json!("user@example.com")
        );

        verify_presentation_claims(
            &credential,
            &disclosed,
            &["sub".to_string(), "email".to_string()],
            credential.issued_at,
        )
        .unwrap();
    }

    #[test]
    fn revoked_credential_rejects_presentation() {
        let claims = BTreeMap::from([("sub".to_string(), json!("user-1"))]);
        let mut credential = issue_sd_jwt_credential(
            "https://issuer.example",
            "user-1",
            claims,
            &[],
            3600,
            "https://issuer.example/status/1",
        )
        .unwrap();
        let credential_id = credential.status.credential_id.clone();
        let registry = HashMap::from([(credential_id.clone(), credential.status.clone())]);
        let registry = revoke_credential(registry, &credential_id, "account_closed").unwrap();
        credential.status = registry.get(&credential_id).cloned().unwrap();

        let err = verify_presentation_claims(
            &credential,
            &BTreeMap::new(),
            &["sub".to_string()],
            credential.issued_at,
        )
        .unwrap_err();

        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn holder_bound_presentation_requires_matching_proof() {
        let key = generate_es256("holder").unwrap();
        let binding = holder_binding_from_jwk(&key.public_jwk).unwrap();
        let claims = BTreeMap::from([("sub".to_string(), json!("user-1"))]);
        let mut credential = issue_sd_jwt_credential(
            "https://issuer.example",
            "user-1",
            claims,
            &[],
            3600,
            "https://issuer.example/status/1",
        )
        .unwrap();
        credential.holder_binding = Some(binding.clone());

        let now = credential.issued_at;
        let proof = sign_es256_jwt_with_jwk_header(
            key.private_pem.as_bytes(),
            &key.public_jwk,
            "openid4vp-proof+jwt",
            &json!({
                "iss": binding.jwk_thumbprint,
                "aud": "https://verifier.example",
                "nonce": "nonce-1",
                "iat": now,
                "jti": "proof-1",
                "credential_id": credential.status.credential_id,
                "cnf": { "jkt": binding.jwk_thumbprint }
            }),
        )
        .unwrap();

        verify_presentation_proof(
            &credential,
            credential.holder_binding.as_ref().unwrap(),
            &PresentationProof { jwt: proof.clone() },
            "https://verifier.example",
            "nonce-1",
            now,
        )
        .unwrap();

        let err = verify_presentation_proof(
            &credential,
            credential.holder_binding.as_ref().unwrap(),
            &PresentationProof { jwt: proof },
            "https://other-verifier.example",
            "nonce-1",
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("audience"));
    }
}
