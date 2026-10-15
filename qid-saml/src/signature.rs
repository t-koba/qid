use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

use crate::xmldsig::{SamlSigningElement, SamlXmlSignatureAlgorithm, sign_saml_document_with_key};
use crate::{SamlIssuedResponse, SamlServiceProviderMetadata, inspect_xml_signature_profile};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SamlSignatureTarget {
    Response,
    Assertion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlSigningPolicy {
    pub sign_response: bool,
    pub sign_assertion: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlSignaturePlan {
    pub targets: Vec<SamlSignatureTarget>,
    pub response_reference: Option<String>,
    pub assertion_reference: Option<String>,
}

pub fn plan_saml_signatures(
    issued: &SamlIssuedResponse,
    sp: &SamlServiceProviderMetadata,
    policy: &SamlSigningPolicy,
) -> QidResult<SamlSignaturePlan> {
    let mut targets = Vec::new();
    if policy.sign_assertion || sp.want_assertions_signed {
        targets.push(SamlSignatureTarget::Assertion);
    }
    if policy.sign_response {
        targets.push(SamlSignatureTarget::Response);
    }
    if targets.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML response must sign response or assertion".to_string(),
        });
    }
    Ok(SamlSignaturePlan {
        response_reference: targets
            .contains(&SamlSignatureTarget::Response)
            .then(|| format!("#{}", issued.response_id)),
        assertion_reference: targets
            .contains(&SamlSignatureTarget::Assertion)
            .then(|| format!("#{}", issued.assertion_id)),
        targets,
    })
}

/// Sign the Assertion before the Response so the outer signature covers the
/// complete inner signature. Each pass signs the full document in context.
pub fn sign_saml_response_with_key(
    issued: &SamlIssuedResponse,
    sp: &SamlServiceProviderMetadata,
    policy: &SamlSigningPolicy,
    private_key_pem: &[u8],
    algorithm: SamlXmlSignatureAlgorithm,
) -> QidResult<SamlIssuedResponse> {
    let plan = plan_saml_signatures(issued, sp, policy)?;
    let mut xml = issued.xml.clone();
    for target in plan.targets {
        let (kind, id) = match target {
            SamlSignatureTarget::Assertion => (SamlSigningElement::Assertion, &issued.assertion_id),
            SamlSignatureTarget::Response => (SamlSigningElement::Response, &issued.response_id),
        };
        xml = sign_saml_document_with_key(&xml, kind, id, algorithm, private_key_pem)?;
    }
    Ok(SamlIssuedResponse {
        xml,
        ..issued.clone()
    })
}

pub fn validate_authn_request_signature_profile(
    req: &crate::SamlAuthnRequest,
    sp: &SamlServiceProviderMetadata,
) -> QidResult<crate::SamlXmlSignatureProfile> {
    // Verify with the existing inbound profile.
    // The trust key is selected from the SP's configured signing certificates.
    if sp.signing_certificates.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML SP metadata must include a signing key; none are configured".to_string(),
        });
    }
    let profile = inspect_xml_signature_profile(&req.raw_xml, "AuthnRequest")?;
    if profile.reference_uri.as_deref() != Some(&format!("#{}", req.id)) {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest signature must reference the AuthnRequest identifier"
                .to_string(),
        });
    }
    let signing_cert =
        profile
            .signing_certificate
            .as_ref()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML AuthnRequest signature must include an X.509 certificate"
                    .to_string(),
            })?;
    if !sp.signing_certificates.iter().any(|t| t == signing_cert) {
        return Err(QidError::BadRequest {
            message: "SAML signing cert does not match any trusted certificate".to_string(),
        });
    }
    // The certificate was matched against SP metadata above. Load only its key.
    let algorithm = profile
        .signature_method
        .as_deref()
        .and_then(crate::xmldsig::SamlXmlSignatureAlgorithm::from_uri)
        .unwrap_or(crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256);
    let public_key_pem = crate::xmldsig::cert_pem_to_public_key_pem_from_pem(signing_cert)?;
    crate::verify_saml_xml_signature_for(
        crate::SamlSignatureInputs {
            document: &req.raw_xml,
            public_key_pem: public_key_pem.as_bytes(),
            profile: algorithm,
        },
        crate::SignedSamlElement::AuthnRequest,
    )?;
    Ok(profile)
}
