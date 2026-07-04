use base64::Engine;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

use crate::xmldsig::{
    SamlXmlSignatureAlgorithm, SigningCanonicalization, sign_saml_element_with_key_c14n,
};
use crate::{
    SamlIssuedResponse, SamlServiceProviderMetadata, insert_after_first_child,
    inspect_xml_signature_profile, reject_insecure_saml_xml,
};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlDetachedSignature {
    pub target: SamlSignatureTarget,
    pub xml: String,
}

pub fn plan_saml_signatures(
    issued: &SamlIssuedResponse,
    sp: &SamlServiceProviderMetadata,
    policy: &SamlSigningPolicy,
) -> QidResult<SamlSignaturePlan> {
    let mut targets = Vec::new();
    if policy.sign_response {
        targets.push(SamlSignatureTarget::Response);
    }
    if policy.sign_assertion || sp.want_assertions_signed {
        targets.push(SamlSignatureTarget::Assertion);
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

pub fn apply_saml_signatures(
    issued: &SamlIssuedResponse,
    signatures: &[SamlDetachedSignature],
) -> QidResult<SamlIssuedResponse> {
    let mut xml = issued.xml.clone();
    for signature in signatures {
        reject_insecure_saml_xml(&signature.xml)?;
        xml =
            match signature.target {
                SamlSignatureTarget::Response => {
                    insert_after_first_child(&xml, "Response", "Issuer", &signature.xml)
                        .ok_or_else(|| QidError::BadRequest {
                            message: "could not insert SAML Response signature".to_string(),
                        })?
                }
                SamlSignatureTarget::Assertion => {
                    insert_after_first_child(&xml, "Assertion", "Issuer", &signature.xml)
                        .ok_or_else(|| QidError::BadRequest {
                            message: "could not insert SAML Assertion signature".to_string(),
                        })?
                }
            };
    }
    reject_insecure_saml_xml(&xml)?;
    Ok(SamlIssuedResponse {
        response_id: issued.response_id.clone(),
        assertion_id: issued.assertion_id.clone(),
        xml,
    })
}

/// Build a `<ds:Signature>` element for a SAML Response or Assertion
/// using W3C XMLDSig. The signature is produced with a PKCS#8 PEM
/// private key so third-party SAML SPs can verify it with the
/// corresponding public key or certificate.
pub fn build_saml_element_signature_with_key(
    xml: &str,
    element_name: &str,
    element_id: &str,
    private_key_pem: &[u8],
    public_key_pem: Option<&[u8]>,
    algorithm: SamlXmlSignatureAlgorithm,
) -> QidResult<String> {
    let _ = element_name;
    let mut signature = sign_saml_element_with_key_c14n(
        xml,
        element_id,
        algorithm,
        private_key_pem,
        SigningCanonicalization::Exclusive,
    )?;
    if let Some(public_key_pem) = public_key_pem {
        let modulus = extract_rsa_modulus(public_key_pem).unwrap_or_default();
        let exponent = extract_rsa_exponent(public_key_pem).unwrap_or_default();
        if !modulus.is_empty() && !exponent.is_empty() {
            signature = inject_keyinfo(&signature, &modulus, &exponent);
        }
    }
    Ok(signature)
}

fn inject_keyinfo(signature_xml: &str, modulus_b64: &str, exponent_b64: &str) -> String {
    let keyinfo = format!(
        "<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{modulus_b64}</ds:Modulus><ds:Exponent>{exponent_b64}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>"
    );
    let insertion = format!("{keyinfo}<ds:SignatureValue");
    if let Some(pos) = signature_xml.find("<ds:SignatureValue") {
        let mut out = String::with_capacity(signature_xml.len() + keyinfo.len());
        out.push_str(&signature_xml[..pos]);
        out.push_str(&insertion);
        out.push_str(&signature_xml[pos..]);
        out
    } else {
        signature_xml.to_string()
    }
}

fn extract_rsa_modulus(public_key_pem: &[u8]) -> QidResult<String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPublicKey::from_public_key_pem(std::str::from_utf8(public_key_pem).map_err(
        |e| QidError::Internal {
            message: format!("RSA public key PEM is not valid UTF-8: {e}"),
        },
    )?)
    .map_err(|e| QidError::Internal {
        message: format!("failed to parse RSA public key: {e}"),
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.n().to_bytes_be()))
}

fn extract_rsa_exponent(public_key_pem: &[u8]) -> QidResult<String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPublicKey::from_public_key_pem(std::str::from_utf8(public_key_pem).map_err(
        |e| QidError::Internal {
            message: format!("RSA public key PEM is not valid UTF-8: {e}"),
        },
    )?)
    .map_err(|e| QidError::Internal {
        message: format!("failed to parse RSA public key: {e}"),
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.e().to_bytes_be()))
}

/// Uses a PKCS#8 PEM private key to produce W3C XMLDSig signatures
/// so the resulting SAML documents can be verified by third-party
/// SAML SPs.
pub fn sign_saml_response_with_key(
    issued: &SamlIssuedResponse,
    sp: &SamlServiceProviderMetadata,
    policy: &SamlSigningPolicy,
    private_key_pem: &[u8],
    public_key_pem: Option<&[u8]>,
    algorithm: SamlXmlSignatureAlgorithm,
) -> QidResult<SamlIssuedResponse> {
    let plan = plan_saml_signatures(issued, sp, policy)?;
    let mut signatures = Vec::new();
    for target in &plan.targets {
        let signature_xml = match target {
            SamlSignatureTarget::Response => build_saml_element_signature_with_key(
                &issued.xml,
                "Response",
                &issued.response_id,
                private_key_pem,
                public_key_pem,
                algorithm,
            )?,
            SamlSignatureTarget::Assertion => {
                let assertion_id = &issued.assertion_id;
                let assertion_marker = format!("Assertion ID=\"{assertion_id}\"");
                let assertion_start =
                    issued
                        .xml
                        .find(&assertion_marker)
                        .ok_or_else(|| QidError::BadRequest {
                            message: "Assertion element not found in response".to_string(),
                        })?;
                let after_id = assertion_start + assertion_marker.len();
                let open_end =
                    issued.xml[after_id..]
                        .find('>')
                        .ok_or_else(|| QidError::BadRequest {
                            message: "Assertion start tag malformed".to_string(),
                        })?
                        + after_id
                        + 1;
                let close_start = crate::find_close_tag(&issued.xml[open_end..], "Assertion")
                    .ok_or_else(|| QidError::BadRequest {
                        message: "Assertion close tag not found".to_string(),
                    })?;
                let close_end = open_end
                    + close_start
                    + crate::close_tag_len(&issued.xml[open_end + close_start..]).ok_or_else(
                        || QidError::BadRequest {
                            message: "Assertion close tag malformed".to_string(),
                        },
                    )?;
                let assertion_xml = &issued.xml[assertion_start..close_end];
                build_saml_element_signature_with_key(
                    assertion_xml,
                    "Assertion",
                    &issued.assertion_id,
                    private_key_pem,
                    public_key_pem,
                    algorithm,
                )?
            }
        };
        signatures.push(SamlDetachedSignature {
            target: *target,
            xml: signature_xml,
        });
    }
    apply_saml_signatures(issued, &signatures)
}

pub fn validate_authn_request_signature_profile(
    req: &crate::SamlAuthnRequest,
    sp: &SamlServiceProviderMetadata,
) -> QidResult<crate::SamlXmlSignatureProfile> {
    // Production path: perform a real W3C XMLDSig verification. The
    // algorithm is chosen by looking at the SP's first configured
    // signing certificate. When the legacy profile is desired for
    // backwards compatibility, use
    // [`validate_authn_request_signature_profile_legacy`].
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
    // Extract the public key from the X.509 certificate embedded in
    // the SAML signature and run the production-grade W3C XMLDSig
    // verifier. This is the symmetric counterpart of the IdP-side
    // signature generation in `sign_saml_response_with_key`.
    let algorithm = profile
        .signature_method
        .as_deref()
        .and_then(crate::xmldsig::SamlXmlSignatureAlgorithm::from_uri)
        .unwrap_or(crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256);
    let public_key_pem = crate::xmldsig::cert_pem_to_public_key_pem_from_pem(signing_cert)?;
    crate::xmldsig::verify_saml_xml_signature(crate::xmldsig::SamlSignatureInputs {
        document: &req.raw_xml,
        public_key_pem: public_key_pem.as_bytes(),
        profile: algorithm,
    })?;
    Ok(profile)
}

/// Legacy profile-only validator that does not perform cryptographic
/// verification. Kept for callers that have not yet wired the real
/// XMLDSig verification path. Production deployments must migrate to
/// [`validate_authn_request_signature_profile`].
pub fn validate_authn_request_signature_profile_legacy(
    req: &crate::SamlAuthnRequest,
    sp: &SamlServiceProviderMetadata,
) -> QidResult<crate::SamlXmlSignatureProfile> {
    let profile = inspect_xml_signature_profile(&req.raw_xml, "AuthnRequest")?;
    if sp.signing_certificates.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML SP metadata must include a signing key; none are configured".to_string(),
        });
    }
    if profile.reference_uri.as_deref() != Some(&format!("#{}", req.id)) {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest signature must reference the AuthnRequest identifier"
                .to_string(),
        });
    }
    let Some(signing_certificate) = &profile.signing_certificate else {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest signature must include an X.509 certificate".to_string(),
        });
    };
    if !sp
        .signing_certificates
        .iter()
        .any(|t| t == signing_certificate)
    {
        return Err(QidError::BadRequest {
            message: "SAML signing cert does not match any trusted certificate".to_string(),
        });
    }
    Ok(profile)
}
