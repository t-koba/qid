use crate::SamlXmlSignatureProfile;
use qid_core::error::{QidError, QidResult};
use roxmltree::Document;

/// Metadata/trust-profile inspection only. Cryptographic verification and
/// bearer claim consumption use the same Uppsala tree in `verification`.
pub(crate) struct SamlDocument<'a> {
    doc: Document<'a>,
}

impl<'a> SamlDocument<'a> {
    /// Parse raw SAML XML into a DOM tree.
    pub(crate) fn parse(xml: &'a str) -> QidResult<Self> {
        let doc = Document::parse(xml).map_err(|e| QidError::BadRequest {
            message: format!("SAML XML parse error: {e}"),
        })?;
        Ok(Self { doc })
    }

    /// Inspect signature metadata for a signed element using this DOM.
    ///
    /// This inspection only selects profile/trust metadata. It does not verify
    /// a signature; the inbound verifier independently enforces its profile.
    pub(crate) fn inspect_signature_profile(
        &self,
        signed_element: &str,
    ) -> QidResult<SamlXmlSignatureProfile> {
        let signed = self
            .doc
            .descendants()
            .find(|n| n.has_tag_name(signed_element))
            .ok_or_else(|| QidError::BadRequest {
                message: format!("SAML signed element {signed_element} is required"),
            })?;

        let element_id = signed.attribute("ID").ok_or_else(|| QidError::BadRequest {
            message: format!("SAML signed element {signed_element} must have an ID attribute"),
        })?;

        let signature_count = signed
            .children()
            .filter(|n| n.has_tag_name("Signature"))
            .count();
        if signature_count != 1 {
            return Err(QidError::BadRequest {
                message: "SAML signed element must contain exactly one Signature".to_string(),
            });
        }

        // XSW hardening: no forbidden siblings inside the signed parent.
        for forbidden in ["Assertion", "Extensions", "Statement"] {
            if signed.children().any(|n| n.has_tag_name(forbidden)) {
                return Err(QidError::BadRequest {
                    message: format!(
                        "SAML signed {signed_element} contains forbidden sibling element {forbidden}"
                    ),
                });
            }
        }

        let reference_uri = signed
            .descendants()
            .find(|n| n.has_tag_name("Reference"))
            .and_then(|n| n.attribute("URI"))
            .map(|s| s.to_string())
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML Signature Reference URI is required".to_string(),
            })?;

        if reference_uri != format!("#{element_id}") {
            return Err(QidError::BadRequest {
                message: format!("SAML Signature Reference URI must match the {signed_element} ID"),
            });
        }

        let signature_method = signed
            .descendants()
            .find(|n| n.has_tag_name("SignatureMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .map(|s| s.to_string())
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML SignatureMethod Algorithm is required".to_string(),
            })?;

        let digest_method = signed
            .descendants()
            .find(|n| n.has_tag_name("DigestMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .map(|s| s.to_string())
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML DigestMethod Algorithm is required".to_string(),
            })?;

        crate::xml::reject_unsupported_signature_algorithm(&signature_method)?;
        crate::xml::reject_unsupported_signature_algorithm(&digest_method)?;

        let signing_certificate = signed
            .descendants()
            .find(|n| n.has_tag_name("X509Certificate"))
            .and_then(|n| n.text())
            .map(|s| s.split_whitespace().collect::<String>());

        Ok(SamlXmlSignatureProfile {
            reference_uri: Some(reference_uri),
            signature_method: Some(signature_method),
            digest_method: Some(digest_method),
            signing_certificate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_saml_xml() -> &'static str {
        include_str!("../tests/fixtures/saml-document-authn-request-test.xml")
    }

    #[test]
    fn dom_parse_valid_xml() {
        let doc = SamlDocument::parse(valid_saml_xml()).unwrap();
        let profile = doc.inspect_signature_profile("AuthnRequest").unwrap();
        assert_eq!(profile.reference_uri.as_deref(), Some("#req-123"));
        assert!(profile.signature_method.is_some());
        assert!(profile.digest_method.is_some());
    }

    #[test]
    fn dom_rejects_multiple_signatures() {
        let xml = valid_saml_xml().replace(
            "</ds:Signature>",
            "</ds:Signature>\n  <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm=\"rsa-sha256\"/><ds:Reference URI=\"#req-123\"><ds:DigestMethod Algorithm=\"sha256\"/></ds:Reference></ds:SignedInfo></ds:Signature>",
        );
        let doc = SamlDocument::parse(&xml).unwrap();
        crate::tests::assert_bad_request_with_context(
            doc.inspect_signature_profile("AuthnRequest"),
            "multiple Signature elements must be rejected",
        );
    }

    #[test]
    fn dom_rejects_forbidden_sibling() {
        let xml = valid_saml_xml().replace(
            "</ds:Signature>",
            "</ds:Signature><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>",
        );
        let doc = SamlDocument::parse(&xml).unwrap();
        crate::tests::assert_bad_request_with_context(
            doc.inspect_signature_profile("AuthnRequest"),
            "forbidden sibling Assertion must be rejected",
        );
    }

    #[test]
    fn dom_rejects_reference_uri_mismatch() {
        let xml = valid_saml_xml().replace("#req-123", "#other");
        let doc = SamlDocument::parse(&xml).unwrap();
        crate::tests::assert_bad_request_with_context(
            doc.inspect_signature_profile("AuthnRequest"),
            "Reference URI mismatch must be rejected",
        );
    }

    #[test]
    fn dom_rejects_comment_before_signature() {
        let xml = valid_saml_xml().replace("<ds:Signature", "<!-- payload --><ds:Signature");

        crate::tests::assert_bad_request_with_context(
            crate::xml::inspect_xml_signature_profile(&xml, "AuthnRequest"),
            "SAML comments must be rejected before DOM inspection",
        );
    }
}
