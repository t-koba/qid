use crate::SamlXmlSignatureProfile;
use qid_core::error::{QidError, QidResult};
use roxmltree::Document;

/// A SAML XML document parsed into a DOM tree.
///
/// The document is parsed once with `roxmltree` and all subsequent
/// lookups (signature metadata, attributes, text values) operate on
/// the **same** in-memory tree, eliminating parser-differential
/// between signature verification and claim extraction.
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

    /// Return the text content of the first element matching `tag`.
    pub(crate) fn element_text(&self, tag: &str) -> Option<String> {
        self.doc
            .descendants()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(|s| s.trim().to_string())
    }

    /// Return an attribute value from the first element matching `tag`.
    pub(crate) fn element_attr(&self, tag: &str, attr: &str) -> Option<String> {
        self.doc
            .descendants()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.attribute(attr))
            .map(|s| s.to_string())
    }

    /// Return all attribute values for a given attribute name across
    /// all matching elements.
    pub(crate) fn element_attrs(&self, tag: &str, attr: &str) -> Vec<String> {
        self.doc
            .descendants()
            .filter(|n| n.has_tag_name(tag))
            .filter_map(|n| n.attribute(attr))
            .map(|s| s.to_string())
            .collect()
    }

    /// Inspect the XML signature profile for a signed element.
    ///
    /// This is the DOM equivalent of `xml::inspect_xml_signature_profile`.
    /// It parses the XML once and extracts all signature metadata from the
    /// same tree, eliminating parser-differential attacks.
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
        r##"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="req-123">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#req-123">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</samlp:AuthnRequest>"##
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
        assert!(
            matches!(
                doc.inspect_signature_profile("AuthnRequest"),
                Err(QidError::BadRequest { .. })
            ),
            "multiple Signature elements must be rejected"
        );
    }

    #[test]
    fn dom_rejects_forbidden_sibling() {
        let xml = valid_saml_xml().replace(
            "</ds:Signature>\n</samlp:AuthnRequest>",
            "</ds:Signature>\n  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>\n</samlp:AuthnRequest>",
        );
        let doc = SamlDocument::parse(&xml).unwrap();
        assert!(
            matches!(
                doc.inspect_signature_profile("AuthnRequest"),
                Err(QidError::BadRequest { .. })
            ),
            "forbidden sibling Assertion must be rejected"
        );
    }

    #[test]
    fn dom_rejects_reference_uri_mismatch() {
        let xml = valid_saml_xml().replace("#req-123", "#other");
        let doc = SamlDocument::parse(&xml).unwrap();
        assert!(
            matches!(
                doc.inspect_signature_profile("AuthnRequest"),
                Err(QidError::BadRequest { .. })
            ),
            "Reference URI mismatch must be rejected"
        );
    }

    #[test]
    fn dom_rejects_comment_before_signature() {
        let xml = valid_saml_xml().replace("<ds:Signature", "<!-- payload --><ds:Signature");

        assert!(
            matches!(
                crate::xml::inspect_xml_signature_profile(&xml, "AuthnRequest"),
                Err(QidError::BadRequest { .. })
            ),
            "SAML comments must be rejected before DOM inspection"
        );
    }

    #[test]
    fn dom_text_values_match_string_scanner() {
        let xml = valid_saml_xml();
        let doc = SamlDocument::parse(xml).unwrap();
        let dom_val = doc.element_text("X509Certificate");
        let scan_val = crate::xml::text_values(xml, "X509Certificate")
            .into_iter()
            .next();
        assert_eq!(dom_val, scan_val);
    }
}
