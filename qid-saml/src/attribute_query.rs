//! Strict SOAP AttributeQuery authentication and response serialization.
use crate::verification::{ASSERTION_NS, DSIG_NS, attribute, children_named, named};
use crate::{
    SamlSignatureInputs, SamlXmlSignatureAlgorithm, SignedSamlElement,
    verify_saml_xml_signature_for,
};
use qid_core::{
    config::SamlServiceProviderConfig,
    error::{QidError, QidResult},
};

pub(crate) struct VerifiedAttributeQuery {
    pub id: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
}

/// Try only keys registered in this realm. Neither unsigned Issuer nor KeyInfo
/// participates in trust selection. Claims are consumed from the verified tree.
pub(crate) fn authenticate_attribute_query<'a>(
    xml: &str,
    providers: &'a [SamlServiceProviderConfig],
) -> QidResult<(VerifiedAttributeQuery, &'a SamlServiceProviderConfig)> {
    for sp in providers {
        for certificate in &sp.signing_certificates {
            let Ok(key) = crate::cert_pem_to_public_key_pem_from_pem(certificate) else {
                continue;
            };
            for profile in [
                SamlXmlSignatureAlgorithm::RsaSha256,
                SamlXmlSignatureAlgorithm::EcdsaSha256,
            ] {
                let Ok(verified) = verify_saml_xml_signature_for(
                    SamlSignatureInputs {
                        document: xml,
                        public_key_pem: key.as_bytes(),
                        profile,
                    },
                    SignedSamlElement::AttributeQuery,
                ) else {
                    continue;
                };
                let doc = verified.document();
                let target = verified.target();
                let one_child = |parent, ns, name| {
                    let nodes = children_named(doc, parent, ns, name);
                    if nodes.len() == 1 {
                        Ok(nodes[0])
                    } else {
                        Err(denied())
                    }
                };
                let leaf_text = |node| {
                    let text = doc.text_content_deep(node).trim().to_owned();
                    if text.is_empty()
                        || doc.children(node).iter().any(|n| doc.element(*n).is_some())
                    {
                        Err(denied())
                    } else {
                        Ok(text)
                    }
                };
                // This subset has no Extensions, selectors, encrypted subjects,
                // or alternative Subject identifiers. Reject rather than ignore.
                if doc.children(target).iter().any(|n| {
                    doc.element(*n).is_some()
                        && !named(doc, *n, ASSERTION_NS, "Issuer")
                        && !named(doc, *n, ASSERTION_NS, "Subject")
                        && !named(doc, *n, DSIG_NS, "Signature")
                }) {
                    return Err(denied());
                }
                let issuer = leaf_text(one_child(target, ASSERTION_NS, "Issuer")?)?;
                if issuer != sp.entity_id {
                    continue;
                }
                let subject = one_child(target, ASSERTION_NS, "Subject")?;
                let name = one_child(subject, ASSERTION_NS, "NameID")?;
                if doc
                    .children(subject)
                    .iter()
                    .filter(|n| doc.element(**n).is_some())
                    .count()
                    != 1
                {
                    return Err(denied());
                }
                return Ok((
                    VerifiedAttributeQuery {
                        id: attribute(doc, target, "ID").ok_or_else(denied)?.to_owned(),
                        name_id: leaf_text(name)?,
                        name_id_format: attribute(doc, name, "Format").map(str::to_owned),
                    },
                    sp,
                ));
            }
        }
    }
    Err(denied())
}

fn denied() -> QidError {
    QidError::Unauthorized {
        message: "SAML AttributeQuery request denied".into(),
    }
}

/// Build a SOAP `<Response>` containing an `<AttributeStatement>` for the
/// attribute query result.
pub(crate) fn build_attribute_query_response(
    in_response_to: &str,
    issuer: &str,
    attributes_xml: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:AttributeStatement>
        {}
      </saml:AttributeStatement>
    </samlp:Response>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        super::artifact::iso_now_utc(),
        xml_escape(in_response_to),
        xml_escape(issuer),
        attributes_xml,
    )
}

/// Build an error SOAP response for attribute query failures.
pub(crate) fn attribute_query_error_soap(
    in_response_to: &str,
    issuer: &str,
    status_code: &str,
    status_message: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="{}"/>
        <samlp:StatusMessage>{}</samlp:StatusMessage>
      </samlp:Status>
    </samlp:Response>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        super::artifact::iso_now_utc(),
        xml_escape(in_response_to),
        xml_escape(issuer),
        xml_escape(status_code),
        xml_escape(status_message),
    )
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
