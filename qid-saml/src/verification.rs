//! Inbound XMLDSig profile. Signing remains in `xmldsig` and is independent.
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::{KeysManager, loader};
use qid_core::error::{QidError, QidResult};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use std::collections::BTreeSet;
use uppsala::{Document, NodeId};

use crate::xmldsig::{ENVELOPED_SIGNATURE_URI, EXC_C14N_URI, SamlXmlSignatureAlgorithm};

pub(crate) const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub(crate) const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Only the key selected by the caller's trust policy is loaded. KeyInfo is not
/// a trust source. Selecting/trusting a certificate remains the caller's job.
pub struct SamlSignatureInputs<'xml, 'key> {
    pub document: &'xml str,
    pub public_key_pem: &'key [u8],
    pub profile: SamlXmlSignatureAlgorithm,
}

/// The exact SAML element expected by the consuming protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedSamlElement {
    Assertion,
    Response,
    AuthnRequest,
    LogoutRequest,
    AttributeQuery,
    ArtifactResolve,
}

impl SignedSamlElement {
    fn name(self) -> (&'static str, &'static str) {
        match self {
            Self::Assertion => (ASSERTION_NS, "Assertion"),
            Self::Response => (PROTOCOL_NS, "Response"),
            Self::AuthnRequest => (PROTOCOL_NS, "AuthnRequest"),
            Self::LogoutRequest => (PROTOCOL_NS, "LogoutRequest"),
            Self::AttributeQuery => (PROTOCOL_NS, "AttributeQuery"),
            Self::ArtifactResolve => (PROTOCOL_NS, "ArtifactResolve"),
        }
    }
}

/// The original parsed tree and the *candidate-resolved* verified target.
/// Consume claims through this tree, never by reparsing or slicing the XML.
pub struct VerifiedSamlDocument<'a> {
    document: Document<'a>,
    target: NodeId,
    kind: SignedSamlElement,
}

/// Identity data extracted only from the candidate-resolved signed tree.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedSamlClaims {
    /// The containing Response ID (not signed when the target is Assertion).
    pub response_id: Option<String>,
    pub assertion_id: String,
    pub issuer: String,
    pub subject: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

impl<'a> VerifiedSamlDocument<'a> {
    pub(crate) fn document(&self) -> &Document<'a> {
        &self.document
    }

    pub(crate) fn target(&self) -> NodeId {
        self.target
    }

    pub fn signed_element(&self) -> SignedSamlElement {
        self.kind
    }

    /// Extract from the exact Assertion target, or the sole direct Assertion of
    /// a signed Response. Only a signed Response may supply the issuer; when it
    /// has no direct issuer, use the covered Assertion issuer instead.
    pub fn assertion_claims(&self) -> QidResult<VerifiedSamlClaims> {
        let doc = &self.document;
        let assertion = match self.kind {
            SignedSamlElement::Assertion => self.target,
            SignedSamlElement::Response => one(
                children_named(doc, self.target, ASSERTION_NS, "Assertion"),
                "direct Assertion",
            )?,
            _ => return Err(bad("verified SAML target does not contain identity claims")),
        };
        let response = if self.kind == SignedSamlElement::Response {
            Some(self.target)
        } else {
            doc.parent(assertion)
                .filter(|n| named(doc, *n, PROTOCOL_NS, "Response"))
        };
        let issuer_parent = if self.kind == SignedSamlElement::Response
            && !children_named(doc, self.target, ASSERTION_NS, "Issuer").is_empty()
        {
            self.target
        } else {
            assertion
        };
        let issuer = one(
            children_named(doc, issuer_parent, ASSERTION_NS, "Issuer"),
            "Issuer",
        )?;
        let subject = one(
            children_named(doc, assertion, ASSERTION_NS, "Subject"),
            "Subject",
        )?;
        let name = one(
            children_named(doc, subject, ASSERTION_NS, "NameID"),
            "Subject NameID",
        )?;
        let required_text = |node| {
            let text = doc.text_content_deep(node).trim().to_owned();
            if text.is_empty() {
                Err(bad("SAML identity claim is empty"))
            } else {
                Ok(text)
            }
        };
        let required_id = |node| {
            attribute(doc, node, "ID")
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| bad("SAML identity element ID is required"))
        };
        let mut attributes = Vec::new();
        for statement in children_named(doc, assertion, ASSERTION_NS, "AttributeStatement") {
            for attr in children_named(doc, statement, ASSERTION_NS, "Attribute") {
                if let Some(name) = attribute(doc, attr, "Name") {
                    let values = children_named(doc, attr, ASSERTION_NS, "AttributeValue")
                        .into_iter()
                        .map(|n| doc.text_content_deep(n).trim().to_owned())
                        .filter(|v| !v.is_empty())
                        .collect();
                    attributes.push((name.to_owned(), values));
                }
            }
        }
        Ok(VerifiedSamlClaims {
            response_id: response.map(required_id).transpose()?,
            assertion_id: required_id(assertion)?,
            issuer: required_text(issuer)?,
            subject: required_text(name)?,
            attributes,
        })
    }
}

fn bad(message: impl Into<String>) -> QidError {
    QidError::BadRequest {
        message: message.into(),
    }
}

pub(crate) fn named(doc: &Document<'_>, node: NodeId, ns: &str, name: &str) -> bool {
    doc.element(node)
        .is_some_and(|e| e.matches_name_ns(ns, name))
}

pub(crate) fn attribute<'d>(doc: &'d Document<'_>, node: NodeId, name: &str) -> Option<&'d str> {
    doc.element(node)?
        .attributes
        .iter()
        .find(|a| a.name.namespace_uri.is_none() && a.name.local_name == name)
        .map(|a| a.value.as_ref())
}

pub(crate) fn children_named(
    doc: &Document<'_>,
    node: NodeId,
    ns: &str,
    name: &str,
) -> Vec<NodeId> {
    doc.children(node)
        .into_iter()
        .filter(|n| named(doc, *n, ns, name))
        .collect()
}

fn one(nodes: Vec<NodeId>, name: &str) -> QidResult<NodeId> {
    if nodes.len() != 1 {
        return Err(bad(format!("SAML XMLDSig requires exactly one {name}")));
    }
    Ok(nodes[0])
}

fn child(doc: &Document<'_>, parent: NodeId, name: &str) -> QidResult<NodeId> {
    one(children_named(doc, parent, DSIG_NS, name), name)
}

fn algorithm(doc: &Document<'_>, parent: NodeId, name: &str) -> QidResult<String> {
    let n = child(doc, parent, name)?;
    attribute(doc, n, "Algorithm")
        .map(str::to_owned)
        .ok_or_else(|| bad(format!("SAML {name} Algorithm is required")))
}

// Exclusive C14N's only supported element parameter is InclusiveNamespaces.
// Enveloped-signature has no element parameters. Do not silently ignore XPath
// or other transform instructions just because the outer URI is allowed.
fn transform_parameters(doc: &Document<'_>, node: NodeId, exclusive: bool) -> QidResult<()> {
    let parameters: Vec<_> = doc
        .children(node)
        .into_iter()
        .filter(|n| doc.element(*n).is_some())
        .collect();
    if (!exclusive && !parameters.is_empty())
        || parameters.len() > 1
        || parameters.iter().any(|n| {
            !named(doc, *n, EXC_C14N_URI, "InclusiveNamespaces")
                || attribute(doc, *n, "PrefixList").is_none()
                || doc
                    .children(*n)
                    .into_iter()
                    .any(|c| doc.element(c).is_some())
        })
    {
        return Err(bad(
            "unsupported SAML canonicalization/transform parameters",
        ));
    }
    Ok(())
}

/// Preflight must complete before any cryptographic verification/key loading.
fn preflight(
    doc: &Document<'_>,
    profile: SamlXmlSignatureAlgorithm,
    expected: SignedSamlElement,
) -> QidResult<(NodeId, NodeId)> {
    let nodes = doc.descendants(doc.root());
    let mut ids = BTreeSet::new();
    for n in &nodes {
        if let Some(e) = doc.element(*n) {
            // Mirror all candidate aliases, including namespaced id attributes.
            for a in &e.attributes {
                if ["ID", "Id", "id", "AssertionID", "xml:id"].contains(&a.name.local_name.as_ref())
                    && !ids.insert(a.value.to_string())
                {
                    return Err(bad("duplicate SAML XML ID/alias"));
                }
            }
        }
    }
    let unique = |name| {
        one(
            nodes
                .iter()
                .copied()
                .filter(|n| named(doc, *n, DSIG_NS, name))
                .collect(),
            name,
        )
    };
    let signature = unique("Signature")?;
    let signed_info = unique("SignedInfo")?;
    let reference = unique("Reference")?;
    if doc.parent(signed_info) != Some(signature) || doc.parent(reference) != Some(signed_info) {
        return Err(bad("SAML XMLDSig SignedInfo/Reference is misplaced"));
    }
    if algorithm(doc, signed_info, "CanonicalizationMethod")? != EXC_C14N_URI {
        return Err(bad("unsupported SAML SignedInfo canonicalization method"));
    }
    transform_parameters(
        doc,
        child(doc, signed_info, "CanonicalizationMethod")?,
        true,
    )?;
    let method = algorithm(doc, signed_info, "SignatureMethod")?;
    if SamlXmlSignatureAlgorithm::from_uri(&method) != Some(profile) {
        return Err(bad(
            "unsupported SAML signature method or enforced profile mismatch",
        ));
    }
    if algorithm(doc, reference, "DigestMethod")? != SHA256_URI {
        return Err(bad("unsupported SAML digest method"));
    }
    let transforms = child(doc, reference, "Transforms")?;
    let transforms: Vec<_> = doc
        .children(transforms)
        .into_iter()
        .filter(|n| doc.element(*n).is_some())
        .collect();
    if transforms.len() != 2
        || transforms
            .iter()
            .any(|n| !named(doc, *n, DSIG_NS, "Transform"))
        || attribute(doc, transforms[0], "Algorithm") != Some(ENVELOPED_SIGNATURE_URI)
        || attribute(doc, transforms[1], "Algorithm") != Some(EXC_C14N_URI)
    {
        return Err(bad(
            "unsupported SAML transforms: require enveloped-signature then exclusive C14N",
        ));
    }
    transform_parameters(doc, transforms[0], false)?;
    transform_parameters(doc, transforms[1], true)?;
    let uri =
        attribute(doc, reference, "URI").ok_or_else(|| bad("SAML Reference URI is required"))?;
    let id = uri
        .strip_prefix('#')
        .filter(|id| {
            !id.is_empty()
                && !id.contains(['#', '(', ')', '/', '%'])
                && !id.chars().any(char::is_whitespace)
        })
        .ok_or_else(|| bad("SAML Reference must be one local #ID"))?;
    let target = one(
        nodes
            .iter()
            .copied()
            .filter(|n| {
                doc.element(*n).is_some_and(|e| {
                    e.attributes.iter().any(|a| {
                        ["ID", "Id", "id", "AssertionID", "xml:id"]
                            .contains(&a.name.local_name.as_ref())
                            && a.value == id
                    })
                })
            })
            .collect(),
        "Reference target",
    )?;
    // SAML 2.0 uses unqualified ID, not any of the more permissive XMLDSig aliases.
    if attribute(doc, target, "ID") != Some(id) {
        return Err(bad("SAML Reference target requires an unqualified ID"));
    }
    let kind = [
        SignedSamlElement::Assertion,
        SignedSamlElement::Response,
        SignedSamlElement::AuthnRequest,
        SignedSamlElement::LogoutRequest,
        SignedSamlElement::AttributeQuery,
        SignedSamlElement::ArtifactResolve,
    ]
    .into_iter()
    .find(|k| {
        let (ns, name) = k.name();
        named(doc, target, ns, name)
    })
    .ok_or_else(|| bad("unsupported SAML Reference target element"))?;
    if expected != kind {
        return Err(bad("SAML Reference target does not match expected element"));
    }
    let root = doc
        .document_element()
        .ok_or_else(|| bad("SAML document element is required"))?;
    let assertion_nodes: Vec<_> = nodes
        .iter()
        .copied()
        .filter(|n| named(doc, *n, ASSERTION_NS, "Assertion"))
        .collect();
    let form_ok = match kind {
        SignedSamlElement::Assertion => {
            assertion_nodes == [target]
                && (target == root
                    || (named(doc, root, PROTOCOL_NS, "Response")
                        && doc.parent(target) == Some(root)))
        }
        SignedSamlElement::Response => {
            target == root
                && assertion_nodes.len() <= 1
                && assertion_nodes.iter().all(|n| doc.parent(*n) == Some(root))
        }
        SignedSamlElement::AttributeQuery => {
            const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
            let elements = |node| {
                doc.children(node)
                    .into_iter()
                    .filter(|n| doc.element(*n).is_some())
                    .collect::<Vec<_>>()
            };
            let bodies = children_named(doc, root, SOAP_NS, "Body");
            named(doc, root, SOAP_NS, "Envelope")
                && bodies.len() == 1
                && elements(root) == bodies
                && elements(bodies[0]) == [target]
                && nodes
                    .iter()
                    .filter(|n| named(doc, **n, SOAP_NS, "Body"))
                    .count()
                    == 1
                && nodes
                    .iter()
                    .filter(|n| named(doc, **n, PROTOCOL_NS, kind.name().1))
                    .count()
                    == 1
                && assertion_nodes.is_empty()
                && doc.parent(signature) == Some(target)
        }
        SignedSamlElement::ArtifactResolve => {
            const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
            let elements = |node| {
                doc.children(node)
                    .into_iter()
                    .filter(|n| doc.element(*n).is_some())
                    .collect::<Vec<_>>()
            };
            let bodies = children_named(doc, root, SOAP_NS, "Body");
            let headers = children_named(doc, root, SOAP_NS, "Header");
            // An optional single SOAP 1.1 Header may precede exactly one Body.
            // Header semantics (mustUnderstand) are enforced by the caller;
            // preflight only fixes the supported envelope shape here.
            let envelope_ok = named(doc, root, SOAP_NS, "Envelope")
                && bodies.len() == 1
                && headers.len() <= 1
                && nodes
                    .iter()
                    .filter(|n| named(doc, **n, SOAP_NS, "Body"))
                    .count()
                    == 1
                && nodes
                    .iter()
                    .filter(|n| named(doc, **n, SOAP_NS, "Header"))
                    .count()
                    == headers.len();
            let order_ok = if headers.is_empty() {
                elements(root) == bodies
            } else {
                elements(root) == vec![headers[0], bodies[0]]
            };
            envelope_ok
                && order_ok
                && elements(bodies[0]) == [target]
                && nodes
                    .iter()
                    .filter(|n| named(doc, **n, PROTOCOL_NS, kind.name().1))
                    .count()
                    == 1
                && assertion_nodes.is_empty()
                && doc.parent(signature) == Some(target)
        }
        _ => target == root && assertion_nodes.is_empty(),
    };
    if !form_ok {
        return Err(bad(
            "unsupported SAML target form or unsigned decoy/wrapping",
        ));
    }
    if !doc.descendants(target).contains(&signature) {
        return Err(bad(
            "SAML Signature must be a descendant of its Reference target",
        ));
    }
    Ok((signature, target))
}

/// Verify the inbound profile and retain the exact resolved node for consumption.
pub fn verify_saml_xml_signature_for<'a>(
    inputs: SamlSignatureInputs<'a, '_>,
    expected: SignedSamlElement,
) -> QidResult<VerifiedSamlDocument<'a>> {
    crate::xml::reject_insecure_saml_xml(inputs.document)?;
    let document =
        uppsala::parse(inputs.document).map_err(|e| bad(format!("SAML XML parse error: {e}")))?;
    let (signature, target) = preflight(&document, inputs.profile, expected)?;
    if inputs.profile == SamlXmlSignatureAlgorithm::RsaSha256 {
        let pem = std::str::from_utf8(inputs.public_key_pem)
            .map_err(|e| bad(format!("SAML selected RSA public key: {e}")))?;
        let public_key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| bad(format!("SAML selected RSA public key: {e}")))?;
        if public_key.n().bits() < 2048 {
            return Err(bad("SAML RSA public key must be at least 2048 bits"));
        }
    }
    let key = loader::load_pem_auto(inputs.public_key_pem, None)
        .map_err(|e| bad(format!("SAML selected public key: {e}")))?;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    let key_matches = match inputs.profile {
        SamlXmlSignatureAlgorithm::RsaSha256 => keys.find_rsa().is_some(),
        SamlXmlSignatureAlgorithm::EcdsaSha256 => keys.find_ec_p256().is_some(),
    };
    if !key_matches {
        return Err(bad("SAML selected key does not match RSA or P-256 profile"));
    }
    // No URL maps, base directory, external resolver, or document-supplied keys.
    let ctx = DsigContext::new(keys)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true);
    let result = bergshamra_dsig::verify::verify_document(&ctx, &document)
        .map_err(|e| bad(format!("SAML XMLDSig verification failed: {e}")))?;
    match result {
        VerifyResult::Valid {
            signature_node,
            references,
            ..
        } if signature_node == signature
            && references.len() == 1
            && references[0].digest_verified
            && references[0].resolved_node == Some(target) =>
        {
            let target = references[0]
                .resolved_node
                .ok_or_else(|| bad("verified SAML Reference target is missing"))?;
            Ok(VerifiedSamlDocument {
                document,
                target,
                kind: expected,
            })
        }
        _ => Err(QidError::Unauthorized {
            message: "SAML XMLDSig signature/digest or verified target mismatch".into(),
        }),
    }
}

#[cfg(test)]
mod tests;
