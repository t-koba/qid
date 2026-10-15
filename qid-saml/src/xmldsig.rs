//! Fixed outbound XMLDSig profile backed by bergshamra 0.9.2.
use crate::verification::{ASSERTION_NS, DSIG_NS, children_named, named};
use base64::Engine;
use bergshamra_dsig::DsigContext;
use bergshamra_keys::{KeysManager, loader};
use qid_core::error::{QidError, QidResult};
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use std::collections::BTreeSet;

/// Exact XMLDSig algorithm URIs accepted by the verifier. Matching is by
/// equality: invented URIs that merely contain these strings are rejected.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const EXC_C14N_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Signature algorithms accepted by this module's limited profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlXmlSignatureAlgorithm {
    /// RSA with SHA-256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`).
    RsaSha256,
    /// ECDSA with SHA-256 (`http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`).
    EcdsaSha256,
}

impl SamlXmlSignatureAlgorithm {
    /// Parse the XMLDSig `SignatureMethod` URI accepted by qid.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(Self::EcdsaSha256),
            _ => None,
        }
    }
}

/// Extract an X.509 certificate's SubjectPublicKeyInfo as PEM.
pub fn cert_pem_to_public_key_pem(cert_der: &[u8]) -> QidResult<String> {
    use x509_parser::prelude::*;
    let (_, certificate): (_, x509_parser::certificate::X509Certificate<'_>) =
        x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
            QidError::BadRequest {
                message: format!("failed to parse X.509 certificate: {e}"),
            }
        })?;
    let spki_der = certificate.public_key().raw;
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki_der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        wrap_base64(&b64)
    ))
}

fn wrap_base64(value: &str) -> String {
    value
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Public-key extraction from a PEM-encoded X.509 certificate.
pub fn cert_pem_to_public_key_pem_from_pem(cert_pem: &str) -> QidResult<String> {
    let body: String = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("X.509 certificate PEM base64 decode failed: {e}"),
        })?;
    cert_pem_to_public_key_pem(&der)
}

/// Expanded name of the caller-selected outbound signature target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSigningElement {
    Assertion,
    Response,
    EntityDescriptor,
}

impl SamlSigningElement {
    fn name(self) -> (&'static str, &'static str) {
        match self {
            Self::Assertion => (ASSERTION_NS, "Assertion"),
            Self::Response => ("urn:oasis:names:tc:SAML:2.0:protocol", "Response"),
            Self::EntityDescriptor => ("urn:oasis:names:tc:SAML:2.0:metadata", "EntityDescriptor"),
        }
    }
}

fn bad(message: impl Into<String>) -> QidError {
    QidError::BadRequest {
        message: message.into(),
    }
}

/// Sign a unique unqualified `ID` on the specified expanded element name.
/// Returns the complete document, preserving inherited namespace context.
/// The fixed profile is enveloped signature, exclusive C14N and SHA-256.
/// Only the supplied private key is loaded; embedded KeyInfo is never trusted.
/// Existing descendant signatures may be covered by a new outer signature;
/// re-signing a target or selecting a template behind another signature fails.
pub fn sign_saml_document_with_key(
    xml: &str,
    target_kind: SamlSigningElement,
    target_id: &str,
    algorithm: SamlXmlSignatureAlgorithm,
    private_key_pem: &[u8],
) -> QidResult<String> {
    // Avoid fragment syntax and URI escaping ambiguities; generated SAML IDs
    // use this NCName subset. This is an outbound profile, not a URI resolver.
    if target_id.is_empty()
        || !target_id.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphabetic()
                || b == b'_'
                || (i > 0 && (b.is_ascii_digit() || b == b'-' || b == b'.'))
        })
    {
        return Err(bad("SAML signing requires a nonempty simple XML ID"));
    }
    if xml.to_ascii_lowercase().contains("<!doctype") {
        return Err(bad("SAML XML DOCTYPE is not allowed"));
    }
    let mut doc =
        uppsala::parse(xml).map_err(|e| bad(format!("invalid SAML signing document: {e}")))?;
    let nodes = doc.descendants(doc.root());
    let mut ids = BTreeSet::new();
    let mut target = None;
    let (ns, name) = target_kind.name();
    for node in &nodes {
        if let Some(element) = doc.element(*node) {
            // Match the backend's ID aliases, rejecting ambiguity before signing.
            for attr in &element.attributes {
                if matches!(
                    attr.name.local_name.as_ref(),
                    "ID" | "Id" | "id" | "AssertionID"
                ) {
                    if !ids.insert(attr.value.as_ref()) {
                        return Err(bad("duplicate SAML signing ID"));
                    }
                    if attr.value == target_id {
                        if attr.name.namespace_uri.is_some()
                            || attr.name.local_name != "ID"
                            || !named(&doc, *node, ns, name)
                        {
                            return Err(bad("SAML signing target name/ID mismatch"));
                        }
                        target = Some(*node);
                    }
                }
            }
        }
    }
    let target = target.ok_or_else(|| bad("SAML signing target not found"))?;
    let descendants = doc.descendants(target);
    if nodes.iter().any(|node| {
        named(&doc, *node, DSIG_NS, "Signature")
            && (doc.parent(*node) == Some(target) || !descendants.contains(node))
    }) {
        return Err(bad(
            "SAML signing requires an unsigned target with no outside signatures",
        ));
    }
    let issuer = children_named(&doc, target, ASSERTION_NS, "Issuer");
    if issuer.len() > 1 || (target_kind == SamlSigningElement::Assertion && issuer.len() != 1) {
        return Err(bad("SAML signing requires an unambiguous Issuer"));
    }
    let method = match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        SamlXmlSignatureAlgorithm::EcdsaSha256 => {
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        }
    };
    // No caller-provided algorithms, transforms, references or KeyInfo enter
    // the signing context. The library canonicalizes and fills this template.
    let template = format!(
        r##"<ds:Signature xmlns:ds="{DSIG_NS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_URI}"/><ds:SignatureMethod Algorithm="{method}"/><ds:Reference URI="#{target_id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_SIGNATURE_URI}"/><ds:Transform Algorithm="{EXC_C14N_URI}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"##
    );
    let template = uppsala::parse(&template).map_err(|e| bad(e.to_string()))?;
    let signature = doc
        .import_subtree(
            &template,
            template
                .document_element()
                .ok_or_else(|| bad("missing signature template"))?,
        )
        .ok_or_else(|| bad("cannot import signature template"))?;
    if target_kind == SamlSigningElement::EntityDescriptor {
        const METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
        let extensions = children_named(&doc, target, METADATA_NS, "Extensions");
        if extensions.len() > 1 {
            return Err(bad(
                "metadata EntityDescriptor has multiple Extensions elements",
            ));
        }
        if let Some(extensions) = extensions.first() {
            // Metadata schema: Signature follows optional Extensions and
            // precedes the role descriptors.
            doc.insert_after(target, signature, *extensions);
        } else if let Some(first_element) = doc
            .children(target)
            .into_iter()
            .find(|node| doc.element(*node).is_some())
        {
            doc.insert_before(target, signature, first_element);
        } else {
            doc.append_child(target, signature);
        }
    } else if let Some(issuer) = issuer.first() {
        doc.insert_after(target, signature, *issuer);
    } else if let Some(first_element) = doc
        .children(target)
        .into_iter()
        .find(|node| doc.element(*node).is_some())
    {
        doc.insert_before(target, signature, first_element);
    } else {
        doc.append_child(target, signature);
    }
    // bergshamra signs the first Signature in document order. Bind that
    // selection to our template, including when covering signed descendants.
    if doc
        .descendants(doc.root())
        .into_iter()
        .find(|n| named(&doc, *n, DSIG_NS, "Signature"))
        != Some(signature)
    {
        return Err(bad(
            "SAML signature template is not first in document order",
        ));
    }
    let pem = std::str::from_utf8(private_key_pem)
        .map_err(|_| bad("invalid private key PEM encoding"))?;
    let key = match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => {
            let local = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
                .map_err(|_| bad("SAML signing requires a PKCS#8 RSA private key"))?;
            if local.n().bits() < 2048 {
                return Err(bad("SAML signing requires RSA >=2048 bits"));
            }
            loader::load_rsa_private_pem(private_key_pem)
        }
        // This loader accepts only PKCS#8 P-256, not arbitrary EC curves.
        SamlXmlSignatureAlgorithm::EcdsaSha256 => loader::load_ec_p256_private_pem(private_key_pem),
    }
    .map_err(|_| bad("invalid SAML signing key for selected algorithm"))?;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    bergshamra_dsig::sign::sign_document(&DsigContext::new(keys), &mut doc)
        .map_err(|e| bad(format!("SAML signing failed: {e}")))?;
    Ok(doc.to_xml())
}
