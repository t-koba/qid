//! ISO 18013-5 mobile document (mdoc) data model.
//!
//! Implements the high-level data types required by the OpenID for
//! Verifiable Credentials family of profiles that bind HAIP
//! (High Assurance Interoperability Profile) to mdoc credentials.

use ciborium::Value as CborValue;
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// mdoc namespace identifier (e.g. `org.iso.18013.5.1`).
pub type Namespace = String;

/// mdoc data element identifier (e.g. `family_name`).
pub type DataElementIdentifier = String;

/// mdoc issuer signed item (ISO 18013-5 §8.3.2.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdocDataElement {
    pub identifier: DataElementIdentifier,
    pub value: MdocDataElementValue,
}

/// Typed mdoc value. The full set of CBOR data types is reduced to
/// the union below because the supporting use cases (PID, mDL) only
/// need a handful of primitive types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MdocDataElementValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
    Date(String),
}

impl MdocDataElementValue {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }
}

/// mdoc namespace container (ISO 18013-5 §8.3.2.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MdocNamespace {
    pub data_elements: BTreeMap<DataElementIdentifier, MdocDataElement>,
}

impl MdocNamespace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, element: MdocDataElement) {
        self.data_elements
            .insert(element.identifier.clone(), element);
    }

    pub fn get(&self, identifier: &str) -> Option<&MdocDataElement> {
        self.data_elements.get(identifier)
    }
}

/// mdoc issuer-signed document (ISO 18013-5 §8.3.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdocDocument {
    pub doc_type: String,
    pub namespaces: BTreeMap<Namespace, MdocNamespace>,
    pub issuer_signed: MdocIssuerSigned,
}

/// Placeholder for the issuer-signed portion. The COSE_Sign1
/// structure that carries the actual MSO is held in bytes; full
/// decoding lives in the dedicated mdoc decoder crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MdocIssuerSigned {
    pub mso_bytes: Vec<u8>,
    pub signature_chain: Vec<MdocCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdocCertificate {
    pub usage: MdocCertificateUsage,
    pub certificate_der: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MdocCertificateUsage {
    IcaoMasterList,
    DocumentSigner,
    Issuer,
}

/// Construct an mdoc document from in-memory namespace data. Used by
/// the issuer in tests and by the verifier to check expected
/// elements.
pub fn build_mdoc_document(
    doc_type: impl Into<String>,
    namespaces: BTreeMap<Namespace, MdocNamespace>,
    issuer_signed: MdocIssuerSigned,
) -> MdocDocument {
    MdocDocument {
        doc_type: doc_type.into(),
        namespaces,
        issuer_signed,
    }
}

/// Encode an mdoc document to CBOR bytes following ISO 18013-5 §8.3.2.
pub fn encode_mdoc_document(document: &MdocDocument) -> QidResult<Vec<u8>> {
    let mut doc_cbor = Vec::new();
    doc_cbor.push((encode_text("docType"), encode_text(&document.doc_type)));

    let mut namespaces_cbor = Vec::new();
    for (ns_name, ns) in &document.namespaces {
        let mut ns_vec = Vec::new();
        for (id, elem) in &ns.data_elements {
            ns_vec.push((encode_text(id), mdoc_value_to_cbor(&elem.value)));
        }
        namespaces_cbor.push((encode_text(ns_name), CborValue::Map(ns_vec)));
    }
    doc_cbor.push((encode_text("namespaces"), CborValue::Map(namespaces_cbor)));

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&CborValue::Map(doc_cbor), &mut buf).map_err(|e| {
        QidError::Internal {
            message: format!("mdoc CBOR encode failed: {e}"),
        }
    })?;
    Ok(buf)
}

/// Decode a CBOR-encoded mdoc document.
pub fn decode_mdoc_document(bytes: &[u8]) -> QidResult<MdocDocument> {
    let value: CborValue = ciborium::de::from_reader(bytes).map_err(|e| QidError::BadRequest {
        message: format!("mdoc CBOR decode failed: {e}"),
    })?;
    let map = value.as_map().ok_or_else(|| QidError::BadRequest {
        message: "mdoc CBOR root is not a map".to_string(),
    })?;

    let mut doc_type = String::new();
    let mut namespaces = BTreeMap::new();

    for (k, v) in map {
        if let Some(key) = k.as_text() {
            match key {
                "docType" => {
                    doc_type = v.as_text().unwrap_or("").to_string();
                }
                "namespaces" => {
                    if let Some(ns_map) = v.as_map() {
                        for (ns_k, ns_v) in ns_map {
                            let ns_name = ns_k.as_text().unwrap_or("").to_string();
                            let mut ns = MdocNamespace::new();
                            if let Some(elem_map) = ns_v.as_map() {
                                for (ek, ev) in elem_map {
                                    let id = ek.as_text().unwrap_or("").to_string();
                                    let val = cbor_to_mdoc_value(ev);
                                    ns.insert(MdocDataElement {
                                        identifier: id,
                                        value: val,
                                    });
                                }
                            }
                            namespaces.insert(ns_name, ns);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(MdocDocument {
        doc_type,
        namespaces,
        issuer_signed: MdocIssuerSigned::default(),
    })
}

fn encode_text(s: &str) -> CborValue {
    CborValue::Text(s.to_string())
}

fn mdoc_value_to_cbor(value: &MdocDataElementValue) -> CborValue {
    match value {
        MdocDataElementValue::Text(t) => CborValue::Text(t.clone()),
        MdocDataElementValue::Integer(i) => CborValue::Integer(ciborium::value::Integer::from(*i)),
        MdocDataElementValue::Boolean(b) => CborValue::Bool(*b),
        MdocDataElementValue::Bytes(b) => CborValue::Bytes(b.clone()),
        MdocDataElementValue::Date(d) => CborValue::Text(d.clone()),
    }
}

fn cbor_to_mdoc_value(value: &CborValue) -> MdocDataElementValue {
    match value {
        CborValue::Text(t) => MdocDataElementValue::Text(t.clone()),
        CborValue::Integer(i) => MdocDataElementValue::Integer(i128::from(*i) as i64),
        CborValue::Bool(b) => MdocDataElementValue::Boolean(*b),
        CborValue::Bytes(b) => MdocDataElementValue::Bytes(b.clone()),
        _ => MdocDataElementValue::Text(format!("{:?}", value)),
    }
}

/// Validate that every required data element is present in the
/// supplied document. `required` is a `(namespace, identifier)`
/// tuple. Returns the first missing element as an error.
pub fn require_mdoc_element<'a>(
    document: &'a MdocDocument,
    namespace: &str,
    identifier: &str,
) -> QidResult<&'a MdocDataElement> {
    let ns = document
        .namespaces
        .get(namespace)
        .ok_or_else(|| QidError::BadRequest {
            message: format!("mdoc namespace {namespace} is missing"),
        })?;
    ns.get(identifier).ok_or_else(|| QidError::BadRequest {
        message: format!("mdoc data element {namespace}/{identifier} is missing from document"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdoc_document_round_trip() {
        let mut ns = MdocNamespace::new();
        ns.insert(MdocDataElement {
            identifier: "family_name".to_string(),
            value: MdocDataElementValue::Text("Doe".to_string()),
        });
        ns.insert(MdocDataElement {
            identifier: "age".to_string(),
            value: MdocDataElementValue::Integer(35),
        });
        let mut namespaces = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), ns);
        let document = build_mdoc_document(
            "org.iso.18013.5.1.mDL",
            namespaces,
            MdocIssuerSigned::default(),
        );
        let family = require_mdoc_element(&document, "org.iso.18013.5.1", "family_name").unwrap();
        assert_eq!(family.value.as_text(), Some("Doe"));
    }

    #[test]
    fn mdoc_missing_element_is_an_error() {
        let document = MdocDocument {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            namespaces: BTreeMap::new(),
            issuer_signed: MdocIssuerSigned::default(),
        };
        assert!(require_mdoc_element(&document, "org.iso.18013.5.1", "family_name").is_err());
    }

    #[test]
    fn mdoc_cbor_round_trip() {
        let mut ns = MdocNamespace::new();
        ns.insert(MdocDataElement {
            identifier: "family_name".to_string(),
            value: MdocDataElementValue::Text("Doe".to_string()),
        });
        ns.insert(MdocDataElement {
            identifier: "age".to_string(),
            value: MdocDataElementValue::Integer(35),
        });
        let mut namespaces = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), ns);
        let doc = build_mdoc_document(
            "org.iso.18013.5.1.mDL",
            namespaces,
            MdocIssuerSigned::default(),
        );
        let encoded = encode_mdoc_document(&doc).unwrap();
        let decoded = decode_mdoc_document(&encoded).unwrap();
        assert_eq!(decoded.doc_type, "org.iso.18013.5.1.mDL");
        let ns = decoded.namespaces.get("org.iso.18013.5.1").unwrap();
        assert_eq!(ns.get("family_name").unwrap().value.as_text(), Some("Doe"));
        assert_eq!(
            ns.get("age").unwrap().value,
            MdocDataElementValue::Integer(35)
        );
    }
}
