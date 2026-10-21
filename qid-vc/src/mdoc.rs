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
///
/// The variants are tagged in CBOR, so a value keeps its type across a
/// round trip: a date is the RFC 8949 tag 0 date/time string, not a
/// plain text value that happens to look like one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdocDataElementValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
    /// An ISO 18013-5 date/time value.
    Date(String),
}

/// The RFC 8949 tag number of a standard date/time string.
const MDOC_DATE_TIME_TAG: u64 = 0;

impl Serialize for MdocDataElementValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            MdocDataElementValue::Text(value) => map.serialize_entry("text", value)?,
            MdocDataElementValue::Integer(value) => map.serialize_entry("integer", value)?,
            MdocDataElementValue::Boolean(value) => map.serialize_entry("boolean", value)?,
            MdocDataElementValue::Bytes(value) => map.serialize_entry("bytes", value)?,
            MdocDataElementValue::Date(value) => map.serialize_entry("date", value)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for MdocDataElementValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("an mdoc value must be an object naming its type"))?;
        if object.len() != 1 {
            return Err(D::Error::custom(
                "an mdoc value must name exactly one of text, integer, boolean, bytes or date",
            ));
        }
        let (key, value) = object.iter().next().expect("the object has one entry");
        match key.as_str() {
            "text" => text_value(value, key)
                .map(MdocDataElementValue::Text)
                .map_err(D::Error::custom),
            "integer" => integer_value(value, key)
                .map(MdocDataElementValue::Integer)
                .map_err(D::Error::custom),
            "boolean" => boolean_value(value, key)
                .map(MdocDataElementValue::Boolean)
                .map_err(D::Error::custom),
            "bytes" => bytes_value(value, key)
                .map(MdocDataElementValue::Bytes)
                .map_err(D::Error::custom),
            "date" => text_value(value, key)
                .map(MdocDataElementValue::Date)
                .map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "an mdoc value has an unknown type `{other}`"
            ))),
        }
    }
}

/// The string an mdoc value carries.
fn text_value(value: &serde_json::Value, key: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("the mdoc value `{key}` must be a string"))
}

/// The integer an mdoc value carries.
fn integer_value(value: &serde_json::Value, key: &str) -> Result<i64, String> {
    value
        .as_i64()
        .ok_or_else(|| format!("the mdoc value `{key}` must be an integer"))
}

/// The boolean an mdoc value carries.
fn boolean_value(value: &serde_json::Value, key: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("the mdoc value `{key}` must be a boolean"))
}

/// The bytes an mdoc value carries.
fn bytes_value(value: &serde_json::Value, key: &str) -> Result<Vec<u8>, String> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("the mdoc value `{key}` must be an array of bytes"))?;
    array
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| format!("the mdoc value `{key}` must be an array of bytes"))
        })
        .collect()
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

/// Encode the unsigned namespace representation of an mdoc document to CBOR.
/// Issuer-signed material has no representation in this format: documents
/// carrying MSO bytes or a signature chain are refused rather than
/// serialized lossily.
pub fn encode_mdoc_document(document: &MdocDocument) -> QidResult<Vec<u8>> {
    if document.issuer_signed != MdocIssuerSigned::default() {
        return Err(QidError::BadRequest {
            message: "mdoc issuer-signed material is not supported by this encoding".to_string(),
        });
    }
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

/// Decode the unsigned namespace representation produced by
/// [`encode_mdoc_document`]. Issuer-signed material is not parsed; use the
/// dedicated mdoc decoder crate for signed documents.
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
                                    let val = cbor_to_mdoc_value(ev)?;
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
        MdocDataElementValue::Date(d) => {
            CborValue::Tag(MDOC_DATE_TIME_TAG, Box::new(CborValue::Text(d.clone())))
        }
    }
}

/// The value a CBOR item carries.
///
/// A shape the model does not represent is an error: rendering it as a
/// debug string would present a value that looks like data but is not.
fn cbor_to_mdoc_value(value: &CborValue) -> QidResult<MdocDataElementValue> {
    match value {
        CborValue::Text(t) => Ok(MdocDataElementValue::Text(t.clone())),
        CborValue::Integer(i) => Ok(MdocDataElementValue::Integer(i128::from(*i) as i64)),
        CborValue::Bool(b) => Ok(MdocDataElementValue::Boolean(*b)),
        CborValue::Bytes(b) => Ok(MdocDataElementValue::Bytes(b.clone())),
        CborValue::Tag(tag, inner) => {
            if *tag != MDOC_DATE_TIME_TAG {
                return Err(QidError::BadRequest {
                    message: format!("mdoc CBOR value carries an unsupported tag {tag}"),
                });
            }
            let text = inner.as_text().ok_or_else(|| QidError::BadRequest {
                message: "an mdoc date/time value must be a text string".to_string(),
            })?;
            Ok(MdocDataElementValue::Date(text.to_string()))
        }
        _ => Err(QidError::BadRequest {
            message: "mdoc CBOR value has a type the data model does not represent".to_string(),
        }),
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
    fn mdoc_unsigned_document_round_trips_through_cbor() {
        let mut ns = MdocNamespace::new();
        ns.insert(MdocDataElement {
            identifier: "family_name".to_string(),
            value: MdocDataElementValue::Text("Doe".to_string()),
        });
        let mut namespaces = BTreeMap::new();
        namespaces.insert("org.iso.18013.5.1".to_string(), ns);
        let document = build_mdoc_document(
            "org.iso.18013.5.1.mDL",
            namespaces,
            MdocIssuerSigned::default(),
        );
        let bytes = encode_mdoc_document(&document).unwrap();
        let decoded = decode_mdoc_document(&bytes).unwrap();
        assert_eq!(decoded, document);
    }

    #[test]
    fn mdoc_encode_refuses_issuer_signed_material() {
        let signed = build_mdoc_document(
            "org.iso.18013.5.1.mDL",
            BTreeMap::new(),
            MdocIssuerSigned {
                mso_bytes: vec![1, 2, 3],
                signature_chain: vec![MdocCertificate {
                    usage: MdocCertificateUsage::Issuer,
                    certificate_der: vec![4, 5, 6],
                }],
            },
        );
        let err = encode_mdoc_document(&signed).unwrap_err();
        assert!(
            err.to_string()
                .contains("issuer-signed material is not supported"),
            "signed documents must fail closed instead of serializing lossily, got {err:?}"
        );
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
