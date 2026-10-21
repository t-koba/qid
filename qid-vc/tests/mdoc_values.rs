use qid_vc::mdoc::{
    MdocDataElement, MdocDataElementValue, MdocIssuerSigned, MdocNamespace, build_mdoc_document,
    decode_mdoc_document, encode_mdoc_document,
};
use std::collections::BTreeMap;

fn document_with(value: MdocDataElementValue) -> qid_vc::mdoc::MdocDocument {
    let mut namespace = MdocNamespace::new();
    namespace.insert(MdocDataElement {
        identifier: "expiration_date".to_string(),
        value,
    });
    let mut namespaces = BTreeMap::new();
    namespaces.insert("org.iso.18013.5.1".to_string(), namespace);
    build_mdoc_document(
        "org.iso.18013.5.1.mDL",
        namespaces,
        MdocIssuerSigned::default(),
    )
}

#[test]
fn a_date_keeps_its_type_across_the_cbor_round_trip() {
    // A date is the RFC 8949 tag 0 date/time string, so the round trip
    // returns a date rather than a plain text value that looks like one.
    let document = document_with(MdocDataElementValue::Date(
        "2024-01-01T00:00:00Z".to_string(),
    ));
    let encoded = encode_mdoc_document(&document).expect("the document encodes");
    let decoded = decode_mdoc_document(&encoded).expect("the document decodes");
    let element = decoded
        .namespaces
        .get("org.iso.18013.5.1")
        .and_then(|namespace| namespace.get("expiration_date"))
        .expect("the date element survives");
    assert_eq!(
        element.value,
        MdocDataElementValue::Date("2024-01-01T00:00:00Z".to_string())
    );
}

#[test]
fn a_text_value_stays_text_across_the_cbor_round_trip() {
    let document = document_with(MdocDataElementValue::Text(
        "2024-01-01T00:00:00Z".to_string(),
    ));
    let encoded = encode_mdoc_document(&document).expect("the document encodes");
    let decoded = decode_mdoc_document(&encoded).expect("the document decodes");
    let element = decoded
        .namespaces
        .get("org.iso.18013.5.1")
        .and_then(|namespace| namespace.get("expiration_date"))
        .expect("the text element survives");
    assert_eq!(
        element.value,
        MdocDataElementValue::Text("2024-01-01T00:00:00Z".to_string())
    );
}

#[test]
fn an_integer_above_the_model_range_is_an_error() {
    // An integer the model does not represent must be refused, not
    // truncated into a different number that looks like data.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("docType".to_string()),
                ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string()),
            ),
            (
                ciborium::Value::Text("namespaces".to_string()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("org.iso.18013.5.1".to_string()),
                    ciborium::Value::Map(vec![(
                        ciborium::Value::Text("expiration_date".to_string()),
                        // The largest unsigned integer is above the range the
                        // model represents.
                        ciborium::Value::Integer(ciborium::value::Integer::from(u64::MAX)),
                    )]),
                )]),
            ),
        ]),
        &mut buf,
    )
    .expect("the fixture encodes");
    let error = decode_mdoc_document(&buf).expect_err("an integer out of range is refused");
    assert!(
        error.message().contains("does not represent"),
        "unexpected error: {}",
        error.message()
    );
}

#[test]
fn a_value_the_model_does_not_represent_is_an_error() {
    // A shape the model does not represent must not be presented as a text
    // value that looks like data.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("docType".to_string()),
                ciborium::Value::Text("org.iso.18013.5.1.mDL".to_string()),
            ),
            (
                ciborium::Value::Text("namespaces".to_string()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("org.iso.18013.5.1".to_string()),
                    ciborium::Value::Map(vec![(
                        ciborium::Value::Text("expiration_date".to_string()),
                        // A float is a shape the data model does not represent.
                        ciborium::Value::Float(1.5),
                    )]),
                )]),
            ),
        ]),
        &mut buf,
    )
    .expect("the fixture encodes");
    let error = decode_mdoc_document(&buf).expect_err("a value with no type is refused");
    assert!(
        error.message().contains("does not represent"),
        "unexpected error: {}",
        error.message()
    );
}
