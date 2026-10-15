//! Offline production-signer regressions, not general XMLDSig or live-IdP coverage.
#![cfg(test)]
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::{KeysManager, loader};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use qid_saml::{
    SamlIssuedResponse, SamlSignatureInputs, SamlSigningElement, SamlSigningPolicy,
    SamlXmlSignatureAlgorithm, SignedSamlElement, decrypt_saml_response, encrypt_saml_response,
    import_sp_metadata, sign_saml_document_with_key, sign_saml_response_with_key,
    verify_saml_xml_signature_for,
};

const RSA: &[u8] = include_bytes!("data/test-sp.key");
const EC: &[u8] = include_bytes!("../src/test-ec-key.pem");
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XML: &str = r#"<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ext="urn:example:claims" ID="r1"><a:Issuer>https://idp.example</a:Issuer><p:Status/><a:Assertion Version="2.0" ID="a1"><a:Issuer>https://idp.example</a:Issuer><a:Subject><a:NameID ext:kind="person">alice&amp;bob</a:NameID></a:Subject></a:Assertion></p:Response>"#;

fn profiles() -> [(SamlXmlSignatureAlgorithm, &'static [u8]); 2] {
    [
        (SamlXmlSignatureAlgorithm::RsaSha256, RSA),
        (SamlXmlSignatureAlgorithm::EcdsaSha256, EC),
    ]
}

fn public_key(algorithm: SamlXmlSignatureAlgorithm) -> String {
    match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => {
            rsa::RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(RSA).unwrap())
                .unwrap()
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
        }
        SamlXmlSignatureAlgorithm::EcdsaSha256 => {
            p256::SecretKey::from_pkcs8_pem(std::str::from_utf8(EC).unwrap())
                .unwrap()
                .public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
        }
    }
}

fn context(algorithm: SamlXmlSignatureAlgorithm) -> DsigContext {
    let public = public_key(algorithm);
    let key = match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => loader::load_rsa_public_pem(public.as_bytes()),
        SamlXmlSignatureAlgorithm::EcdsaSha256 => loader::load_spki_pem(public.as_bytes()),
    }
    .unwrap();
    let mut keys = KeysManager::new();
    keys.add_key(key);
    DsigContext::new(keys)
}

// The inbound protocol profile deliberately permits only one signature. Use
// the backend directly to check both signatures without broadening that policy.
fn check_references(xml: &str, algorithm: SamlXmlSignatureAlgorithm, ids: &[&str]) {
    let doc = uppsala::parse(xml).unwrap();
    let results = bergshamra_dsig::verify::verify_all_document(&context(algorithm), &doc).unwrap();
    assert_eq!(results.len(), ids.len());
    for (result, id) in results.iter().zip(ids) {
        let VerifyResult::Valid {
            signature_node,
            references,
            ..
        } = result
        else {
            panic!("invalid signature: {result:?}");
        };
        assert_eq!(references.len(), 1);
        assert!(references[0].digest_verified);
        assert_eq!(references[0].uri, format!("#{id}"));
        let target = references[0].resolved_node.unwrap();
        assert_eq!(doc.parent(*signature_node), Some(target));
        assert_eq!(doc.element(target).unwrap().get_attribute("ID"), Some(*id));
    }
    let parsed = roxmltree::Document::parse(xml).unwrap();
    for reference in parsed
        .descendants()
        .filter(|n| n.has_tag_name((DS, "Reference")))
    {
        let transforms: Vec<_> = reference
            .descendants()
            .filter(|n| n.has_tag_name((DS, "Transform")))
            .map(|n| n.attribute("Algorithm").unwrap())
            .collect();
        assert_eq!(
            transforms,
            [
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                "http://www.w3.org/2001/10/xml-exc-c14n#",
            ]
        );
        assert_eq!(
            reference
                .descendants()
                .find(|n| n.has_tag_name((DS, "DigestMethod")))
                .unwrap()
                .attribute("Algorithm"),
            Some("http://www.w3.org/2001/04/xmlenc#sha256")
        );
    }
    // Encryption may carry KeyInfo, but the signer must not emit it.
    for signature in parsed
        .descendants()
        .filter(|n| n.has_tag_name((DS, "Signature")))
    {
        assert!(
            !signature
                .descendants()
                .any(|n| n.has_tag_name((DS, "KeyInfo")))
        );
    }
}

#[test]
fn production_signer_binds_rsa_and_p256_inherited_namespace_targets() {
    for (algorithm, key) in profiles() {
        for (kind, expected, id) in [
            (
                SamlSigningElement::Assertion,
                SignedSamlElement::Assertion,
                "a1",
            ),
            (
                SamlSigningElement::Response,
                SignedSamlElement::Response,
                "r1",
            ),
        ] {
            let signed = sign_saml_document_with_key(XML, kind, id, algorithm, key).unwrap();
            check_references(&signed, algorithm, &[id]);
            let public = public_key(algorithm);
            let verified = verify_saml_xml_signature_for(
                SamlSignatureInputs {
                    document: &signed,
                    public_key_pem: public.as_bytes(),
                    profile: algorithm,
                },
                expected,
            )
            .unwrap();
            assert_eq!(verified.assertion_claims().unwrap().subject, "alice&bob");
            let changed = signed.replace("alice&amp;bob", "mallory");
            assert!(
                verify_saml_xml_signature_for(
                    SamlSignatureInputs {
                        document: &changed,
                        public_key_pem: public.as_bytes(),
                        profile: algorithm,
                    },
                    expected
                )
                .is_err()
            );
            assert!(sign_saml_document_with_key(&signed, kind, id, algorithm, key).is_err());
        }
    }
}

#[test]
fn sequential_response_signing_covers_the_inner_signature_and_honors_policy() {
    let mut sp = import_sp_metadata(r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example"><SPSSODescriptor WantAssertionsSigned="true"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs"/></SPSSODescriptor></EntityDescriptor>"#).unwrap();
    let issued = SamlIssuedResponse {
        response_id: "r1".into(),
        assertion_id: "a1".into(),
        xml: XML.into(),
    };
    for (algorithm, key) in profiles() {
        // SP requirement adds Assertion even though caller requests only Response.
        let both = sign_saml_response_with_key(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: true,
                sign_assertion: false,
            },
            key,
            algorithm,
        )
        .unwrap();
        check_references(&both.xml, algorithm, &["r1", "a1"]);
        let doc = roxmltree::Document::parse(&both.xml).unwrap();
        let inner_value = doc
            .descendants()
            .filter(|n| n.has_tag_name((DS, "SignatureValue")))
            .nth(1)
            .unwrap()
            .first_child()
            .unwrap()
            .range();
        let mut changed = both.xml.clone();
        let replacement = if &changed[inner_value.start..inner_value.start + 1] == "A" {
            "B"
        } else {
            "A"
        };
        changed.replace_range(inner_value.start..inner_value.start + 1, replacement);
        assert!(
            !bergshamra_dsig::verify::verify(&context(algorithm), &changed)
                .unwrap()
                .is_valid(),
            "outer Response must cover the inner Assertion signature"
        );
        let assertion = sign_saml_response_with_key(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: false,
                sign_assertion: false,
            },
            key,
            algorithm,
        )
        .unwrap();
        check_references(&assertion.xml, algorithm, &["a1"]);
        sp.want_assertions_signed = false;
        let requested_assertion = sign_saml_response_with_key(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: false,
                sign_assertion: true,
            },
            key,
            algorithm,
        )
        .unwrap();
        check_references(&requested_assertion.xml, algorithm, &["a1"]);
        let response = sign_saml_response_with_key(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: true,
                sign_assertion: false,
            },
            key,
            algorithm,
        )
        .unwrap();
        check_references(&response.xml, algorithm, &["r1"]);
        assert!(
            sign_saml_response_with_key(
                &issued,
                &sp,
                &SamlSigningPolicy {
                    sign_response: false,
                    sign_assertion: false,
                },
                key,
                algorithm
            )
            .is_err()
        );
        sp.want_assertions_signed = true;
    }
}

#[test]
fn assertion_sign_encrypt_response_sign_decrypt_preserves_both_signatures() {
    let sp = import_sp_metadata(r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example"><SPSSODescriptor WantAssertionsSigned="true"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs"/></SPSSODescriptor></EntityDescriptor>"#).unwrap();
    let cert: String = include_str!("data/test-sp.crt")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let issued = SamlIssuedResponse {
        response_id: "r1".into(),
        assertion_id: "a1".into(),
        xml: XML.into(),
    };
    for (algorithm, key) in profiles() {
        // Match SSO's production order: no outer signature before encryption.
        let assertion_signed = sign_saml_response_with_key(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: false,
                sign_assertion: true,
            },
            key,
            algorithm,
        )
        .unwrap();
        check_references(&assertion_signed.xml, algorithm, &["a1"]);
        let encrypted = encrypt_saml_response(&assertion_signed, &cert).unwrap();
        let signed = sign_saml_document_with_key(
            &encrypted.xml,
            SamlSigningElement::Response,
            &encrypted.response_id,
            algorithm,
            key,
        )
        .unwrap();
        check_references(&signed, algorithm, &["r1"]);
        let doc = roxmltree::Document::parse(&signed).unwrap();
        const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
        assert!(
            !doc.descendants()
                .any(|n| n.has_tag_name((ASSERTION_NS, "Assertion")))
        );
        assert_eq!(
            doc.descendants()
                .filter(|n| n.has_tag_name((ASSERTION_NS, "EncryptedAssertion")))
                .count(),
            1
        );
        assert!(!signed.contains("alice"));
        // Changing encrypted content must invalidate the outer signature.
        let changed = signed.replace("<xenc:CipherValue>", "<xenc:CipherValue>A");
        assert_ne!(signed, changed);
        assert!(
            !bergshamra_dsig::verify::verify(&context(algorithm), &changed)
                .unwrap()
                .is_valid()
        );
        let decrypted = decrypt_saml_response(&signed, RSA).unwrap();
        // The outer signature covered ciphertext, not this decrypted document.
        // Remove only that signature before checking the inner one, preserving
        // the Assertion's inherited namespace context. Do not widen inbound policy.
        let doc = roxmltree::Document::parse(&decrypted).unwrap();
        let outer = doc
            .root_element()
            .children()
            .find(|n| n.has_tag_name((DS, "Signature")))
            .unwrap()
            .range();
        let mut assertion_document = decrypted.clone();
        assertion_document.replace_range(outer, "");
        check_references(&assertion_document, algorithm, &["a1"]);
        let public = public_key(algorithm);
        let verified = verify_saml_xml_signature_for(
            SamlSignatureInputs {
                document: &assertion_document,
                public_key_pem: public.as_bytes(),
                profile: algorithm,
            },
            SignedSamlElement::Assertion,
        )
        .unwrap();
        assert_eq!(verified.assertion_claims().unwrap().subject, "alice&bob");
    }
}

#[test]
fn metadata_signature_follows_extensions_and_covers_the_complete_entity_descriptor() {
    let xml = r#"<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="metadata-1" entityID="https://idp.example"><Extensions/><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>"#;
    for xml in [xml.to_string(), xml.replace("<Extensions/>", "")] {
        for (algorithm, key) in profiles() {
            let signed = sign_saml_document_with_key(
                &xml,
                SamlSigningElement::EntityDescriptor,
                "metadata-1",
                algorithm,
                key,
            )
            .unwrap();
            check_references(&signed, algorithm, &["metadata-1"]);
            let doc = roxmltree::Document::parse(&signed).unwrap();
            let children: Vec<_> = doc
                .root_element()
                .children()
                .filter(|n| n.is_element())
                .collect();
            let signature_index = if xml.contains("<Extensions/>") {
                assert_eq!(children[0].tag_name().name(), "Extensions");
                1
            } else {
                0
            };
            assert!(children[signature_index].has_tag_name((DS, "Signature")));
            assert_eq!(
                children[signature_index + 1].tag_name().name(),
                "IDPSSODescriptor"
            );
            let changed = signed.replace("https://idp.example", "https://changed.example");
            assert!(
                !bergshamra_dsig::verify::verify(&context(algorithm), &changed)
                    .unwrap()
                    .is_valid()
            );
        }
    }
}

#[test]
fn target_binding_rejects_wrong_names_ids_and_alias_ambiguities() {
    for xml in [
        XML.replace("ID=\"a1\"", "ID=\"other\""),
        XML.replace("ID=\"a1\"", "Id=\"a1\""),
        XML.replace("ID=\"a1\"", "ext:ID=\"a1\""),
        XML.replace("ID=\"a1\"", "ID=\"a1\" ext:id=\"a1\""),
        XML.replace("ID=\"r1\"", "ID=\"a1\""),
        XML.replace("a:Assertion", "p:Assertion"),
        XML.replace("urn:oasis:names:tc:SAML:2.0:assertion", "urn:wrong"),
    ] {
        assert!(
            sign_saml_document_with_key(
                &xml,
                SamlSigningElement::Assertion,
                "a1",
                SamlXmlSignatureAlgorithm::RsaSha256,
                RSA
            )
            .is_err()
        );
    }
    assert!(
        sign_saml_document_with_key(
            XML,
            SamlSigningElement::Response,
            "a1",
            SamlXmlSignatureAlgorithm::RsaSha256,
            RSA
        )
        .is_err()
    );
    // A substring that resembles the old target marker is not a target.
    let decoy = XML.replace(
        "<p:Status/>",
        "<p:Status>Assertion ID=\"missing\"</p:Status>",
    );
    assert!(
        sign_saml_document_with_key(
            &decoy,
            SamlSigningElement::Assertion,
            "missing",
            SamlXmlSignatureAlgorithm::RsaSha256,
            RSA
        )
        .is_err()
    );
}

#[test]
fn local_signing_keys_must_match_the_profile_and_rsa_size_floor() {
    let weak = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024)
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    for (algorithm, key) in [
        (SamlXmlSignatureAlgorithm::RsaSha256, weak.as_bytes()),
        (SamlXmlSignatureAlgorithm::RsaSha256, EC),
        (SamlXmlSignatureAlgorithm::EcdsaSha256, RSA),
    ] {
        assert!(
            sign_saml_document_with_key(XML, SamlSigningElement::Assertion, "a1", algorithm, key)
                .is_err()
        );
    }
}
