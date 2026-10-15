use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

// MIT: Query-farm/vgi-saml@5c14a1902c51261696f5fa81210ce62e150f3bbd
// See tests/fixtures/README.md for provenance. Do not reserialize this fixture.
const EXTERNAL_EC: &str = include_str!("../../tests/fixtures/vgi-saml-signed-response-ecdsa.xml");
const EC_METHOD: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

fn fixture_key() -> String {
    let doc = uppsala::parse(EXTERNAL_EC).unwrap();
    let cert = doc
        .descendants(doc.root())
        .into_iter()
        .find(|n| named(&doc, *n, DSIG_NS, "X509Certificate"))
        .unwrap();
    let cert = doc
        .text_content_deep(cert)
        .split_whitespace()
        .collect::<String>();
    let der = STANDARD.decode(&cert).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&der)),
        "21b45f117b1a67a32300d524eefde46d111a64ba4bfacecdd75b68be0330d953"
    );
    crate::xmldsig::cert_pem_to_public_key_pem(&der).unwrap()
}

fn verify_ec<'a>(xml: &'a str, key: &[u8]) -> QidResult<VerifiedSamlDocument<'a>> {
    // The returned tree borrows XML only, never the selected key.
    verify_saml_xml_signature_for(
        SamlSignatureInputs {
            document: xml,
            public_key_pem: key,
            profile: SamlXmlSignatureAlgorithm::EcdsaSha256,
        },
        SignedSamlElement::Assertion,
    )
}

#[test]
fn independent_ecdsa_fixture_has_pinned_bytes_certificate_and_exact_claim_node() {
    assert_eq!(
        hex::encode(Sha256::digest(EXTERNAL_EC.as_bytes())),
        "9fde9a20177bfcb853b2d667a0ced457ee4ea1a2cb94834559c35d6abad45013"
    );
    let key = fixture_key();
    let verified = verify_ec(EXTERNAL_EC, key.as_bytes()).unwrap();
    let doc = verified.document();
    let assertion = verified.target();
    assert!(named(doc, assertion, ASSERTION_NS, "Assertion"));
    assert_eq!(attribute(doc, assertion, "ID"), Some("_a1"));
    assert_ne!(Some(assertion), doc.document_element());
    let claims = verified.assertion_claims().unwrap();
    assert_eq!(claims.response_id.as_deref(), Some("_r1"));
    assert_eq!(claims.assertion_id, "_a1");
    assert_eq!(claims.issuer, "https://idp.example.com/saml");
    assert_eq!(claims.subject, "alice@example.com");
    assert_eq!(
        claims.attributes,
        vec![
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(),
                vec!["alice@example.com".into()]
            ),
            ("role".into(), vec!["admin".into(), "user".into()]),
        ]
    );
    let changed = EXTERNAL_EC.replacen(
        "https://idp.example.com/saml",
        "https://unsigned.example",
        1,
    );
    assert_eq!(
        verify_ec(&changed, key.as_bytes())
            .unwrap()
            .assertion_claims()
            .unwrap(),
        claims
    );
}

#[test]
fn embedded_keyinfo_cannot_override_the_selected_key() {
    use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
    let wrong = p256::SecretKey::from_pkcs8_pem(include_str!("../test-ec-key.pem")).unwrap();
    let wrong_public = wrong
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let key = fixture_key();
    assert!(
        verify_ec(EXTERNAL_EC, wrong_public.as_bytes()).is_err(),
        "embedded valid certificate must not override the configured wrong key"
    );
    assert!(verify_ec(EXTERNAL_EC, key.as_bytes()).is_ok());
    // Add an unrelated document-supplied ECKeyValue, outside SignedInfo/target digest.
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = STANDARD.encode(wrong.public_key().to_encoded_point(false).as_bytes());
    let inline = format!(
        r#"<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>{point}</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>"#
    );
    let changed = EXTERNAL_EC.replace("<ds:KeyInfo>", &format!("<ds:KeyInfo>{inline}"));
    assert!(
        verify_ec(&changed, key.as_bytes()).is_ok(),
        "untrusted KeyInfo must be ignored"
    );
    assert!(verify_ec(&changed, wrong_public.as_bytes()).is_err());
}

fn signature(xml: &str) -> &str {
    let start = xml.find("<ds:Signature ").unwrap();
    let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    &xml[start..end]
}

#[test]
fn preflight_rejects_unsupported_algorithms_references_transforms_and_shapes_before_keys() {
    let reference_start = EXTERNAL_EC.find("<ds:Reference ").unwrap();
    let reference_end = EXTERNAL_EC.find("</ds:Reference>").unwrap() + "</ds:Reference>".len();
    let reference = &EXTERNAL_EC[reference_start..reference_end];
    let signed_info_start = EXTERNAL_EC.find("<ds:SignedInfo>").unwrap();
    let signed_info_end = EXTERNAL_EC.find("</ds:SignedInfo>").unwrap() + "</ds:SignedInfo>".len();
    let signed_info = &EXTERNAL_EC[signed_info_start..signed_info_end];
    let sig = signature(EXTERNAL_EC);
    let moved = EXTERNAL_EC
        .replace(sig, "")
        .replace("</samlp:Response>", &format!("{sig}</samlp:Response>"));
    let mutations = vec![
        ("SHA-1 signature", EXTERNAL_EC.replace(EC_METHOD, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")),
        ("SHA-1 digest", EXTERNAL_EC.replace(SHA256_URI, "http://www.w3.org/2000/09/xmldsig#sha1")),
        ("HMAC", EXTERNAL_EC.replace(EC_METHOD, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256")),
        ("unknown method", EXTERNAL_EC.replace(EC_METHOD, "urn:unknown:ecdsa-sha256")),
        ("unknown digest", EXTERNAL_EC.replace(SHA256_URI, "urn:unknown:sha256")),
        ("external https", EXTERNAL_EC.replace("URI=\"#_a1\"", "URI=\"https://example.invalid/assertion\"")),
        ("external file", EXTERNAL_EC.replace("URI=\"#_a1\"", "URI=\"file:///assertion\"")),
        ("empty reference", EXTERNAL_EC.replace("URI=\"#_a1\"", "URI=\"\"")),
        ("xpointer", EXTERNAL_EC.replace("URI=\"#_a1\"", "URI=\"#xpointer(id('_a1'))\"")),
        ("missing target", EXTERNAL_EC.replace("URI=\"#_a1\"", "URI=\"#missing\"")),
        ("multiple references", EXTERNAL_EC.replace(reference, &format!("{reference}{reference}"))),
        ("multiple signatures", EXTERNAL_EC.replace(sig, &format!("{sig}{sig}"))),
        ("multiple SignedInfo", EXTERNAL_EC.replace(signed_info, &format!("{signed_info}{signed_info}"))),
        ("missing SignedInfo", EXTERNAL_EC.replace(signed_info, "")),
        ("missing reference", EXTERNAL_EC.replace(reference, "")),
        ("unknown transform", EXTERNAL_EC.replace(ENVELOPED_SIGNATURE_URI, "urn:unsupported-transform")),
        ("unsupported transform parameter", EXTERNAL_EC.replace(&format!("<ds:Transform Algorithm=\"{EXC_C14N_URI}\"/>"), &format!("<ds:Transform Algorithm=\"{EXC_C14N_URI}\"><ds:XPath>//*</ds:XPath></ds:Transform>"))),
        ("single quoted unknown transform", EXTERNAL_EC.replace(&format!("Algorithm=\"{ENVELOPED_SIGNATURE_URI}\""), "Algorithm='urn:unknown'")),
        ("unquoted transform", EXTERNAL_EC.replace(&format!("Algorithm=\"{ENVELOPED_SIGNATURE_URI}\""), "Algorithm=/")),
        ("missing enveloped transform", EXTERNAL_EC.replace(&format!("<ds:Transform Algorithm=\"{ENVELOPED_SIGNATURE_URI}\"/>"), "")),
        ("reversed transforms", EXTERNAL_EC.replace(&format!("<ds:Transform Algorithm=\"{ENVELOPED_SIGNATURE_URI}\"/><ds:Transform Algorithm=\"{EXC_C14N_URI}\"/>"), &format!("<ds:Transform Algorithm=\"{EXC_C14N_URI}\"/><ds:Transform Algorithm=\"{ENVELOPED_SIGNATURE_URI}\"/>"))),
        ("inclusive SignedInfo", EXTERNAL_EC.replacen(EXC_C14N_URI, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", 1)),
        ("missing canonicalization method", EXTERNAL_EC.replace(&format!("<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N_URI}\"/>"), "")),
        ("unknown canonicalization method", EXTERNAL_EC.replacen(EXC_C14N_URI, "urn:unknown-c14n", 1)),
        ("wrong SAML namespace", EXTERNAL_EC.replace(ASSERTION_NS, "urn:foreign-assertion")),
        ("unsupported element", EXTERNAL_EC.replace("saml:Assertion", "saml:Statement")),
        ("alias-only target", EXTERNAL_EC.replace("ID=\"_a1\"", "Id=\"_a1\"")),
        ("wrapping", EXTERNAL_EC.replace("<saml:Assertion ", "<saml:Advice><saml:Assertion ").replace("</saml:Assertion>", "</saml:Assertion></saml:Advice>")),
        ("unsigned decoy", EXTERNAL_EC.replace("</samlp:Response>", "<saml:Assertion ID=\"decoy\"><saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>")),
        ("misplaced signature", moved),
    ];
    for (name, xml) in mutations {
        // Empty selected key proves rejection did not depend on key or crypto.
        let error = verify_ec(&xml, b"")
            .err()
            .unwrap_or_else(|| panic!("accepted {name}"));
        assert!(
            !error.message().contains("selected public key"),
            "{name} reached key loading: {error}"
        );
    }
}

#[test]
fn duplicate_ids_and_every_candidate_alias_fail_preflight() {
    for alias in ["ID", "Id", "id", "AssertionID", "xml:id"] {
        for (from, to) in [
            (
                "ID=\"_r1\"".to_string(),
                format!("ID=\"_r1\" {alias}=\"_a1\""),
            ),
            (
                "ID=\"_a1\"".to_string(),
                format!("ID=\"_a1\" {alias}=\"_a1\""),
            ),
        ] {
            let changed = EXTERNAL_EC.replace(&from, &to);
            let error = verify_ec(&changed, b"")
                .err()
                .expect("duplicate ID must fail");
            assert!(
                !error.message().contains("selected public key"),
                "{alias}: {error}"
            );
        }
    }
}

#[test]
fn verified_target_type_and_caller_algorithm_are_enforced() {
    let key = fixture_key();
    for kind in [
        SignedSamlElement::Response,
        SignedSamlElement::AuthnRequest,
        SignedSamlElement::LogoutRequest,
    ] {
        let err = verify_saml_xml_signature_for(
            SamlSignatureInputs {
                document: EXTERNAL_EC,
                public_key_pem: b"",
                profile: SamlXmlSignatureAlgorithm::EcdsaSha256,
            },
            kind,
        )
        .err()
        .unwrap();
        assert!(err.message().contains("expected element"));
    }
    let err = verify_saml_xml_signature_for(
        SamlSignatureInputs {
            document: EXTERNAL_EC,
            public_key_pem: key.as_bytes(),
            profile: SamlXmlSignatureAlgorithm::RsaSha256,
        },
        SignedSamlElement::Assertion,
    )
    .err()
    .unwrap();
    assert!(err.message().contains("profile mismatch"));
}

#[test]
fn rsa_sha256_algorithm_path_and_all_target_types_smoke() {
    // Local algorithm-path smoke, not an independent interoperability vector.
    let key = include_bytes!("../../tests/data/test-sp.key");
    let cert = include_str!("../../tests/data/test-sp.crt");
    let body = cert
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let public = crate::cert_pem_to_public_key_pem_from_pem(cert).unwrap();
    assert!(
        RsaPublicKey::from_public_key_pem(&public)
            .unwrap()
            .n()
            .bits()
            >= 2048
    );
    for kind in [
        SignedSamlElement::Assertion,
        SignedSamlElement::Response,
        SignedSamlElement::AuthnRequest,
        SignedSamlElement::LogoutRequest,
    ] {
        let (ns, name) = kind.name();
        let xml = format!(r#"<s:{name} xmlns:s="{ns}" ID="rsa-1"><!--SIGNATURE--></s:{name}>"#);
        let signed = crate::tests::sign_saml_test_document(&xml, "rsa-1", key, &body);
        let verified = verify_saml_xml_signature_for(
            SamlSignatureInputs {
                document: &signed,
                public_key_pem: public.as_bytes(),
                profile: SamlXmlSignatureAlgorithm::RsaSha256,
            },
            kind,
        )
        .unwrap();
        assert_eq!(
            Some(verified.target()),
            verified.document().document_element()
        );
        let tampered = signed.replace("ID=\"rsa-1\"", "ID=\"rsa-2\"");
        assert!(
            verify_saml_xml_signature_for(
                SamlSignatureInputs {
                    document: &tampered,
                    public_key_pem: public.as_bytes(),
                    profile: SamlXmlSignatureAlgorithm::RsaSha256,
                },
                kind
            )
            .is_err()
        );
    }
}

#[test]
fn rsa_sha256_rejects_ephemeral_1024_bit_selected_key_before_verification() {
    use rsa::pkcs8::{EncodePublicKey, LineEnding};

    // Generate only in memory: never commit an undersized private-key fixture.
    let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
    let public = private.to_public_key();
    assert_eq!(public.n().bits(), 1024);
    let public_pem = public.to_public_key_pem(LineEnding::LF).unwrap();
    let xml = format!(
        r#"<s:Assertion xmlns:s="{ASSERTION_NS}" ID="weak-rsa"><!--SIGNATURE--></s:Assertion>"#
    );
    let signed = crate::tests::sign_saml_test_document(
        &xml,
        "weak-rsa",
        include_bytes!("../../tests/data/test-sp.key"),
        "",
    );
    // A valid document passes with the existing >=2048-bit selected key.
    assert!(verify_rsa(&signed, SignedSamlElement::Assertion).is_ok());
    // Selecting a weak key must fail the size check, not signature verification.
    let error = verify_saml_xml_signature_for(
        SamlSignatureInputs {
            document: &signed,
            public_key_pem: public_pem.as_bytes(),
            profile: SamlXmlSignatureAlgorithm::RsaSha256,
        },
        SignedSamlElement::Assertion,
    )
    .err()
    .expect("1024-bit selected RSA must be rejected before signature verification");
    assert!(matches!(
        error,
        QidError::BadRequest { message } if message == "SAML RSA public key must be at least 2048 bits"
    ));
}

#[test]
fn tampered_signed_claims_and_digest_fail_crypto() {
    let key = fixture_key();
    for xml in [
        EXTERNAL_EC.replace("alice@example.com", "mallory@example.com"),
        EXTERNAL_EC.replace(">admin<", ">owner<"),
        EXTERNAL_EC.replace(
            "0hyKGHddcGcjfQJTJTRKvvDcy+UkSvAtcHfAtRDP9+M=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    ] {
        assert!(verify_ec(&xml, key.as_bytes()).is_err());
    }
}

#[test]
fn namespace_aware_preflight_supports_standard_exclusive_parameters_and_quoted_attributes() {
    let key = fixture_key();
    let single_quotes = EXTERNAL_EC.replace(
        &format!("Algorithm=\"{ENVELOPED_SIGNATURE_URI}\""),
        &format!("Algorithm='{ENVELOPED_SIGNATURE_URI}'"),
    );
    assert!(verify_ec(&single_quotes, key.as_bytes()).is_ok());
    let inclusive = EXTERNAL_EC.replace(
        &format!("<ds:Transform Algorithm=\"{EXC_C14N_URI}\"/>"),
        &format!("<ds:Transform Algorithm=\"{EXC_C14N_URI}\"><ec:InclusiveNamespaces xmlns:ec=\"{EXC_C14N_URI}\" PrefixList=\"saml xs xsi\"/></ds:Transform>"));
    let doc = uppsala::parse(&inclusive).unwrap();
    preflight(
        &doc,
        SamlXmlSignatureAlgorithm::EcdsaSha256,
        SignedSamlElement::Assertion,
    )
    .unwrap();
    // The mutation changed SignedInfo, so preflight support is not acceptance.
    assert!(verify_ec(&inclusive, key.as_bytes()).is_err());
    let rsa =
        crate::cert_pem_to_public_key_pem_from_pem(include_str!("../../tests/data/test-sp.crt"))
            .unwrap();
    let err = verify_ec(EXTERNAL_EC, rsa.as_bytes()).err().unwrap();
    assert!(err.message().contains("selected key does not match"));
}

fn verify_rsa(xml: &str, kind: SignedSamlElement) -> QidResult<VerifiedSamlDocument<'_>> {
    let public =
        crate::cert_pem_to_public_key_pem_from_pem(include_str!("../../tests/data/test-sp.crt"))
            .unwrap();
    verify_saml_xml_signature_for(
        SamlSignatureInputs {
            document: xml,
            public_key_pem: public.as_bytes(),
            profile: SamlXmlSignatureAlgorithm::RsaSha256,
        },
        kind,
    )
}

#[test]
fn both_signature_targets_extract_only_the_exact_assertions_direct_claims() {
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="r"><saml:Issuer>response-issuer</saml:Issuer>
<saml:Assertion ID="a"><saml:Issuer>assertion-issuer</saml:Issuer><!--SIGNATURE-->
<saml:NameID>decoy</saml:NameID><saml:Subject><saml:NameID>verified-subject</saml:NameID></saml:Subject>
<saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
<saml:Advice><saml:Attribute Name="role"><saml:AttributeValue>decoy</saml:AttributeValue></saml:Attribute></saml:Advice>
</saml:Assertion></samlp:Response>"#
    );
    for (kind, id, issuer) in [
        (SignedSamlElement::Assertion, "a", "assertion-issuer"),
        (SignedSamlElement::Response, "r", "response-issuer"),
    ] {
        let signed = crate::tests::sign_saml_test_document(
            &xml,
            id,
            include_bytes!("../../tests/data/test-sp.key"),
            "",
        );
        let verified = verify_rsa(&signed, kind).unwrap();
        assert_eq!(verified.signed_element(), kind);
        let claims = verified.assertion_claims().unwrap();
        assert_eq!(claims.issuer, issuer);
        assert_eq!(claims.subject, "verified-subject");
        assert_eq!(claims.response_id.as_deref(), Some("r"));
        assert_eq!(claims.assertion_id, "a");
        assert_eq!(
            claims.attributes,
            vec![("role".into(), vec!["admin".into(), "user".into()])]
        );
        let tampered = signed.replace("verified-subject", "changed-subject");
        assert!(verify_rsa(&tampered, kind).is_err());
        let decoy = signed.replace(
            "</samlp:Response>",
            "<saml:Assertion ID=\"decoy\"/></samlp:Response>",
        );
        assert!(verify_rsa(&decoy, kind).is_err());
    }
}

#[test]
fn signed_response_claim_extraction_requires_one_direct_assertion() {
    for body in [
        "".to_string(),
        "<saml:Assertion ID=\"a\"/><saml:Assertion ID=\"b\"/>".to_string(),
        "<saml:Advice><saml:Assertion ID=\"a\"/></saml:Advice>".to_string(),
    ] {
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="r"><saml:Issuer>issuer</saml:Issuer><!--SIGNATURE-->{body}</samlp:Response>"#
        );
        let signed = crate::tests::sign_saml_test_document(
            &xml,
            "r",
            include_bytes!("../../tests/data/test-sp.key"),
            "",
        );
        match verify_rsa(&signed, SignedSamlElement::Response) {
            Ok(verified) => assert!(verified.assertion_claims().is_err()),
            Err(error) => assert!(error.message().contains("wrapping"), "{error}"),
        }
    }
}
