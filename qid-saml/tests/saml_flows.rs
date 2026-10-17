use base64::{Engine, engine::general_purpose::STANDARD};
mod common;
use qid_saml::{
    EMAIL_NAME_ID_FORMAT, SamlAssertionRequest, SamlPostBindingForm, SamlRelayStatePolicy,
    SamlSubject, build_assertion_request_from_authn, build_saml_response, import_sp_metadata,
    inspect_saml_authn_request, inspect_saml_response_profile, parse_post_binding_authn_request,
    validate_authn_request_for_sp,
};

fn sp_metadata() -> String {
    include_str!("fixtures/sp-metadata-flow-test.xml")
        .replace("{name_id_format}", EMAIL_NAME_ID_FORMAT)
        .replace("{cert_body}", &common::test_sp_cert_body())
}

fn signed_authn_request_xml() -> anyhow::Result<String> {
    Ok(common::sign_test_document(
        include_str!("fixtures/authn-request-test.xml"),
        "req-123",
    ))
}

#[test]
fn sp_metadata_authn_request_and_response_round_trip() -> anyhow::Result<()> {
    let sp = import_sp_metadata(&sp_metadata())?;
    assert_eq!(sp.entity_id, "https://sp.example.com/metadata");
    assert_eq!(sp.acs_url, "https://sp.example.com/acs");
    assert_eq!(sp.name_id_formats, vec![EMAIL_NAME_ID_FORMAT]);
    assert_eq!(sp.signing_certificates, vec![common::test_sp_cert_body()]);
    assert!(sp.want_assertions_signed);

    let form = SamlPostBindingForm {
        saml_request: STANDARD.encode(signed_authn_request_xml()?),
        relay_state: Some("/app/home".to_string()),
    };
    let authn = parse_post_binding_authn_request(&form, &SamlRelayStatePolicy::default())?;
    validate_authn_request_for_sp(&authn, &sp, Some("https://idp.example.com/saml/corp/sso"))?;

    let assertion_request = build_assertion_request_from_authn(
        &authn,
        &sp,
        "https://idp.example.com/saml/corp",
        SamlSubject {
            user_id: "user-123".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice Example".to_string()),
            groups: vec!["engineering".to_string()],
        },
        1_735_689_600,
        300,
        Some("sid-123".to_string()),
    )?;
    let issued = build_saml_response(&assertion_request)?;
    let profile = inspect_saml_response_profile(&issued.xml)?;
    assert_eq!(
        profile.response_id.as_deref(),
        Some(issued.response_id.as_str())
    );
    assert_eq!(profile.assertion_ids, vec![issued.assertion_id]);
    assert_eq!(
        profile.destination.as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(profile.in_response_to.as_deref(), Some("req-123"));
    assert!(issued.xml.contains("<saml:NameID Format=\""));
    assert!(issued.xml.contains("alice@example.com"));
    Ok(())
}

#[test]
fn public_saml_entrypoints_reject_xsw_attack_patterns() -> anyhow::Result<()> {
    let sp = import_sp_metadata(&sp_metadata())?;
    let signed_authn = signed_authn_request_xml()?;
    let valid_authn = inspect_saml_authn_request(&signed_authn, None)?;
    validate_authn_request_for_sp(
        &valid_authn,
        &sp,
        Some("https://idp.example.com/saml/corp/sso"),
    )?;

    let signature_profile_attacks = [
        (
            "duplicate Signature",
            signed_authn.replace(
                "</ds:Signature>",
                "</ds:Signature><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#req-123\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/></ds:Reference></ds:SignedInfo></ds:Signature>",
            ),
        ),
        (
            "forbidden sibling Assertion",
            signed_authn.replace(
                "</ds:Signature>",
                "</ds:Signature><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>",
            ),
        ),
        (
            "forbidden sibling Extensions",
            signed_authn.replace("</ds:Signature>", "</ds:Signature><samlp:Extensions/>"),
        ),
        (
            "Reference URI mismatch",
            signed_authn.replace("URI=\"#req-123\"", "URI=\"#other\""),
        ),
        (
            "namespace-prefixed sibling Assertion",
            signed_authn.replace(
                "</ds:Signature>",
                "</ds:Signature><pfx:Assertion xmlns:pfx=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>",
            ),
        ),
    ];
    for (name, xml) in signature_profile_attacks {
        let req = inspect_saml_authn_request(&xml, None)
            .map_err(|err| anyhow::anyhow!("{name} should reach signature validation: {err:?}"))?;
        assert!(
            validate_authn_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/sso"))
                .is_err(),
            "{name} must be rejected"
        );
    }

    let parse_attacks = [
        (
            "duplicate AuthnRequest",
            signed_authn.replace(
                "</samlp:AuthnRequest>",
                "<samlp:AuthnRequest ID=\"wrapped\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest></samlp:AuthnRequest>",
            ),
        ),
        (
            "DOCTYPE AuthnRequest",
            signed_authn.replacen(
                "<samlp:AuthnRequest",
                "<!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><samlp:AuthnRequest",
                1,
            ),
        ),
        (
            "comment-hidden AuthnRequest",
            signed_authn.replacen("<ds:Signature", "<!-- hidden --> <ds:Signature", 1),
        ),
    ];
    for (name, xml) in parse_attacks {
        assert!(
            inspect_saml_authn_request(&xml, None).is_err(),
            "{name} must be rejected"
        );
    }

    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/saml/corp".to_string(),
        sp_entity_id: "https://sp.example.com/metadata".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        request_id: Some("req-123".to_string()),
        subject: SamlSubject {
            user_id: "user-123".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_735_689_600,
        not_on_or_after: 1_735_689_900,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })?
    .xml;
    let response_attacks = [
        (
            "duplicate Response",
            issued.replace(
                "</samlp:Response>",
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"wrapped\"></samlp:Response></samlp:Response>",
            ),
        ),
        (
            "duplicate Assertion",
            issued.replace(
                "</saml:Assertion>",
                "</saml:Assertion><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"wrapped\"/>",
            ),
        ),
        (
            "DOCTYPE Response",
            issued.replacen(
                "<samlp:Response",
                "<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><samlp:Response",
                1,
            ),
        ),
    ];
    for (name, xml) in response_attacks {
        assert!(
            inspect_saml_response_profile(&xml).is_err(),
            "{name} must be rejected"
        );
    }
    Ok(())
}
