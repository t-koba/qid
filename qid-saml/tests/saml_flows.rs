#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::{Engine, engine::general_purpose::STANDARD};
use qid_saml::{
    EMAIL_NAME_ID_FORMAT, SamlAssertionRequest, SamlPostBindingForm, SamlRelayStatePolicy,
    SamlSubject, SamlXmlSignatureAlgorithm, build_assertion_request_from_authn,
    build_saml_response, import_sp_metadata, inspect_saml_authn_request,
    inspect_saml_response_profile, parse_post_binding_authn_request, sign_saml_element_with_key,
    validate_authn_request_for_sp,
};

const TEST_SP_CERT_PEM: &str = include_str!("data/test-sp.crt");
const TEST_SP_KEY_PEM: &str = include_str!("data/test-sp.key");
const SIGNATURE_PLACEHOLDER: &str = "<!--SIGNATURE-->";

fn test_sp_cert_body() -> String {
    TEST_SP_CERT_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .trim()
        .to_string()
}

fn sp_metadata() -> String {
    format!(
        r#"
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
  <md:SPSSODescriptor WantAssertionsSigned="true">
    <md:NameIDFormat>{EMAIL_NAME_ID_FORMAT}</md:NameIDFormat>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        test_sp_cert_body()
    )
}

fn sign_saml_test_document(document_xml: &str, element_id: &str) -> anyhow::Result<String> {
    let mut signature = sign_saml_element_with_key(
        document_xml,
        element_id,
        SamlXmlSignatureAlgorithm::RsaSha256,
        TEST_SP_KEY_PEM.as_bytes(),
    )?;
    let keyinfo = format!(
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        test_sp_cert_body()
    );
    let insertion = format!("{keyinfo}<ds:SignatureValue");
    if let Some(pos) = signature.find("<ds:SignatureValue") {
        let mut out = String::with_capacity(signature.len() + keyinfo.len());
        out.push_str(&signature[..pos]);
        out.push_str(&insertion);
        out.push_str(&signature[pos..]);
        signature = out;
    }
    Ok(document_xml.replace(SIGNATURE_PLACEHOLDER, &signature))
}

fn signed_authn_request_xml() -> anyhow::Result<String> {
    let unsigned = r##"
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="req-123" Version="2.0" Destination="https://idp.example.com/saml/corp/sso" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://sp.example.com/acs" ForceAuthn="true">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <!--SIGNATURE-->
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>
"##;
    sign_saml_test_document(unsigned, "req-123")
}

fn response_xml(request: &SamlAssertionRequest) -> anyhow::Result<String> {
    Ok(build_saml_response(request)?.xml)
}

#[test]
fn sp_metadata_authn_request_and_response_round_trip() -> anyhow::Result<()> {
    let sp = import_sp_metadata(&sp_metadata())?;
    assert_eq!(sp.entity_id, "https://sp.example.com/metadata");
    assert_eq!(sp.acs_url, "https://sp.example.com/acs");
    assert_eq!(sp.name_id_formats, vec![EMAIL_NAME_ID_FORMAT]);
    assert_eq!(sp.signing_certificates, vec![test_sp_cert_body()]);
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

    let issued = response_xml(&SamlAssertionRequest {
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
    })?;
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
