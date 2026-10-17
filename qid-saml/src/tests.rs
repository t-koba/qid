use super::*;
use crate::routes::{extract_cookie, is_active_session_for_realm};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use qid_core::config::SamlServiceProviderConfig;
use qid_core::models::{Session, User};

pub(crate) use crate::test_support::sign_saml_test_document;
pub(crate) fn external_ec_cert() -> String {
    roxmltree::Document::parse(include_str!(
        "../tests/fixtures/vgi-saml-signed-response-ecdsa.xml"
    ))
    .unwrap()
    .descendants()
    .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate")))
    .unwrap()
    .text()
    .unwrap()
    .split_whitespace()
    .collect()
}
use crate::test_support::{
    TEST_SP_CERT_PEM, TEST_SP_KEY_PEM, sign_test_document, test_sp_cert_body,
};

pub(crate) fn assert_bad_request<T>(result: Result<T, QidError>) {
    assert!(matches!(result, Err(QidError::BadRequest { .. })));
}
pub(crate) fn assert_bad_request_with_context<T: std::fmt::Debug>(
    result: Result<T, QidError>,
    context: &str,
) {
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "{context}: {result:?}"
    );
}

fn assert_xsw_rejected(xml: &str, context: &str) {
    assert_bad_request_with_context(inspect_xml_signature_profile(xml, "AuthnRequest"), context);
}

fn test_session(acr: Option<&str>, amr: &[&str]) -> Session {
    Session {
        id: "sid-1".to_string(),
        realm_id: "corp".to_string(),
        user_id: "user-1".to_string(),
        auth_time: 1_000,
        acr: acr.map(str::to_string),
        amr: amr.iter().map(|method| (*method).to_string()).collect(),
        idle_expires_at: qid_core::util::now_seconds() + 300,
        absolute_expires_at: qid_core::util::now_seconds() + 3_600,
        revoked: false,
        created_at: 1_000,
        cnf: None,
    }
}

fn test_subject(display_name: Option<&str>, groups: &[&str]) -> SamlSubject {
    SamlSubject {
        user_id: "user-1".to_string(),
        email: Some("alice@example.com".to_string()),
        display_name: display_name.map(str::to_string),
        groups: groups.iter().map(|group| (*group).to_string()).collect(),
    }
}

fn test_assertion_request(
    sp: &SamlServiceProviderMetadata,
    subject: SamlSubject,
) -> SamlAssertionRequest {
    SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: Some("req-123".to_string()),
        subject,
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    }
}

fn assert_bearer_rejected(assertion: &str, audience: &str, now: u64) {
    assert_bad_request(validate_saml_bearer_assertion(
        assertion,
        audience,
        now,
        60,
        &[TEST_SP_CERT_PEM.to_string()],
    ));
}

fn assert_authn_request_rejected(xml: &str, sp: &SamlServiceProviderMetadata) {
    let request = inspect_saml_authn_request(xml, None).unwrap();
    assert_bad_request(validate_authn_request_for_sp(
        &request,
        sp,
        Some("https://idp.example.com/saml/corp/sso"),
    ));
}

fn assert_authn_signature_rejected(xml: &str, sp: &SamlServiceProviderMetadata) {
    let request = inspect_saml_authn_request(xml, None).unwrap();
    assert_bad_request(validate_authn_request_signature_profile(&request, sp));
}

fn assert_logout_request_rejected(xml: &str, sp: &SamlServiceProviderMetadata) {
    let request = inspect_saml_logout_request(xml, None).unwrap();
    assert_bad_request(validate_logout_request_for_sp(
        &request,
        sp,
        Some("https://idp.example.com/saml/corp/slo"),
    ));
}

fn sp_metadata() -> String {
    let cert_body = test_sp_cert_body();
    let raw = include_str!("../tests/fixtures/sp-metadata-test.xml");
    raw.replace("CERT_BODY_PLACEHOLDER", &cert_body)
}

fn authn_request_xml() -> String {
    sign_test_document(
        include_str!("../tests/fixtures/authn-request-test.xml"),
        "req-123",
    )
}

fn logout_request_xml() -> String {
    sign_test_document(
        include_str!("../tests/fixtures/logout-request-test.xml"),
        "logout-123",
    )
}

fn unsigned_bearer_assertion() -> &'static str {
    include_str!("../tests/fixtures/unsigned-bearer-assertion-test.xml")
}

fn sign_bearer_assertion(unsigned: &str) -> String {
    crate::test_support::sign_test_document(unsigned, "assert-bearer-regression")
}

#[test]
fn imports_sp_metadata_and_rejects_sha1() {
    let imported = import_sp_metadata(&sp_metadata()).unwrap();
    assert_eq!(imported.entity_id, "https://sp.example.com/metadata");
    assert_eq!(imported.acs_url, "https://sp.example.com/acs");
    assert_eq!(
        imported.slo_url.as_deref(),
        Some("https://sp.example.com/slo")
    );
    assert_eq!(imported.name_id_formats, vec![EMAIL_NAME_ID_FORMAT]);
    assert_eq!(
        imported.entity_categories,
        vec!["http://refeds.org/category/research-and-scholarship"]
    );
    assert_eq!(imported.signing_certificates, vec![test_sp_cert_body()]);
    assert_eq!(imported.encryption_certificates, vec![test_sp_cert_body()]);
    assert!(imported.want_assertions_signed);

    let insecure = sp_metadata().replace(
            "</md:SPSSODescriptor>",
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></md:SPSSODescriptor>"#,
        );
    assert_bad_request(import_sp_metadata(&insecure));
}

#[test]
fn imports_federation_metadata_aggregate_entity_categories_and_rollover_keys() {
    let rollover_metadata = sp_metadata()
            .replace(
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">"#,
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://rollover.example.com/metadata">"#,
            )
            .replace(
                "https://sp.example.com/acs",
                "https://rollover.example.com/acs",
            )
            .replace(
                "https://sp.example.com/slo",
                "https://rollover.example.com/slo",
            )
            .replace(
                "</md:KeyDescriptor>",
                "</md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIBnextsigningcertificate</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
            );
    let aggregate = include_str!("../tests/fixtures/entities-descriptor-test.xml")
        .replace("{first}", &sp_metadata())
        .replace("{rollover}", &rollover_metadata)
        .replace("{duplicate}", &sp_metadata());

    let imported = import_sp_metadata_aggregate(&aggregate).unwrap();

    assert_eq!(imported.service_providers.len(), 2);
    assert_eq!(
        imported.duplicate_entity_ids,
        vec!["https://sp.example.com/metadata"]
    );
    assert_eq!(
        imported.rollover_entity_ids,
        vec!["https://rollover.example.com/metadata"]
    );
    assert_eq!(
        imported.entity_category_index["http://refeds.org/category/research-and-scholarship"],
        vec![
            "https://sp.example.com/metadata".to_string(),
            "https://rollover.example.com/metadata".to_string()
        ]
    );
    assert_eq!(imported.rejected[0].reason, "duplicate_entity_id");
}

#[test]
fn builds_sp_metadata_from_static_config() {
    let configured = service_provider_from_config(&SamlServiceProviderConfig {
        entity_id: "https://sp.example.com/metadata".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        slo_url: Some("https://sp.example.com/slo".to_string()),
        name_id_formats: vec![EMAIL_NAME_ID_FORMAT.to_string()],
        attribute_release_policy: vec![],
        signing_certificates: vec![test_sp_cert_body()],
        encryption_certificates: vec![test_sp_cert_body()],
        want_assertions_signed: true,
    });
    assert_eq!(configured.entity_id, "https://sp.example.com/metadata");
    assert_eq!(configured.acs_url, "https://sp.example.com/acs");
    assert_eq!(
        configured.slo_url.as_deref(),
        Some("https://sp.example.com/slo")
    );
    assert_eq!(configured.name_id_formats, vec![EMAIL_NAME_ID_FORMAT]);
    assert_eq!(configured.signing_certificates, vec![test_sp_cert_body()]);
    assert_eq!(
        configured.encryption_certificates,
        vec![test_sp_cert_body()]
    );
    assert!(configured.want_assertions_signed);
}

#[test]
fn parses_post_binding_authn_request_and_validates_sp() {
    let form = SamlPostBindingForm {
        saml_request: STANDARD.encode(authn_request_xml()),
        relay_state: Some("/app/home".to_string()),
    };
    let req = parse_post_binding_authn_request(&form, &SamlRelayStatePolicy::default()).unwrap();
    assert_eq!(req.id, "req-123");
    assert_eq!(req.issuer, "https://sp.example.com/metadata");
    assert_eq!(
        req.assertion_consumer_service_url.as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(
        req.destination.as_deref(),
        Some("https://idp.example.com/saml/corp/sso")
    );
    assert_eq!(
        req.protocol_binding.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    );
    assert_eq!(
        req.name_id_policy_format.as_deref(),
        Some(EMAIL_NAME_ID_FORMAT)
    );
    assert!(req.force_authn);
    assert!(!req.is_passive);
    assert_eq!(req.relay_state.as_deref(), Some("/app/home"));

    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    validate_authn_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/sso"))
        .unwrap();
    let signature = validate_authn_request_signature_profile(&req, &sp).unwrap();
    assert_eq!(signature.reference_uri.as_deref(), Some("#req-123"));
    assert_eq!(
        signature.signing_certificate.as_deref(),
        Some(test_sp_cert_body().as_str())
    );
}

#[test]
fn authn_request_validation_rejects_unsafe_or_mismatched_inputs() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let invalid_relay = SamlPostBindingForm {
        saml_request: STANDARD.encode(authn_request_xml()),
        relay_state: Some("https://evil.example".to_string()),
    };
    assert_bad_request(parse_post_binding_authn_request(
        &invalid_relay,
        &SamlRelayStatePolicy::default(),
    ));

    let bad_binding = authn_request_xml().replace(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    );
    assert_authn_request_rejected(&bad_binding, &sp);

    let bad_acs = authn_request_xml().replace(
        "https://sp.example.com/acs",
        "https://sp.example.com/other-acs",
    );
    assert_authn_request_rejected(&bad_acs, &sp);

    let duplicate = authn_request_xml().replace(
        "</samlp:AuthnRequest>",
        "<samlp:AuthnRequest ID=\"req-456\"></samlp:AuthnRequest></samlp:AuthnRequest>",
    );
    assert_bad_request(inspect_saml_authn_request(&duplicate, None));
}

#[test]
fn authn_request_signature_profile_is_fail_closed() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let signed = authn_request_xml();
    let stripped = signed.replacen("<ds:Signature", "<ds:XSignature", 1);
    let mut stripped = stripped.replacen("</ds:Signature>", "</ds:XSignature>", 1);
    if let Some(pos) = stripped.find("</ds:XSignature>") {
        stripped.replace_range(pos..pos + "</ds:XSignature>".len(), "");
    }
    assert_authn_signature_rejected(&stripped, &sp);

    let wrong_reference = authn_request_xml().replace("URI=\"#req-123\"", "URI=\"#other\"");
    assert_authn_signature_rejected(&wrong_reference, &sp);

    let untrusted_cert =
        authn_request_xml().replace(&test_sp_cert_body()[..18], "MIIBuntrustedcertif");
    assert_authn_signature_rejected(&untrusted_cert, &sp);

    let insecure_digest =
        authn_request_xml().replace("http://www.w3.org/2001/04/xmlenc#sha256", "md5");
    assert_bad_request(inspect_saml_authn_request(&insecure_digest, None));

    let insecure_signature =
        authn_request_xml().replace("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "md5");
    assert_bad_request(inspect_saml_authn_request(&insecure_signature, None));
}

#[test]
fn parses_and_validates_logout_request() {
    let form = SamlPostBindingForm {
        saml_request: STANDARD.encode(logout_request_xml()),
        relay_state: Some("/app/logout".to_string()),
    };
    let req = parse_post_binding_logout_request(&form, &SamlRelayStatePolicy::default()).unwrap();
    assert_eq!(req.id, "logout-123");
    assert_eq!(req.issuer, "https://sp.example.com/metadata");
    assert_eq!(
        req.destination.as_deref(),
        Some("https://idp.example.com/saml/corp/slo")
    );
    assert_eq!(req.name_id.as_deref(), Some("alice@example.com"));
    assert_eq!(req.session_indexes, vec!["sid-1"]);
    assert_eq!(req.relay_state.as_deref(), Some("/app/logout"));

    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let profile =
        validate_logout_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/slo"))
            .unwrap();
    assert_eq!(profile.reference_uri.as_deref(), Some("#logout-123"));
    assert_eq!(
        profile.signing_certificate.as_deref(),
        Some(test_sp_cert_body().as_str())
    );
}

#[test]
fn builds_logout_response_and_post_binding_form() {
    let issued = build_saml_logout_response(
        "https://idp.example.com/realms/corp",
        "https://sp.example.com/slo",
        "logout-123",
        1_000,
    )
    .unwrap();
    assert!(issued.response_id.starts_with("logout_resp_"));
    assert_eq!(issued.in_response_to, "logout-123");
    assert_eq!(issued.destination, "https://sp.example.com/slo");
    assert!(issued.xml.contains("<samlp:LogoutResponse"));
    assert!(
        issued
            .xml
            .contains("Destination=\"https://sp.example.com/slo\"")
    );
    assert!(issued.xml.contains("InResponseTo=\"logout-123\""));
    assert!(
        issued
            .xml
            .contains("urn:oasis:names:tc:SAML:2.0:status:Success")
    );

    let post =
        build_saml_logout_post_response(&issued, "https://sp.example.com/slo", Some("/done"));
    assert_eq!(post.acs_url, "https://sp.example.com/slo");
    assert_eq!(post.relay_state.as_deref(), Some("/done"));
    assert!(post.html.contains("name=\"SAMLResponse\""));
    assert!(post.html.contains("name=\"RelayState\""));
    let decoded = STANDARD.decode(post.saml_response.as_bytes()).unwrap();
    let decoded = String::from_utf8(decoded).unwrap();
    assert_eq!(decoded, issued.xml);

    assert_bad_request(build_saml_logout_response(
        "https://idp.example.com/realms/corp",
        "",
        "logout-123",
        1_000,
    ));
}

#[test]
fn logout_request_validation_is_fail_closed() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let wrong_destination = logout_request_xml().replace(
        "https://idp.example.com/saml/corp/slo",
        "https://idp.example.com/saml/other/slo",
    );
    assert_logout_request_rejected(&wrong_destination, &sp);

    let wrong_reference = logout_request_xml().replace("URI=\"#logout-123\"", "URI=\"#other\"");
    assert_logout_request_rejected(&wrong_reference, &sp);

    let untrusted_cert =
        logout_request_xml().replace(&test_sp_cert_body()[..18], "MIIBuntrustedcertif");
    assert_logout_request_rejected(&untrusted_cert, &sp);

    let duplicate = logout_request_xml().replace(
        "</samlp:LogoutRequest>",
        "<samlp:LogoutRequest ID=\"logout-456\"></samlp:LogoutRequest></samlp:LogoutRequest>",
    );
    assert_bad_request(inspect_saml_logout_request(&duplicate, None));
}

#[test]
fn builds_assertion_request_from_valid_authn_request() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let req = inspect_saml_authn_request(&authn_request_xml(), None).unwrap();
    let assertion_req = build_assertion_request_from_authn(
        &req,
        &sp,
        "https://idp.example.com/realms/corp",
        test_subject(None, &[]),
        1_000,
        300,
        Some("session-1".to_string()),
    )
    .unwrap();
    assert_eq!(assertion_req.request_id.as_deref(), Some("req-123"));
    assert_eq!(assertion_req.sp_entity_id, sp.entity_id);
    assert_eq!(assertion_req.acs_url, sp.acs_url);
    assert_eq!(assertion_req.name_id_format, EMAIL_NAME_ID_FORMAT);
    assert_eq!(assertion_req.not_on_or_after, 1_300);
    let issued = build_saml_response(&assertion_req).unwrap();
    assert!(issued.xml.contains("InResponseTo=\"req-123\""));
    assert!(issued.xml.contains("SessionIndex=\"session-1\""));
}

#[test]
fn builds_subject_and_post_response_from_browser_session() {
    let browser_subject = SamlBrowserSubject {
        session: test_session(Some("urn:qid:acr:password"), &["pwd"]),
        user: User {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            display_name: Some("Alice Example".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        },
    };
    assert!(is_active_session_for_realm(
        &browser_subject.session,
        "corp"
    ));
    let subject = subject_from_browser_session(&browser_subject);
    assert_eq!(subject.user_id, "user-1");
    assert_eq!(subject.email.as_deref(), Some("alice@example.com"));
    assert_eq!(subject.display_name.as_deref(), Some("Alice Example"));

    let issued = SamlIssuedResponse {
        response_id: "resp-1".to_string(),
        assertion_id: "assert-1".to_string(),
        xml: "<samlp:Response/>".to_string(),
    };
    let post = build_saml_post_response(&issued, "https://sp.example.com/acs", Some("/app/home"));
    assert_eq!(post.acs_url, "https://sp.example.com/acs");
    assert_eq!(post.relay_state.as_deref(), Some("/app/home"));
    assert!(post.html.contains("name=\"SAMLResponse\""));
    assert!(post.html.contains("name=\"RelayState\""));
    assert!(post.html.contains("document.forms[0].submit()"));
}

#[test]
fn cookie_and_session_checks_are_strict() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "other=x; qid_session=sid-1; theme=light".parse().unwrap(),
    );
    assert_eq!(
        extract_cookie(&headers, "qid_session").as_deref(),
        Some("sid-1")
    );
    assert!(extract_cookie(&headers, "missing").is_none());

    let mut session = test_session(None, &[]);
    assert!(is_active_session_for_realm(&session, "corp"));
    assert!(!is_active_session_for_realm(&session, "other"));
    session.revoked = true;
    assert!(!is_active_session_for_realm(&session, "corp"));
}

#[test]
fn validates_relay_state_policy() {
    let policy = SamlRelayStatePolicy {
        max_len: 16,
        allowed_prefixes: vec!["/app".to_string()],
    };
    validate_relay_state(Some("/app/home"), &policy).unwrap();
    assert_bad_request(validate_relay_state(Some("https://evil.example"), &policy));
    assert_bad_request(validate_relay_state(Some("/app/home\nx"), &policy));
}

#[test]
fn inspects_response_profile_and_rejects_wrapping_shapes() {
    let response = include_str!("../tests/fixtures/response-profile-test.xml");
    let profile = inspect_saml_response_profile(response).unwrap();
    assert_eq!(profile.response_id.as_deref(), Some("resp1"));
    assert_eq!(profile.assertion_ids, vec!["assert1"]);
    assert_eq!(profile.in_response_to.as_deref(), Some("req1"));

    let duplicate_id = response.replace("ID=\"assert1\"", "ID=\"resp1\"");
    assert_bad_request(inspect_saml_response_profile(&duplicate_id));

    let multiple_assertions = response.replace(
            "</samlp:Response>",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert2"/></samlp:Response>"#,
        );
    assert_bad_request(inspect_saml_response_profile(&multiple_assertions));
}

#[test]
fn validates_saml_bearer_assertion_profile() {
    let now = 1_700_000_000;
    let unsigned = include_str!("../tests/fixtures/bearer-assertion-profile-test.xml")
        .replace("{now}", &now.to_string());
    let assertion = crate::test_support::sign_test_document(&unsigned, "assert-bearer-1");
    let validated = validate_saml_bearer_assertion(
        &assertion,
        "https://id.example.com/oauth2/token",
        now,
        60,
        &[TEST_SP_CERT_PEM.to_string()],
    )
    .expect("SAML bearer assertion should validate");
    assert_eq!(validated.name_id.value, "subject@example.com");
    assert_eq!(validated.issuer, "https://issuer.example.com");
    assert_eq!(validated.expires_at, 1_700_000_300);
    assert_eq!(validated.auth_time, Some(now));

    assert_bearer_rejected(&assertion, "https://other.example.com/token", now);

    let conflicting_unsigned = unsigned.replace(
        "</saml:AudienceRestriction>",
        "</saml:AudienceRestriction>\n    <saml:AudienceRestriction><saml:Audience>https://other.example.com/audience</saml:Audience></saml:AudienceRestriction>",
    );
    let conflicting_assertion =
        crate::test_support::sign_test_document(&conflicting_unsigned, "assert-bearer-1");
    assert_bearer_rejected(
        &conflicting_assertion,
        "https://id.example.com/oauth2/token",
        now,
    );
}

#[test]
fn rejects_empty_saml_bearer_issuer_and_subject() {
    let assertion = unsigned_bearer_assertion();
    let unsigned_variants = [
        assertion.replace(
            "<saml:Issuer>https://issuer.example.com</saml:Issuer>",
            "<saml:Issuer> </saml:Issuer>",
        ),
        assertion.replace(
            "<saml:NameID>subject@example.com</saml:NameID>",
            "<saml:NameID> </saml:NameID>",
        ),
    ];

    for unsigned in unsigned_variants {
        let signed = sign_bearer_assertion(&unsigned);
        assert_bearer_rejected(
            &signed,
            "https://id.example.com/oauth2/token",
            1_700_000_000,
        );
    }
}

#[test]
fn rejects_unsupported_saml_bearer_condition() {
    for condition in ["<saml:Condition/>", "<saml:OneTimeUse/>"] {
        let unsigned = unsigned_bearer_assertion().replace(
            "</saml:Conditions>",
            &format!("{condition}</saml:Conditions>"),
        );
        let assertion = sign_bearer_assertion(&unsigned);
        assert_bearer_rejected(
            &assertion,
            "https://id.example.com/oauth2/token",
            1_700_000_000,
        );
    }
}

#[test]
fn rejects_duplicate_saml_bearer_conditions_with_expired_second_element() {
    let unsigned = unsigned_bearer_assertion().replace(
        "</saml:Assertion>",
        "<saml:Conditions NotOnOrAfter=\"1600000000\"><saml:AudienceRestriction><saml:Audience>https://id.example.com/oauth2/token</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>",
    );
    let assertion = sign_bearer_assertion(&unsigned);
    assert_bearer_rejected(
        &assertion,
        "https://id.example.com/oauth2/token",
        1_700_000_000,
    );
}

#[test]
fn rejects_saml_bearer_subject_confirmation_data_not_before() {
    let unsigned = unsigned_bearer_assertion().replace(
        "Recipient=\"https://id.example.com/oauth2/token\"",
        "Recipient=\"https://id.example.com/oauth2/token\" NotBefore=\"1699999990\"",
    );
    let assertion = sign_bearer_assertion(&unsigned);
    assert_bearer_rejected(
        &assertion,
        "https://id.example.com/oauth2/token",
        1_700_000_000,
    );
}

#[test]
fn selects_name_id_and_builds_saml_response() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let name_id_format = select_name_id_format(&sp, Some(EMAIL_NAME_ID_FORMAT));
    assert_eq!(name_id_format, EMAIL_NAME_ID_FORMAT);
    let mut request = test_assertion_request(
        &sp,
        test_subject(Some("Alice <Example>"), &["engineering", "admins"]),
    );
    request.name_id_format = name_id_format;
    request.session_index = Some("session-1".to_string());
    let issued = build_saml_response(&request).unwrap();

    let profile = inspect_saml_response_profile(&issued.xml).unwrap();
    assert_eq!(
        profile.response_id.as_deref(),
        Some(issued.response_id.as_str())
    );
    assert_eq!(profile.assertion_ids, vec![issued.assertion_id.clone()]);
    assert_eq!(profile.destination.as_deref(), Some(sp.acs_url.as_str()));
    assert!(
        issued
            .xml
            .contains("<saml:Audience>https://sp.example.com/metadata</saml:Audience>")
    );
    assert!(
        issued
            .xml
            .contains("Recipient=\"https://sp.example.com/acs\"")
    );
    assert!(issued.xml.contains("InResponseTo=\"req-123\""));
    assert!(issued.xml.contains("alice@example.com"));
    assert!(issued.xml.contains("Alice &lt;Example&gt;"));
    assert!(issued.xml.contains("<saml:Attribute Name=\"groups\">"));
}

#[test]
fn persistent_name_id_uses_stable_subject_id_and_rejects_missing_email() {
    let subject = SamlSubject {
        user_id: "user-stable".to_string(),
        email: None,
        display_name: None,
        groups: vec![],
    };
    assert_eq!(
        name_id_value(&subject, PERSISTENT_NAME_ID_FORMAT).unwrap(),
        "user-stable"
    );
    assert_bad_request(name_id_value(&subject, EMAIL_NAME_ID_FORMAT));
}

#[test]
fn plans_response_and_assertion_signatures() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let request = test_assertion_request(&sp, test_subject(None, &[]));
    let issued = build_saml_response(&request).unwrap();

    let plan = plan_saml_signatures(
        &issued,
        &sp,
        &SamlSigningPolicy {
            sign_response: true,
            sign_assertion: false,
        },
    )
    .unwrap();
    assert_eq!(
        plan.targets,
        vec![
            SamlSignatureTarget::Assertion,
            SamlSignatureTarget::Response
        ]
    );
    assert_eq!(
        plan.response_reference,
        Some(format!("#{}", issued.response_id))
    );
    assert_eq!(
        plan.assertion_reference,
        Some(format!("#{}", issued.assertion_id))
    );
}

#[test]
fn signature_plan_rejects_unsigned_saml_response_policy() {
    let mut sp = import_sp_metadata(&sp_metadata()).unwrap();
    sp.signing_certificates.clear();
    sp.encryption_certificates.clear();
    sp.want_assertions_signed = false;
    let mut request = test_assertion_request(&sp, test_subject(None, &[]));
    request.request_id = None;
    let issued = build_saml_response(&request).unwrap();
    assert_bad_request(plan_saml_signatures(
        &issued,
        &sp,
        &SamlSigningPolicy {
            sign_response: false,
            sign_assertion: false,
        },
    ));
}

#[test]
fn plans_and_applies_encrypted_assertion() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let request = test_assertion_request(&sp, test_subject(None, &[]));
    let issued = build_saml_response(&request).unwrap();

    let plan = plan_saml_encryption(
        &issued,
        &sp,
        &SamlEncryptionPolicy {
            encrypt_assertion: true,
        },
    )
    .unwrap()
    .expect("encryption plan");
    assert_eq!(plan.assertion_id, issued.assertion_id);
    assert_eq!(plan.recipient_entity_id, sp.entity_id);
    assert_eq!(plan.encryption_certificate, test_sp_cert_body());

    let encrypted = apply_encrypted_assertion(
            &issued,
            "<saml:EncryptedAssertion><xenc:EncryptedData>cipher</xenc:EncryptedData></saml:EncryptedAssertion>",
        )
        .unwrap();
    assert!(encrypted.xml.contains("<saml:EncryptedAssertion>"));
    assert!(!encrypted.xml.contains("<saml:Assertion ID="));
    let profile = inspect_saml_response_profile(&encrypted.xml).unwrap();
    assert!(profile.assertion_ids.is_empty());
}

#[test]
fn encryption_plan_rejects_missing_sp_certificate() {
    let mut sp = import_sp_metadata(&sp_metadata()).unwrap();
    sp.encryption_certificates.clear();
    let mut request = test_assertion_request(&sp, test_subject(None, &[]));
    request.request_id = None;
    let issued = build_saml_response(&request).unwrap();

    assert_bad_request(plan_saml_encryption(
        &issued,
        &sp,
        &SamlEncryptionPolicy {
            encrypt_assertion: true,
        },
    ));
    assert_eq!(
        plan_saml_encryption(
            &issued,
            &sp,
            &SamlEncryptionPolicy {
                encrypt_assertion: false,
            }
        )
        .unwrap(),
        None
    );
}

#[test]
fn encrypt_decrypt_assertion_xml_roundtrip() {
    let assertion_xml = include_str!("../tests/fixtures/assertion-encryption-test.xml");

    let cert_body = test_sp_cert_body();
    let encrypted = encrypt_assertion_xml(assertion_xml, &cert_body).unwrap();
    assert!(encrypted.contains("EncryptedAssertion"));
    assert!(!encrypted.contains("Assertion ID="));

    let decrypted = decrypt_assertion_xml(&encrypted, TEST_SP_KEY_PEM.as_bytes()).unwrap();
    assert_eq!(decrypted, assertion_xml);
}

#[test]
fn decrypt_assertion_xml_rejects_bad_key() {
    let assertion_xml = r#"<saml:Assertion ID="a1"/>"#;
    let cert_body = test_sp_cert_body();
    let encrypted = encrypt_assertion_xml(assertion_xml, &cert_body).unwrap();

    let wrong_key = "-----BEGIN PRIVATE KEY-----\nMIIBvAIBADANBgkqhkiG9w0BAQEFAASCBaUwggGhAgEAAQH/AAAAAQIDBAUGBwgJ\nCgsMDQ4P\n-----END PRIVATE KEY-----\n";
    assert!(matches!(
        decrypt_assertion_xml(&encrypted, wrong_key.as_bytes()),
        Err(QidError::Crypto { .. })
    ));
}

#[test]
fn decrypt_assertion_xml_rejects_garbage_xml() {
    assert_bad_request(decrypt_assertion_xml(
        "<not-encrypted/>",
        TEST_SP_KEY_PEM.as_bytes(),
    ));
}

#[test]
fn encrypt_decrypt_saml_response_roundtrip() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let mut request = test_assertion_request(&sp, test_subject(None, &[]));
    request.request_id = Some("req-1".to_string());
    let issued = build_saml_response(&request).unwrap();

    let encrypted = encrypt_saml_response(&issued, &test_sp_cert_body()).unwrap();
    assert!(encrypted.xml.contains("EncryptedAssertion"));
    assert!(!encrypted.xml.contains("<saml:Assertion ID="));

    let decrypted = decrypt_saml_response(&encrypted.xml, TEST_SP_KEY_PEM.as_bytes()).unwrap();
    let profile = inspect_saml_response_profile(&decrypted).unwrap();
    assert_eq!(profile.assertion_ids, vec![issued.assertion_id]);
    assert!(decrypted.contains("<saml:Assertion ID="));
    assert!(!decrypted.contains("EncryptedAssertion"));
}

// ---------------------------------------------------------------------------
// XSW (XML Signature Wrapping) attack corpus
// ---------------------------------------------------------------------------

fn xsw_valid_signed_element() -> String {
    include_str!("../tests/fixtures/xsw-authn-request-test.xml").to_string()
}

#[test]
fn xsw_rejects_multiple_signatures() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>",
        "</ds:Signature>\n  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n    <ds:SignedInfo>\n      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n      <ds:Reference URI=\"#req-123\">\n        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n      </ds:Reference>\n    </ds:SignedInfo>\n  </ds:Signature>",
    );
    assert_xsw_rejected(&xml, "multiple Signature elements must be rejected");
}

#[test]
fn xsw_rejects_forbidden_sibling_assertion() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>\n</samlp:AuthnRequest>",
        "</ds:Signature>\n  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>\n</samlp:AuthnRequest>",
    );
    assert_xsw_rejected(&xml, "forbidden sibling Assertion must be rejected");
}

#[test]
fn xsw_rejects_forbidden_sibling_extensions() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>\n</samlp:AuthnRequest>",
        "</ds:Signature>\n  <samlp:Extensions/>\n</samlp:AuthnRequest>",
    );
    assert_xsw_rejected(&xml, "forbidden sibling Extensions must be rejected");
}

#[test]
fn xsw_rejects_reference_uri_mismatch() {
    let xml = xsw_valid_signed_element().replace("#req-123", "#other");
    assert_xsw_rejected(&xml, "Reference URI mismatch must be rejected");
}

#[test]
fn xsw_comment_is_rejected_before_tag_scanning() {
    let xml = xsw_valid_signed_element().replace(
        "<ds:Signature",
        "<!-- hidden attacker payload --><ds:Signature",
    );
    assert_xsw_rejected(&xml, "comment before Signature must be rejected");
}

#[test]
fn xsw_doctype_is_rejected_before_tag_scanning() {
    let xml = xsw_valid_signed_element().replacen(
        "<samlp:AuthnRequest",
        "<!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<samlp:AuthnRequest",
        1,
    );
    assert_xsw_rejected(&xml, "DOCTYPE must be rejected");
}

#[test]
fn xsw_cdata_does_not_confuse_tag_scanning() {
    // CDATA sections must be transparent to the tag scanner.
    let xml =
        xsw_valid_signed_element().replace("<ds:Signature", "<![CDATA[<fake>]]><ds:Signature");
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        result.is_ok(),
        "CDATA before Signature must not break scanning: {:?}",
        result
    );
    let profile = result.unwrap();
    assert_eq!(profile.reference_uri.as_deref(), Some("#req-123"));
}

#[test]
fn xsw_namespace_prefix_trick_does_not_bypass_sibling_check() {
    // Using a different namespace prefix that resolves to the same namespace
    // must still be rejected by the forbidden-sibling check.
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>\n</samlp:AuthnRequest>",
        "</ds:Signature>\n  <pfx:Assertion xmlns:pfx=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>\n</samlp:AuthnRequest>",
    );
    assert_xsw_rejected(
        &xml,
        "namespace-prefixed forbidden sibling must be rejected",
    );
}
