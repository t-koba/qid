use super::*;
use crate::routes::{extract_cookie, is_active_session_for_realm};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use qid_core::config::SamlServiceProviderConfig;
use qid_core::models::{Session, User};

const TEST_SP_CERT_PEM: &str = include_str!("../tests/data/test-sp.crt");
const TEST_SP_KEY_PEM: &str = include_str!("../tests/data/test-sp.key");
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
    let cert_body = test_sp_cert_body();
    let raw = r#"
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
  <md:Extensions>
    <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
      <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="http://macedir.org/entity-category">
        <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor WantAssertionsSigned="true">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>
          CERT_BODY_PLACEHOLDER
        </ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>
          CERT_BODY_PLACEHOLDER
        </ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/slo"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#;
    raw.replace("CERT_BODY_PLACEHOLDER", &cert_body)
}

fn sign_saml_test_document(
    document_xml: &str,
    element_id: &str,
    key_pem: &[u8],
    cert_body: &str,
) -> String {
    use crate::xmldsig::{SamlXmlSignatureAlgorithm, sign_saml_element_with_key};
    let mut signature = sign_saml_element_with_key(
        document_xml,
        element_id,
        SamlXmlSignatureAlgorithm::RsaSha256,
        key_pem,
    )
    .expect("test SAML document must sign successfully");
    let keyinfo = format!(
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
    );
    let insertion = format!("{keyinfo}<ds:SignatureValue");
    if let Some(pos) = signature.find("<ds:SignatureValue") {
        let mut out = String::with_capacity(signature.len() + keyinfo.len());
        out.push_str(&signature[..pos]);
        out.push_str(&insertion);
        out.push_str(&signature[pos..]);
        signature = out;
    }
    document_xml.replace(SIGNATURE_PLACEHOLDER, &signature)
}

fn authn_request_xml() -> String {
    let unsigned = r##"
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="req-123" Version="2.0" Destination="https://idp.example.com/saml/corp/sso" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://sp.example.com/acs" ForceAuthn="true">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <!--SIGNATURE-->
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>
"##
    .to_string();
    sign_saml_test_document(
        &unsigned,
        "req-123",
        TEST_SP_KEY_PEM.as_bytes(),
        &test_sp_cert_body(),
    )
}

fn logout_request_xml() -> String {
    let unsigned = r##"
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="logout-123" Version="2.0" Destination="https://idp.example.com/saml/corp/slo">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <!--SIGNATURE-->
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
  <samlp:SessionIndex>sid-1</samlp:SessionIndex>
</samlp:LogoutRequest>
"##
    .to_string();
    sign_saml_test_document(
        &unsigned,
        "logout-123",
        TEST_SP_KEY_PEM.as_bytes(),
        &test_sp_cert_body(),
    )
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
    assert!(matches!(
        import_sp_metadata(&insecure),
        Err(QidError::BadRequest { .. })
    ));
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
    let aggregate = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
{}
{}
{}
</md:EntitiesDescriptor>"#,
        sp_metadata(),
        rollover_metadata,
        sp_metadata()
    );

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
    assert!(matches!(
        parse_post_binding_authn_request(&invalid_relay, &SamlRelayStatePolicy::default()),
        Err(QidError::BadRequest { .. })
    ));

    let bad_binding = authn_request_xml().replace(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    );
    let req = inspect_saml_authn_request(&bad_binding, None).unwrap();
    assert!(matches!(
        validate_authn_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/sso")),
        Err(QidError::BadRequest { .. })
    ));

    let bad_acs = authn_request_xml().replace(
        "https://sp.example.com/acs",
        "https://sp.example.com/other-acs",
    );
    let req = inspect_saml_authn_request(&bad_acs, None).unwrap();
    assert!(matches!(
        validate_authn_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/sso")),
        Err(QidError::BadRequest { .. })
    ));

    let duplicate = authn_request_xml().replace(
        "</samlp:AuthnRequest>",
        "<samlp:AuthnRequest ID=\"req-456\"></samlp:AuthnRequest></samlp:AuthnRequest>",
    );
    assert!(matches!(
        inspect_saml_authn_request(&duplicate, None),
        Err(QidError::BadRequest { .. })
    ));
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
    let req = inspect_saml_authn_request(&stripped, None).unwrap();
    assert!(matches!(
        validate_authn_request_signature_profile(&req, &sp),
        Err(QidError::BadRequest { .. })
    ));

    let wrong_reference = authn_request_xml().replace("URI=\"#req-123\"", "URI=\"#other\"");
    let req = inspect_saml_authn_request(&wrong_reference, None).unwrap();
    assert!(matches!(
        validate_authn_request_signature_profile(&req, &sp),
        Err(QidError::BadRequest { .. })
    ));

    let untrusted_cert =
        authn_request_xml().replace(&test_sp_cert_body()[..18], "MIIBuntrustedcertif");
    let req = inspect_saml_authn_request(&untrusted_cert, None).unwrap();
    assert!(matches!(
        validate_authn_request_signature_profile(&req, &sp),
        Err(QidError::BadRequest { .. })
    ));

    let insecure_digest =
        authn_request_xml().replace("http://www.w3.org/2001/04/xmlenc#sha256", "md5");
    assert!(matches!(
        inspect_saml_authn_request(&insecure_digest, None),
        Err(QidError::BadRequest { .. })
    ));

    let insecure_signature =
        authn_request_xml().replace("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "md5");
    assert!(matches!(
        inspect_saml_authn_request(&insecure_signature, None),
        Err(QidError::BadRequest { .. })
    ));
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

    assert!(matches!(
        build_saml_logout_response(
            "https://idp.example.com/realms/corp",
            "",
            "logout-123",
            1_000
        ),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn logout_request_validation_is_fail_closed() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let wrong_destination = logout_request_xml().replace(
        "https://idp.example.com/saml/corp/slo",
        "https://idp.example.com/saml/other/slo",
    );
    let req = inspect_saml_logout_request(&wrong_destination, None).unwrap();
    assert!(matches!(
        validate_logout_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/slo")),
        Err(QidError::BadRequest { .. })
    ));

    let wrong_reference = logout_request_xml().replace("URI=\"#logout-123\"", "URI=\"#other\"");
    let req = inspect_saml_logout_request(&wrong_reference, None).unwrap();
    assert!(matches!(
        validate_logout_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/slo")),
        Err(QidError::BadRequest { .. })
    ));

    let untrusted_cert =
        logout_request_xml().replace(&test_sp_cert_body()[..18], "MIIBuntrustedcertif");
    let req = inspect_saml_logout_request(&untrusted_cert, None).unwrap();
    assert!(matches!(
        validate_logout_request_for_sp(&req, &sp, Some("https://idp.example.com/saml/corp/slo")),
        Err(QidError::BadRequest { .. })
    ));

    let duplicate = logout_request_xml().replace(
        "</samlp:LogoutRequest>",
        "<samlp:LogoutRequest ID=\"logout-456\"></samlp:LogoutRequest></samlp:LogoutRequest>",
    );
    assert!(matches!(
        inspect_saml_logout_request(&duplicate, None),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn builds_assertion_request_from_valid_authn_request() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let req = inspect_saml_authn_request(&authn_request_xml(), None).unwrap();
    let assertion_req = build_assertion_request_from_authn(
        &req,
        &sp,
        "https://idp.example.com/realms/corp",
        SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
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
        session: Session {
            id: "sid-1".to_string(),
            realm_id: "corp".to_string(),
            user_id: "user-1".to_string(),
            auth_time: 1_000,
            acr: Some("urn:qid:acr:password".to_string()),
            amr: vec!["pwd".to_string()],
            idle_expires_at: qid_core::util::now_seconds() + 300,
            absolute_expires_at: qid_core::util::now_seconds() + 3_600,
            revoked: false,
            created_at: 1_000,
            cnf: None,
        },
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

    let mut session = Session {
        id: "sid-1".to_string(),
        realm_id: "corp".to_string(),
        user_id: "user-1".to_string(),
        auth_time: 1_000,
        acr: None,
        amr: vec![],
        idle_expires_at: qid_core::util::now_seconds() + 300,
        absolute_expires_at: qid_core::util::now_seconds() + 3_600,
        revoked: false,
        created_at: 1_000,
        cnf: None,
    };
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
    assert!(matches!(
        validate_relay_state(Some("https://evil.example"), &policy),
        Err(QidError::BadRequest { .. })
    ));
    assert!(matches!(
        validate_relay_state(Some("/app/home\nx"), &policy),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn inspects_response_profile_and_rejects_wrapping_shapes() {
    let response = r#"
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp1" Destination="https://idp.example.com/saml/corp/sso" InResponseTo="req1">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert1"/>
</samlp:Response>
"#;
    let profile = inspect_saml_response_profile(response).unwrap();
    assert_eq!(profile.response_id.as_deref(), Some("resp1"));
    assert_eq!(profile.assertion_ids, vec!["assert1"]);
    assert_eq!(profile.in_response_to.as_deref(), Some("req1"));

    let duplicate_id = response.replace("ID=\"assert1\"", "ID=\"resp1\"");
    assert!(matches!(
        inspect_saml_response_profile(&duplicate_id),
        Err(QidError::BadRequest { .. })
    ));

    let multiple_assertions = response.replace(
            "</samlp:Response>",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert2"/></samlp:Response>"#,
        );
    assert!(matches!(
        inspect_saml_response_profile(&multiple_assertions),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn validates_saml_bearer_assertion_profile() {
    let now = 1_700_000_000;
    let unsigned = format!(
        r##"
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="assert-bearer-1" Version="2.0" IssueInstant="{now}">
  <saml:Issuer>https://issuer.example.com</saml:Issuer>
  <!--SIGNATURE-->
  <saml:Subject>
    <saml:NameID>subject@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData Recipient="https://id.example.com/oauth2/token" NotOnOrAfter="1700000300"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300">
    <saml:AudienceRestriction><saml:Audience>https://id.example.com/oauth2/token</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{now}"/>
</saml:Assertion>
"##
    );
    let assertion = sign_saml_test_document(
        &unsigned,
        "assert-bearer-1",
        TEST_SP_KEY_PEM.as_bytes(),
        &test_sp_cert_body(),
    );
    let validated =
        validate_saml_bearer_assertion(&assertion, "https://id.example.com/oauth2/token", now, 60)
            .expect("SAML bearer assertion should validate");
    assert_eq!(validated.subject, "subject@example.com");
    assert_eq!(validated.issuer, "https://issuer.example.com");
    assert_eq!(validated.expires_at, 1_700_000_300);
    assert_eq!(validated.auth_time, Some(now));

    assert!(matches!(
        validate_saml_bearer_assertion(&assertion, "https://other.example.com/token", now, 60),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn selects_name_id_and_builds_saml_response() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let name_id_format = select_name_id_format(&sp, Some(EMAIL_NAME_ID_FORMAT));
    assert_eq!(name_id_format, EMAIL_NAME_ID_FORMAT);
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: Some("req-123".to_string()),
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice <Example>".to_string()),
            groups: vec!["engineering".to_string(), "admins".to_string()],
        },
        name_id_format,
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: Some("session-1".to_string()),
        attribute_release_policy: Vec::new(),
    })
    .unwrap();

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
    assert!(matches!(
        name_id_value(&subject, EMAIL_NAME_ID_FORMAT),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn plans_and_applies_response_and_assertion_signatures() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: Some("req-123".to_string()),
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })
    .unwrap();

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
            SamlSignatureTarget::Response,
            SamlSignatureTarget::Assertion
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

    let signed = apply_saml_signatures(
        &issued,
        &[
            SamlDetachedSignature {
                target: SamlSignatureTarget::Response,
                xml: "<ds:Signature><ds:SignedInfo/></ds:Signature>".to_string(),
            },
            SamlDetachedSignature {
                target: SamlSignatureTarget::Assertion,
                xml: "<ds:Signature><ds:SignedInfo/></ds:Signature>".to_string(),
            },
        ],
    )
    .unwrap();
    let response_signature = signed
        .xml
        .find("<saml:Issuer>https://idp.example.com/realms/corp</saml:Issuer><ds:Signature>")
        .expect("response signature follows response issuer");
    let assertion_signature = signed
        .xml
        .find("<saml:Assertion")
        .and_then(|start| {
            signed.xml[start..]
                .find(
                    "<saml:Issuer>https://idp.example.com/realms/corp</saml:Issuer><ds:Signature>",
                )
                .map(|pos| start + pos)
        })
        .expect("assertion signature follows assertion issuer");
    assert!(assertion_signature > response_signature);
    inspect_saml_response_profile(&signed.xml).unwrap();
}

#[test]
fn signature_plan_rejects_unsigned_saml_response_policy() {
    let sp = SamlServiceProviderMetadata {
        entity_id: "https://sp.example.com/metadata".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        slo_url: None,
        name_id_formats: vec![EMAIL_NAME_ID_FORMAT.to_string()],
        attribute_release_policy: vec![],
        signing_certificates: vec![],
        encryption_certificates: vec![],
        want_assertions_signed: false,
        entity_categories: Vec::new(),
    };
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: None,
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })
    .unwrap();
    assert!(matches!(
        plan_saml_signatures(
            &issued,
            &sp,
            &SamlSigningPolicy {
                sign_response: false,
                sign_assertion: false,
            }
        ),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn plans_and_applies_encrypted_assertion() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: Some("req-123".to_string()),
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })
    .unwrap();

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
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: None,
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })
    .unwrap();

    assert!(matches!(
        plan_saml_encryption(
            &issued,
            &sp,
            &SamlEncryptionPolicy {
                encrypt_assertion: true,
            }
        ),
        Err(QidError::BadRequest { .. })
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
    let assertion_xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert-1" Version="2.0" IssueInstant="1000">
  <saml:Issuer>https://idp.example.com/realms/corp</saml:Issuer>
  <saml:Subject>
    <saml:NameID>alice@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>"#;

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
    assert!(matches!(
        decrypt_assertion_xml("<not-encrypted/>", TEST_SP_KEY_PEM.as_bytes()),
        Err(QidError::BadRequest { .. })
    ));
}

#[test]
fn encrypt_decrypt_saml_response_roundtrip() {
    let sp = import_sp_metadata(&sp_metadata()).unwrap();
    let issued = build_saml_response(&SamlAssertionRequest {
        issuer: "https://idp.example.com/realms/corp".to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: sp.acs_url.clone(),
        request_id: Some("req-1".to_string()),
        subject: SamlSubject {
            user_id: "user-1".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            groups: vec![],
        },
        name_id_format: EMAIL_NAME_ID_FORMAT.to_string(),
        issued_at: 1_000,
        not_on_or_after: 1_300,
        session_index: None,
        attribute_release_policy: Vec::new(),
    })
    .unwrap();

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
    r##"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="req-123">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#req-123">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</samlp:AuthnRequest>"##
        .to_string()
}

#[test]
fn xsw_rejects_multiple_signatures() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>",
        "</ds:Signature>\n  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n    <ds:SignedInfo>\n      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n      <ds:Reference URI=\"#req-123\">\n        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n      </ds:Reference>\n    </ds:SignedInfo>\n  </ds:Signature>",
    );
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "multiple Signature elements must be rejected: {:?}",
        result
    );
}

#[test]
fn xsw_rejects_forbidden_sibling_assertion() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>\n</samlp:AuthnRequest>",
        "</ds:Signature>\n  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"fake\"/>\n</samlp:AuthnRequest>",
    );
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "forbidden sibling Assertion must be rejected: {:?}",
        result
    );
}

#[test]
fn xsw_rejects_forbidden_sibling_extensions() {
    let xml = xsw_valid_signed_element().replace(
        "</ds:Signature>\n</samlp:AuthnRequest>",
        "</ds:Signature>\n  <samlp:Extensions/>\n</samlp:AuthnRequest>",
    );
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "forbidden sibling Extensions must be rejected: {:?}",
        result
    );
}

#[test]
fn xsw_rejects_reference_uri_mismatch() {
    let xml = xsw_valid_signed_element().replace("#req-123", "#other");
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "Reference URI mismatch must be rejected: {:?}",
        result
    );
}

#[test]
fn xsw_comment_does_not_confuse_tag_scanning() {
    // Comments <!-- ... --> must be transparent to the tag scanner.
    let xml = xsw_valid_signed_element().replace(
        "<ds:Signature",
        "<!-- hidden attacker payload --><ds:Signature",
    );
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        result.is_ok(),
        "comment before Signature must not break scanning: {:?}",
        result
    );
    // Check that the Reference URI is still correctly extracted.
    let profile = result.unwrap();
    assert_eq!(profile.reference_uri.as_deref(), Some("#req-123"));
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
    let result = inspect_xml_signature_profile(&xml, "AuthnRequest");
    assert!(
        matches!(result, Err(QidError::BadRequest { .. })),
        "namespace-prefixed forbidden sibling must be rejected: {:?}",
        result
    );
}
