//! Offline route regressions; only existing public test keys/certificates are used.
use super::*;
use crate::test_support::{TEST_SP_CERT_PEM as CERT, test_sp_cert_body};
use crate::xml::xml_escape_preserving_whitespace;
use axum::{body::Body, http::Request};
use qid_core::{
    config::SamlServiceProviderConfig,
    models::User,
    tenant::{RealmId, TenantId},
    test_helpers::test_config,
};
use tower::ServiceExt;

const A: &str = "https://a.example.com/saml";
const B: &str = "https://b.example.com/saml";
const LOCAL_EMAIL: &str = "local@example.com";
const FOREIGN_EMAIL: &str = "foreign@example.com";
const IDP: &str = "https://idp.example.com/test?x=1&y=\"issuer\"";
const ESCAPED_ID: &str = "local<&\"'id";
const ESCAPED_EMAIL: &str = "local+<&\"'@example.com";
const PRIVATE_NAME: &str = "Private Display Name";
const PRIVATE_ATTRIBUTE: &str = "private-attribute-value";

fn service_provider(
    entity_id: &str,
    certificate: String,
    release: &[&str],
) -> SamlServiceProviderConfig {
    SamlServiceProviderConfig {
        entity_id: entity_id.into(),
        signing_certificates: vec![certificate],
        attribute_release_policy: release.iter().map(|name| (*name).into()).collect(),
        ..Default::default()
    }
}

fn query(issuer: &str, subject: &str, format: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion"><soap:Body><p:AttributeQuery ID="_query" Version="2.0" IssueInstant="2026-10-17T00:00:00Z"><s:Issuer>{}</s:Issuer><!--SIGNATURE--><s:Subject><s:NameID Format="{}">{}</s:NameID></s:Subject></p:AttributeQuery></soap:Body></soap:Envelope>"#,
        xml_escape_preserving_whitespace(issuer),
        xml_escape_preserving_whitespace(format),
        xml_escape_preserving_whitespace(subject)
    )
}

fn sign(xml: &str) -> String {
    crate::test_support::sign_test_document(xml, "_query")
}

async fn post_query(app: &Router, realm: &str, xml: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/saml/{realm}/attribute-query"))
                .header(header::CONTENT_TYPE, "text/xml")
                .body(Body::from(xml.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 32_768)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn assert_no_attributes(body: &str) {
    for private in [
        LOCAL_EMAIL,
        FOREIGN_EMAIL,
        PRIVATE_NAME,
        "AttributeStatement",
        "AttributeValue",
        "local-id",
        "foreign-id",
        "_query",
        PRIVATE_ATTRIBUTE,
    ] {
        assert!(!body.contains(private), "failure leaked {private}");
    }
}

/// Inspect expanded names and direct children, not XML prefixes or substrings.
fn assert_attribute_result(
    body: &str,
    subject: &str,
    format: Option<&str>,
    expected_attributes: &[(&str, &str)],
) {
    const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
    const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    fn child<'a, 'input>(
        parent: roxmltree::Node<'a, 'input>,
        ns: &str,
        name: &str,
    ) -> roxmltree::Node<'a, 'input> {
        let children: Vec<_> = parent
            .children()
            .filter(|n| n.has_tag_name((ns, name)))
            .collect();
        assert_eq!(children.len(), 1, "expected one direct {name}");
        children[0]
    }
    let doc = roxmltree::Document::parse(body).unwrap();
    let envelope = doc.root_element();
    assert!(envelope.has_tag_name((SOAP, "Envelope")));
    let soap_body = child(envelope, SOAP, "Body");
    let response = child(soap_body, PROTOCOL, "Response");
    assert_eq!(response.attribute("InResponseTo"), Some("_query"));
    assert_eq!(child(response, SAML, "Issuer").text(), Some(IDP));
    let status = child(response, PROTOCOL, "Status");
    assert_eq!(
        child(status, PROTOCOL, "StatusCode").attribute("Value"),
        Some("urn:oasis:names:tc:SAML:2.0:status:Success")
    );
    let assertion = child(response, SAML, "Assertion");
    assert_eq!(child(assertion, SAML, "Issuer").text(), Some(IDP));
    let response_id = response.attribute("ID").unwrap();
    let assertion_id = assertion.attribute("ID").unwrap();
    assert_ne!(response_id, assertion_id);
    for node in [response, assertion] {
        let id = node.attribute("ID").unwrap();
        assert!(id.starts_with('_') && id.len() > 1);
        assert_eq!(node.attribute("Version"), Some("2.0"));
        let instant = node.attribute("IssueInstant").unwrap();
        assert!(instant.contains('T') && instant.ends_with('Z'));
        for name in ["ID", "Version", "IssueInstant"] {
            assert!(
                node.attributes()
                    .any(|a| a.name() == name && a.namespace().is_none())
            );
        }
        assert_eq!(
            doc.descendants()
                .filter(|n| n.attribute("ID") == Some(id))
                .count(),
            1
        );
    }
    let name_id = child(child(assertion, SAML, "Subject"), SAML, "NameID");
    assert_eq!(name_id.text(), Some(subject));
    assert_eq!(name_id.attribute("Format"), format);
    let statement = child(assertion, SAML, "AttributeStatement");
    // No bare AttributeStatement under Response, nor any extra result statements.
    assert_eq!(
        doc.descendants()
            .filter(|n| n.has_tag_name((SAML, "AttributeStatement")))
            .count(),
        1
    );
    let attributes: Vec<_> = statement.children().filter(|n| n.is_element()).collect();
    assert_eq!(attributes.len(), expected_attributes.len());
    assert_eq!(
        doc.descendants()
            .filter(|n| n.has_tag_name((SAML, "Attribute")))
            .count(),
        attributes.len()
    );
    for (attribute, (name, value)) in attributes.iter().zip(expected_attributes) {
        assert!(attribute.has_tag_name((SAML, "Attribute")));
        assert_eq!(attribute.attribute("Name"), Some(*name));
        assert_eq!(
            child(*attribute, SAML, "AttributeValue").text(),
            Some(*value)
        );
    }
    let display_name_released = expected_attributes.iter().any(|a| a.0 == "displayName");
    assert_eq!(body.contains(PRIVATE_NAME), display_name_released);
    assert_eq!(body.contains("displayName"), display_name_released);
    // These assertions remain unsigned; structure coverage is not XMLDSig validation.
    assert!(
        !doc.descendants()
            .any(|n| n.has_tag_name((crate::verification::DSIG_NS, "Signature")))
    );
}

async fn route_regressions<R: Repository>(repo: R) {
    for realm in ["test", "other"] {
        repo.create_realm(
            &TenantId::from("tenant-1"),
            &RealmId::from(realm),
            &format!("https://idp.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    for (id, realm, email) in [
        ("local-id", "test", LOCAL_EMAIL),
        ("foreign-id", "other", FOREIGN_EMAIL),
        (ESCAPED_ID, "test", ESCAPED_EMAIL),
    ] {
        repo.create_user(&User {
            id: id.into(),
            realm_id: realm.into(),
            email: Some(email.into()),
            email_verified: true,
            display_name: Some(PRIVATE_NAME.into()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
    // Exercise the narrow repository method directly as well as through HTTP.
    assert!(
        repo.get_user_by_id_in_realm(&RealmId::from("test"), "local-id")
            .await
            .unwrap()
            .is_some()
    );
    for id in ["foreign-id", "missing-id"] {
        assert!(
            repo.get_user_by_id_in_realm(&RealmId::from("test"), id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut config = test_config();
    config.realms[0].issuer = IDP.into();
    config.realms[0].protocols.saml.enabled = true;
    config.realms[0].protocols.saml.service_providers = vec![
        service_provider(A, CERT.into(), &["email"]),
        service_provider("https://all.example.com/saml", CERT.into(), &[]),
        service_provider(B, crate::tests::external_ec_cert(), &[]),
    ];
    let mut other = config.realms[0].clone();
    other.id = "other".into();
    for sp in &mut other.protocols.saml.service_providers {
        sp.signing_certificates = vec![crate::tests::external_ec_cert()];
    }
    config.realms.push(other);
    let mut disabled = config.realms[0].clone();
    disabled.id = "disabled".into();
    disabled.protocols.saml.enabled = false;
    config.realms.push(disabled);
    let state = Arc::new(
        SharedState::new(
            config,
            Arc::new(repo),
            Arc::new(super::tests::TestSigner),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let app = saml_routes::<R>().with_state(state);
    let unsigned = query(A, "local-id", crate::PERSISTENT_NAME_ID_FORMAT);
    let signed = sign(&unsigned);
    for format in [crate::PERSISTENT_NAME_ID_FORMAT, ""] {
        let (status, body) = post_query(&app, "test", &sign(&query(A, "local-id", format))).await;
        assert_eq!(status, StatusCode::OK);
        assert_attribute_result(&body, "local-id", Some(format), &[("email", LOCAL_EMAIL)]);
    }
    let without_format = unsigned.replace(
        &format!(" Format=\"{}\"", crate::PERSISTENT_NAME_ID_FORMAT),
        "",
    );
    let (status, body) = post_query(&app, "test", &sign(&without_format)).await;
    assert_eq!(status, StatusCode::OK);
    assert_attribute_result(&body, "local-id", None, &[("email", LOCAL_EMAIL)]);
    // Exact verified text (including whitespace) and an arbitrary Format must
    // survive XML escaping, without replacing the subject with a stored user ID.
    let escaped_subject = format!(" \t{ESCAPED_ID} \n\r");
    let escaped_format = "urn:example:format:<&\"'\t\n\r";
    let (status, body) = post_query(
        &app,
        "test",
        &sign(&query(A, &escaped_subject, escaped_format)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_attribute_result(
        &body,
        &escaped_subject,
        Some(escaped_format),
        &[("email", ESCAPED_EMAIL)],
    );
    let (status, body) = post_query(
        &app,
        "test",
        &sign(&query(
            "https://all.example.com/saml",
            "local-id",
            crate::PERSISTENT_NAME_ID_FORMAT,
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_attribute_result(
        &body,
        "local-id",
        Some(crate::PERSISTENT_NAME_ID_FORMAT),
        &[("email", LOCAL_EMAIL), ("displayName", PRIVATE_NAME)],
    );

    let (status, body) = post_query(
        &app,
        "test",
        &sign(&query(A, LOCAL_EMAIL, EMAIL_NAME_ID_FORMAT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_attribute_result(
        &body,
        LOCAL_EMAIL,
        Some(EMAIL_NAME_ID_FORMAT),
        &[("email", LOCAL_EMAIL)],
    );

    // KeyInfo is ignored even if it names a different certificate/key. Only
    // the configured RSA key may verify this request.
    let decoy_cert = crate::tests::external_ec_cert();
    let with_decoy_key = signed.replace(&test_sp_cert_body(), &decoy_cert);
    assert_eq!(
        post_query(&app, "test", &with_decoy_key).await.0,
        StatusCode::OK
    );
    let with_matching_key = signed.clone();
    // The same embedded certificate must not create trust in another realm.
    for (realm, xml) in [
        ("test", unsigned.replace("<!--SIGNATURE-->", "")),
        (
            "test",
            sign(&query(B, "local-id", crate::PERSISTENT_NAME_ID_FORMAT)),
        ),
        ("other", with_matching_key),
        ("test", signed.replace("local-id", "foreign-id")),
        (
            "test",
            format!(
                "<AttributeQuery><AttributeValue>{PRIVATE_ATTRIBUTE}</AttributeValue></AttributeQuery>"
            ),
        ),
    ] {
        let (status, body) = post_query(&app, realm, &xml).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("RequestDenied"));
        assert_no_attributes(&body);
    }
    for (subject, format) in [
        ("foreign-id", crate::PERSISTENT_NAME_ID_FORMAT),
        ("missing-id", crate::PERSISTENT_NAME_ID_FORMAT),
        (FOREIGN_EMAIL, EMAIL_NAME_ID_FORMAT),
        ("missing@example.com", EMAIL_NAME_ID_FORMAT),
    ] {
        let (status, body) = post_query(&app, "test", &sign(&query(A, subject, format))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("UnknownPrincipal"));
        assert_no_attributes(&body);
        assert!(!body.contains(subject));
    }
    for realm in ["disabled", "missing"] {
        let (status, body) = post_query(&app, realm, &signed).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_no_attributes(&body);
    }

    // Signatures remain cryptographically valid for the unsigned SOAP wrapper
    // mutations; preflight must reject these instead of using a descendant.
    let duplicate = "<p:AttributeQuery ID=\"_decoy\"><s:Issuer>decoy</s:Issuer></p:AttributeQuery>";
    for xml in [
        signed
            .replace("<soap:Body>", "<soap:Body><wrapper>")
            .replace("</soap:Body>", "</wrapper></soap:Body>"),
        signed.replace("</soap:Body>", &format!("{duplicate}</soap:Body>")),
        signed.replace("</soap:Envelope>", "<soap:Body/></soap:Envelope>"),
        signed.replace(
            "<soap:Body>",
            &format!("<soap:Header>{duplicate}</soap:Header><soap:Body>"),
        ),
        signed.replace(
            "http://schemas.xmlsoap.org/soap/envelope/",
            "http://www.w3.org/2003/05/soap-envelope",
        ),
        signed.replace("<soap:Body>", "<soap:Body Id=\"_query\">"),
        signed.replace("URI=\"#_query\"", "URI=\"#_decoy\""),
        sign(&unsigned.replace(
            "</s:Subject>",
            "</s:Subject><s:Subject><s:NameID>foreign-id</s:NameID></s:Subject>",
        )),
        sign(&unsigned.replace("</s:Issuer>", "</s:Issuer><s:Issuer>decoy</s:Issuer>")),
        sign(&unsigned.replace("</s:NameID>", "</s:NameID><s:NameID>foreign-id</s:NameID>")),
        sign(&unsigned.replace(
            "</p:AttributeQuery>",
            "<s:Attribute Name=\"email\"/></p:AttributeQuery>",
        )),
    ] {
        let (status, body) = post_query(&app, "test", &xml).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_no_attributes(&body);
    }
}

#[tokio::test]
async fn attribute_query_file_route_regressions() {
    let directory = tempfile::tempdir().unwrap();
    let repo =
        qid_storage::FileRepository::new(directory.path().join("store.json").to_str().unwrap())
            .await
            .unwrap();
    repo.migrate().await.unwrap();
    route_regressions(repo).await;
}

#[tokio::test]
async fn attribute_query_sql_route_regressions() {
    let directory = tempfile::tempdir().unwrap();
    let repo = qid_storage::SqlRepository::connect(&format!(
        "sqlite:{}",
        directory.path().join("store.db").display()
    ))
    .await
    .unwrap();
    repo.migrate().await.unwrap();
    route_regressions(repo).await;
}
