//! ArtifactResolve regressions using only the existing public test key.
use super::*;
use crate::test_support::{TEST_SP_CERT_PEM, sign_test_document};
use crate::xml::xml_escape_preserving_whitespace as escape;
use axum::{body::Body, http::Request};
use qid_core::{config::SamlServiceProviderConfig, test_helpers::test_config};
use tower::ServiceExt;

const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const P: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const S: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const A: &str = "https://a.example.com/saml";
const B: &str = "https://b.example.com/saml";
const IDP: &str = "https://idp.example.com/?x=<&\"'\t\n\r";
const RESPONSE: &str = r#"<samlp:Response ID="_private-response"/>"#;
const DEST: &str = "https://id.example.com/saml/test/artifact";

fn query(issuer: &str, artifact: &str) -> String {
    format!(
        r#"<env:Envelope xmlns:env="{SOAP}" xmlns:p="{P}" xmlns:s="{S}"><env:Body><p:ArtifactResolve ID="_resolve" Version="2.0" IssueInstant="2026-10-18T00:00:00Z"><s:Issuer>{}</s:Issuer><!--SIGNATURE--><p:Artifact>{}</p:Artifact></p:ArtifactResolve></env:Body></env:Envelope>"#,
        escape(issuer),
        escape(artifact)
    )
}

fn sign(xml: &str) -> String {
    sign_test_document(xml, "_resolve")
}

async fn post(app: &Router, realm: &str, xml: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/saml/{realm}/artifact"))
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

fn assert_result(body: &str, success: bool, correlation: &str) {
    let doc = roxmltree::Document::parse(body).unwrap();
    assert!(doc.root_element().has_tag_name((SOAP, "Envelope")));
    let response = doc
        .descendants()
        .find(|n| n.has_tag_name((P, "ArtifactResponse")))
        .unwrap();
    assert_eq!(response.attribute("InResponseTo"), Some(correlation));
    assert_eq!(
        response
            .children()
            .find(|n| n.has_tag_name((S, "Issuer")))
            .unwrap()
            .text(),
        Some(IDP)
    );
    let code = doc
        .descendants()
        .find(|n| n.has_tag_name((P, "StatusCode")))
        .unwrap();
    assert_eq!(
        code.attribute("Value"),
        Some(if success {
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        } else {
            "urn:oasis:names:tc:SAML:2.0:status:Requester"
        })
    );
    assert_eq!(body.contains("_private-response"), success);
}

async fn recover_once(app: &Router, artifact: &str) {
    let signed = sign(&query(A, artifact));
    let (status, body) = post(app, "test", &signed).await;
    assert_eq!(status, StatusCode::OK);
    assert_result(&body, true, "_resolve");
    let (status, body) = post(app, "test", &signed).await;
    assert_eq!(status, StatusCode::OK);
    assert_result(&body, false, "_resolve");
}

fn store() -> String {
    crate::artifact::store_artifact(RESPONSE, 300, "test", A)
        .unwrap()
        .artifact
}

#[tokio::test]
async fn artifact_authentication_binding_and_soap_regressions() {
    let directory = tempfile::tempdir().unwrap();
    let repo =
        qid_storage::FileRepository::new(directory.path().join("store.json").to_str().unwrap())
            .await
            .unwrap();
    let mut config = test_config();
    let realm = &mut config.realms[0];
    realm.issuer = IDP.into();
    realm.protocols.saml.enabled = true;
    realm.protocols.saml.service_providers = vec![
        SamlServiceProviderConfig {
            entity_id: A.into(),
            // Try every configured cert, including a non-matching/invalid one.
            signing_certificates: vec![
                "invalid certificate".into(),
                crate::tests::external_ec_cert(),
                TEST_SP_CERT_PEM.into(),
            ],
            ..Default::default()
        },
        // Sharing a key must not make a verified Issuer interchangeable.
        SamlServiceProviderConfig {
            entity_id: B.into(),
            signing_certificates: vec![TEST_SP_CERT_PEM.into()],
            ..Default::default()
        },
    ];
    for name in ["other", "untrusted", "no-certs", "no-sps"] {
        let mut other = config.realms[0].clone();
        other.id = name.into();
        if name == "untrusted" {
            for sp in &mut other.protocols.saml.service_providers {
                sp.signing_certificates = vec![crate::tests::external_ec_cert()];
            }
        } else if name == "no-certs" {
            for sp in &mut other.protocols.saml.service_providers {
                sp.signing_certificates.clear();
            }
        } else if name == "no-sps" {
            other.protocols.saml.service_providers.clear();
        }
        config.realms.push(other);
    }
    let state = Arc::new(
        SharedState::new(
            config,
            Arc::new(repo),
            Arc::new(super::tests::TestSigner),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let app = saml_routes::<qid_storage::FileRepository>().with_state(state);

    // Valid intended SP, single use, and certificate rollover all work.
    recover_once(&app, &store()).await;
    // A correctly signed request without KeyInfo still uses the configured key.
    let artifact = store();
    let signed = sign(&query(A, &artifact));
    let key_info_start = signed.find("<ds:KeyInfo>").unwrap();
    let key_info_end = signed.find("</ds:KeyInfo>").unwrap() + "</ds:KeyInfo>".len();
    let without_key_info = format!("{}{}", &signed[..key_info_start], &signed[key_info_end..]);
    let (status, body) = post(&app, "test", &without_key_info).await;
    assert_eq!(status, StatusCode::OK);
    assert_result(&body, true, "_resolve");

    // Each rejected attempt leaves its artifact available to the intended SP.
    for (realm, issuer, signed, expected_status, correlation) in [
        ("test", A, false, StatusCode::UNAUTHORIZED, ""),
        (
            "test",
            " https://a.example.com/saml ",
            true,
            StatusCode::UNAUTHORIZED,
            "",
        ),
        ("untrusted", A, true, StatusCode::UNAUTHORIZED, ""),
        ("no-certs", A, true, StatusCode::UNAUTHORIZED, ""),
        ("no-sps", A, true, StatusCode::UNAUTHORIZED, ""),
        (
            "test",
            "https://unknown.example.com/",
            true,
            StatusCode::UNAUTHORIZED,
            "",
        ),
        // An authenticated SP with the same key is still the wrong recipient.
        ("test", B, true, StatusCode::OK, "_resolve"),
        // Same trusted SP/key, but the stored artifact belongs to another realm.
        ("other", A, true, StatusCode::OK, "_resolve"),
    ] {
        let artifact = store();
        let xml = query(issuer, &artifact);
        let xml = if signed {
            sign(&xml)
        } else {
            xml.replace("<!--SIGNATURE-->", "")
        };
        let (status, body) = post(&app, realm, &xml).await;
        assert_eq!(status, expected_status, "{realm} {issuer}");
        assert_result(&body, false, correlation);
        recover_once(&app, &artifact).await;
    }

    // Trusting a key for B cannot authorize a request signed with it as A.
    let artifact = store();
    let mut providers = vec![SamlServiceProviderConfig {
        entity_id: B.into(),
        signing_certificates: vec![TEST_SP_CERT_PEM.into()],
        ..Default::default()
    }];
    assert!(
        crate::artifact::authenticate_artifact_resolve(
            &sign(&query(A, &artifact)),
            &providers,
            DEST
        )
        .is_err()
    );
    providers[0].entity_id = A.into();
    assert!(
        crate::artifact::authenticate_artifact_resolve(
            &sign(&query(A, &artifact)),
            &providers,
            DEST
        )
        .is_ok()
    );
    recover_once(&app, &artifact).await;

    // Prefixes are immaterial, including a default protocol namespace and
    // single-quoted attributes; namespace URI and structure are what matter.
    let artifact = store();
    let xml = query(A, &artifact)
        .replace("<p:", "<")
        .replace("</p:", "</")
        .replace(&format!("xmlns:p=\"{P}\""), &format!("xmlns=\"{P}\""))
        .replace('"', "'");
    let (status, body) = post(&app, "test", &sign(&xml)).await;
    assert_eq!(status, StatusCode::OK);
    assert_result(&body, true, "_resolve");

    // Valid signatures over invalid SOAP/claim structures must not be enough.
    // Re-sign each mutated document so failures are structural, not just digest
    // mismatches. The final recovery proves that rejection did not burn it.
    let artifact = store();
    let xml = query(A, &artifact);
    let issuer = format!("<s:Issuer>{A}</s:Issuer>");
    let art = format!("<p:Artifact>{artifact}</p:Artifact>");
    let target_start = xml.find("<p:ArtifactResolve ").unwrap();
    let target_end = xml.find("</p:ArtifactResolve>").unwrap() + "</p:ArtifactResolve>".len();
    for invalid in [
        xml.replace(SOAP, "urn:wrong-soap"),
        xml.replace(P, "urn:wrong-protocol"),
        xml.replace(S, "urn:wrong-assertion"),
        xml[target_start..target_end].to_owned().replace(
            "<p:ArtifactResolve ",
            &format!("<p:ArtifactResolve xmlns:p=\"{P}\" xmlns:s=\"{S}\" "),
        ),
        xml.replace("<env:Body>", "<env:Body><env:Body>")
            .replace("</env:Body>", "</env:Body></env:Body>"),
        xml.replace("</env:Body>", "</env:Body><env:Body/>"),
        xml.replace(
            "</env:Body>",
            "<p:ArtifactResolve ID=\"_decoy\"/></env:Body>",
        ),
        xml.replace("<env:Body>", "<env:Body><p:Extensions>")
            .replace("</env:Body>", "</p:Extensions></env:Body>"),
        xml.replace(&issuer, ""),
        xml.replace(&issuer, &format!("{issuer}{issuer}")),
        xml.replace(&issuer, &format!("<p:Extensions>{issuer}</p:Extensions>")),
        xml.replace(&issuer, "<s:Issuer><s:NameID>nested</s:NameID></s:Issuer>"),
        xml.replace(&art, ""),
        xml.replace(&art, &format!("{art}{art}")),
        xml.replace(&art, &format!("<p:Extensions>{art}</p:Extensions>")),
        xml.replace(
            &art,
            "<p:Artifact><p:Artifact>nested</p:Artifact></p:Artifact>",
        ),
    ] {
        let (status, body) = post(&app, "test", &sign(&invalid)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "accepted: {invalid}");
        assert_result(&body, false, "");
    }
    // Tampered signed claims and malformed XML also fail closed.
    for invalid in [sign(&xml).replace(A, B), "<env:Envelope".into()] {
        let (status, body) = post(&app, "test", &invalid).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_result(&body, false, "");
    }
    recover_once(&app, &artifact).await;

    // Optional SOAP Header: empty or ordinary headers are ignored, while
    // mandatory blocks addressed here are rejected. Each success consumes its
    // own artifact; failures below share one artifact and recover afterwards.
    for header in [
        "<env:Header/>",
        "<env:Header><note xmlns=\"urn:example\">hello</note></env:Header>",
        "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"0\">hi</note></env:Header>",
        "<env:Header><note xmlns=\"urn:example\" mustUnderstand=\"1\" actor=\"https://other.example.com/\">hi</note></env:Header>",
        "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"1\" env:actor=\"https://other.example.com/\">hi</note></env:Header>",
    ] {
        let artifact = store();
        let with_header = query(A, &artifact).replace("<env:Body>", &format!("{header}<env:Body>"));
        let (status, body) = post(&app, "test", &sign(&with_header)).await;
        assert_eq!(status, StatusCode::OK, "header accepted: {with_header}");
        assert_result(&body, true, "_resolve");
    }
    let artifact = store();
    let xml = query(A, &artifact);
    for rejected in [
        xml.replace(
            "<env:Body>",
            "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"1\" actor=\"https://other.example.com/\">hi</note></env:Header><env:Body>",
        ),
        xml.replace(
            "<env:Body>",
            "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"1\">hi</note></env:Header><env:Body>",
        ),
        xml.replace(
            "<env:Body>",
            "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"true\" env:actor=\"http://schemas.xmlsoap.org/soap/actor/next\">hi</note></env:Header><env:Body>",
        ),
        xml.replace(
            "<env:Body>",
            &format!(
                "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"1\" env:actor=\"{DEST}\">hi</note></env:Header><env:Body>"
            ),
        ),
        xml.replace(
            "<env:Body>",
            "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"2\">hi</note></env:Header><env:Body>",
        ),
        xml.replace(
            "<env:Body>",
            "<env:Header><note xmlns=\"urn:example\" env:mustUnderstand=\"maybe\">hi</note></env:Header><env:Body>",
        ),
        xml.replace("<env:Body>", "<env:Header/><env:Header/><env:Body>"),
        xml.replace("</env:Envelope>", "<env:Header/><env:Body/></env:Envelope>"),
    ] {
        let (status, body) = post(&app, "test", &sign(&rejected)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "header rejected: {rejected}");
        assert_result(&body, false, "");
    }
    recover_once(&app, &artifact).await;

    // One direct samlp:Extensions child is signed and ignored; a second one or
    // any other unexpected direct child is rejected.
    let artifact = store();
    let xml = query(A, &artifact);
    let with_extensions = xml.replace(
        "<!--SIGNATURE-->",
        "<p:Extensions><custom:Data xmlns:custom=\"urn:example\">ignored</custom:Data></p:Extensions><!--SIGNATURE-->",
    );
    let (status, body) = post(&app, "test", &sign(&with_extensions)).await;
    assert_eq!(status, StatusCode::OK);
    assert_result(&body, true, "_resolve");
    let artifact = store();
    let xml = query(A, &artifact);
    for rejected in [
        xml.replace(
            "<!--SIGNATURE-->",
            "<p:Extensions><a xmlns=\"urn:x\">1</a></p:Extensions><p:Extensions><b xmlns=\"urn:x\">2</b></p:Extensions><!--SIGNATURE-->",
        ),
        xml.replace(
            "<!--SIGNATURE-->",
            "<p:Status xmlns:p=\"urn:oasis:names:tc:SAML:2.0:protocol\"/><!--SIGNATURE-->",
        ),
    ] {
        let (status, body) = post(&app, "test", &sign(&rejected)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "extensions: {rejected}");
        assert_result(&body, false, "");
    }
    recover_once(&app, &artifact).await;

    // Version, IssueInstant and Destination: Destination absent or exactly the
    // configured external endpoint URL succeeds; anything else fails closed.
    let artifact = store();
    let xml = query(A, &artifact);
    for accepted in [
        xml.replace(
            "IssueInstant=\"2026-10-18T00:00:00Z\"",
            "IssueInstant=\"2026-10-18T00:00:00.123Z\"",
        ),
        xml.replace(
            "IssueInstant=\"2026-10-18T00:00:00Z\"",
            "IssueInstant=\"2026-10-18T00:00:00+09:00\"",
        ),
        xml.replace(
            "<p:ArtifactResolve ",
            &format!("<p:ArtifactResolve Destination=\"{DEST}\" "),
        ),
    ] {
        let fresh = store();
        let replay = accepted.replace(&artifact, &fresh);
        let (status, body) = post(&app, "test", &sign(&replay)).await;
        assert_eq!(status, StatusCode::OK, "fields accepted: {replay}");
        assert_result(&body, true, "_resolve");
    }
    let artifact = store();
    let xml = query(A, &artifact);
    for rejected in [
        xml.replace("Version=\"2.0\"", "Version=\"1.0\""),
        xml.replace(" Version=\"2.0\"", ""),
        xml.replace("IssueInstant=\"2026-10-18T00:00:00Z\"", ""),
        xml.replace(
            "IssueInstant=\"2026-10-18T00:00:00Z\"",
            "IssueInstant=\"not-a-time\"",
        ),
        xml.replace(
            "IssueInstant=\"2026-10-18T00:00:00Z\"",
            "IssueInstant=\"2026-13-01T00:00:00Z\"",
        ),
        xml.replace(
            "<p:ArtifactResolve ",
            "<p:ArtifactResolve Destination=\"https://evil.example/artifact\" ",
        ),
        xml.replace(
            "<p:ArtifactResolve ",
            "<p:ArtifactResolve Destination=\"https://id.example.com/saml/other/artifact\" ",
        ),
    ] {
        let (status, body) = post(&app, "test", &sign(&rejected)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "fields rejected: {rejected}"
        );
        assert_result(&body, false, "");
    }
    recover_once(&app, &artifact).await;
}

#[test]
fn artifact_response_values_are_escaped_and_roundtrip() {
    let id = "_request<&\"'\t\n\r";
    let error = "error: <injected attr=\"bad\">&'\t\n\r";
    for xml in [
        crate::artifact::build_artifact_response(id, IDP, RESPONSE),
        artifact_error_soap(id, IDP, error.into()),
    ] {
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let response = doc
            .descendants()
            .find(|n| n.has_tag_name((P, "ArtifactResponse")))
            .unwrap();
        assert_eq!(response.attribute("InResponseTo"), Some(id));
        assert_eq!(
            response
                .children()
                .find(|n| n.has_tag_name((S, "Issuer")))
                .unwrap()
                .text(),
            Some(IDP)
        );
        if let Some(message) = doc
            .descendants()
            .find(|n| n.has_tag_name((P, "StatusMessage")))
        {
            assert_eq!(message.text(), Some(error));
            assert!(!message.children().any(|n| n.is_element()));
        }
        assert!(!xml.contains("<injected"));
    }
}
