//! SAML 2.0 Attribute Query protocol (SOAP-based).
//!
//! Allows SPs to query user attributes from the IdP outside of an SSO
//! assertion, as defined in SAML 2.0 Core §3.3.

use qid_core::error::{QidError, QidResult};

pub(crate) struct ParsedAttributeQuery {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
}

/// Parse a SAML `<AttributeQuery>` from raw SOAP XML.
pub(crate) fn parse_attribute_query(soap_body: &str) -> QidResult<ParsedAttributeQuery> {
    let (_, query_tag) = soap_body
        .split_once("<samlp:AttributeQuery")
        .ok_or_else(|| QidError::BadRequest {
            message: "missing samlp:AttributeQuery element".to_string(),
        })?;
    let id = query_tag
        .split_once("ID=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(id, _)| id.to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "missing AttributeQuery ID".to_string(),
        })?;
    let (body, _) = query_tag
        .split_once("</samlp:AttributeQuery>")
        .ok_or_else(|| QidError::BadRequest {
            message: "unclosed samlp:AttributeQuery element".to_string(),
        })?;
    let issuer = body
        .split_once("<saml:Issuer>")
        .and_then(|(_, rest)| rest.split_once("</saml:Issuer>"))
        .map(|(iss, _)| iss.trim().to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "missing AttributeQuery Issuer".to_string(),
        })?;
    let name_id_format = body
        .split_once("Format=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(fmt, _)| fmt.to_string());
    let name_id = body
        .split_once("<saml:NameID")
        .and_then(|(_, after_nameid)| {
            let after_open = after_nameid.split_once('>')?.1;
            let value = after_open.split_once("</saml:NameID>")?.0;
            Some(value.trim().to_string())
        })
        .ok_or_else(|| QidError::BadRequest {
            message: "missing saml:NameID in AttributeQuery Subject".to_string(),
        })?;
    Ok(ParsedAttributeQuery {
        id,
        issuer,
        name_id,
        name_id_format,
    })
}

/// Build a SOAP `<Response>` containing an `<AttributeStatement>` for the
/// attribute query result.
pub(crate) fn build_attribute_query_response(
    in_response_to: &str,
    issuer: &str,
    attributes_xml: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:AttributeStatement>
        {}
      </saml:AttributeStatement>
    </samlp:Response>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        super::artifact::iso_now_utc(),
        in_response_to,
        xml_escape(issuer),
        attributes_xml,
    )
}

/// Build an error SOAP response for attribute query failures.
pub(crate) fn attribute_query_error_soap(
    in_response_to: &str,
    issuer: &str,
    status_code: &str,
    status_message: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="{}"/>
        <samlp:StatusMessage>{}</samlp:StatusMessage>
      </samlp:Status>
    </samlp:Response>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        super::artifact::iso_now_utc(),
        in_response_to,
        xml_escape(issuer),
        status_code,
        xml_escape(status_message),
    )
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attribute_query_valid() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_query123" Version="2.0" IssueInstant="2026-06-21T12:00:00Z">
      <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
          user@example.com
        </saml:NameID>
      </saml:Subject>
    </samlp:AttributeQuery>
  </soap:Body>
</soap:Envelope>"#;
        let parsed = parse_attribute_query(xml).unwrap();
        assert_eq!(parsed.id, "_query123");
        assert_eq!(parsed.issuer, "https://sp.example.com/saml");
        assert_eq!(parsed.name_id, "user@example.com");
        assert_eq!(
            parsed.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
    }

    #[test]
    fn parse_attribute_query_persistent() {
        let xml = r#"<samlp:AttributeQuery ID="_q1"
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
      <saml:Issuer>sp</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
          abc-123-def
        </saml:NameID>
      </saml:Subject>
    </samlp:AttributeQuery>"#;
        let parsed = parse_attribute_query(xml).unwrap();
        assert_eq!(parsed.id, "_q1");
        assert_eq!(parsed.name_id, "abc-123-def");
        assert_eq!(
            parsed.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        );
    }

    #[test]
    fn parse_attribute_query_missing_id() {
        let xml = r#"<samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Issuer>sp</saml:Issuer>
      <saml:Subject>
        <saml:NameID>user</saml:NameID>
      </saml:Subject>
    </samlp:AttributeQuery>"#;
        let result = parse_attribute_query(xml);
        assert!(result.is_err());
    }

    #[test]
    fn build_response_contains_elements() {
        let attrs = r#"<saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute>"#;
        let xml = build_attribute_query_response("_req1", "https://idp.example.com", attrs);
        assert!(xml.contains("InResponseTo=\"_req1\""));
        assert!(xml.contains("https://idp.example.com"));
        assert!(xml.contains("email"));
        assert!(xml.contains("AttributeStatement"));
        assert!(xml.contains("soap:Envelope"));
    }

    #[test]
    fn error_response_contains_status() {
        let xml = attribute_query_error_soap(
            "_req1",
            "https://idp.example.com",
            "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
            "user not found",
        );
        assert!(xml.contains("UnknownPrincipal"));
        assert!(xml.contains("user not found"));
    }
}
