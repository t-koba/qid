use axum::{
    Json,
    extract::{Form, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use qid_core::{QidError, state::SharedState, util};
use qid_storage::prelude::*;
use roxmltree::{Document, Node};
use std::sync::Arc;

use crate::{
    ExternalIdentityClaims, HomeRealmDiscoveryRequest, InboundIdentityProvider, plan_inbound_login,
};

use super::{SamlAcsForm, exec_broker_login_plan, load_broker_links, providers_from_config};

pub async fn saml_inbound_acs<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Form(form): Form<SamlAcsForm>,
) -> Response {
    let realm_config = match state.config.realms.iter().find(|r| r.id == realm) {
        Some(cfg) => cfg,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm_not_found"})),
            )
                .into_response();
        }
    };
    if !realm_config.protocols.federation.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation_disabled"})),
        )
            .into_response();
    }
    let providers = providers_from_config(&realm_config.protocols.federation.inbound_providers);
    let saml_response_xml = match &form.saml_response {
        Some(raw) => match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(xml) => xml,
                Err(_) => {
                    return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid_saml_response", "message": "SAMLResponse is not valid UTF-8"})),
                        )
                            .into_response();
                }
            },
            Err(_) => {
                return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_saml_response", "message": "SAMLResponse is not valid base64"})),
                    )
                        .into_response();
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing_saml_response", "message": "SAMLResponse parameter is required"})),
            )
                .into_response();
        }
    };
    let issuer = match extract_saml_response_issuer(&saml_response_xml) {
        Ok(issuer) => issuer,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "saml_response_validation_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    };
    let provider = match providers.iter().find(|p| p.issuer == issuer && p.enabled) {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "untrusted_saml_provider", "message": format!("No enabled inbound provider matches issuer {issuer}")})),
            )
                .into_response();
        }
    };
    let expected_acs_url = format!(
        "{}/federation/{}/saml/acs",
        state.plan.public_base_url.trim_end_matches('/'),
        realm
    );
    let validated = match validate_saml_acs_response(
        &saml_response_xml,
        &provider,
        &realm_config.issuer,
        &expected_acs_url,
        util::now_seconds(),
        realm_config.protocols.saml.max_clock_skew_seconds,
    ) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "saml_response_validation_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    };
    let replay_key = format!(
        "saml-acs:{}:{}:{}:{}",
        realm, provider.id, validated.response_id, validated.assertion_id
    );
    if let Err(e) = state.assertion_replay_cache.record_replay_key(
        &replay_key,
        validated.expires_at,
        util::now_seconds(),
        "SAML Response or Assertion ID has already been used (replay detected)",
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "saml_response_replay_detected", "message": e.to_string()})),
        )
            .into_response();
    }
    let claims = validated.claims;
    let links = load_broker_links(state.repo.as_ref(), &realm, &provider.id, &claims).await;

    let login_plan = match plan_inbound_login(
        &providers,
        &HomeRealmDiscoveryRequest {
            login_hint: None,
            domain: None,
            idp_hint: Some(provider.id.clone()),
            social_provider: None,
        },
        &claims,
        &links,
    ) {
        Ok(plan) => plan,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "login_plan_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    };

    let local_user_id = exec_broker_login_plan(
        state.repo.as_ref(),
        &realm,
        &provider.id,
        &claims,
        &login_plan,
    )
    .await;

    match local_user_id {
        Ok(uid) => Json(serde_json::json!({
            "status": "linked",
            "provider": provider.id,
            "provider_kind": provider.kind.as_str(),
            "local_user_id": uid,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "login_plan_execution_failed", "message": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug)]
struct ValidatedSamlAcsResponse {
    claims: ExternalIdentityClaims,
    response_id: String,
    assertion_id: String,
    expires_at: u64,
}

fn extract_saml_response_issuer(xml: &str) -> Result<String, QidError> {
    reject_insecure_saml_response_xml(xml)?;
    let doc = Document::parse(xml).map_err(|e| QidError::BadRequest {
        message: format!("SAMLResponse XML parse failed: {e}"),
    })?;
    let response = response_element(&doc)?;
    direct_child_text(response, "Issuer").ok_or_else(|| QidError::BadRequest {
        message: "SAML Response Issuer is required".to_string(),
    })
}

fn validate_saml_acs_response(
    xml: &str,
    provider: &InboundIdentityProvider,
    expected_audience: &str,
    expected_acs_url: &str,
    now: u64,
    clock_skew_seconds: u64,
) -> Result<ValidatedSamlAcsResponse, QidError> {
    reject_insecure_saml_response_xml(xml)?;
    let doc = Document::parse(xml).map_err(|e| QidError::BadRequest {
        message: format!("SAMLResponse XML parse failed: {e}"),
    })?;
    let response = response_element(&doc)?;
    let assertion = single_descendant(response, "Assertion")?;
    let issuer = direct_child_text(response, "Issuer")
        .or_else(|| direct_child_text(assertion, "Issuer"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Response or Assertion Issuer is required".to_string(),
        })?;
    if issuer != provider.issuer {
        return Err(QidError::BadRequest {
            message: "SAML Response issuer does not match inbound provider".to_string(),
        });
    }
    validate_saml_signature(xml, response, assertion, provider)?;
    let expires_at = validate_saml_response_protocol(
        response,
        assertion,
        expected_audience,
        expected_acs_url,
        now,
        clock_skew_seconds,
    )?;

    let subject = descendant_text(assertion, "NameID").ok_or_else(|| QidError::BadRequest {
        message: "SAML Assertion Subject NameID is required".to_string(),
    })?;
    let response_id = response
        .attribute("ID")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Response ID is required".to_string(),
        })?
        .to_string();
    let assertion_id = assertion
        .attribute("ID")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion ID is required".to_string(),
        })?
        .to_string();

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        "issuer".to_string(),
        serde_json::Value::String(issuer.clone()),
    );
    claims.insert(
        "external_subject".to_string(),
        serde_json::Value::String(subject.clone()),
    );
    claims.insert(
        "subject".to_string(),
        serde_json::Value::String(subject.clone()),
    );

    for attribute in assertion
        .descendants()
        .filter(|node| is_element(*node, "Attribute"))
    {
        if let Some(name) = attribute.attribute("Name") {
            let values = attribute
                .children()
                .filter(|node| is_element(*node, "AttributeValue"))
                .filter_map(|node| node.text())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            let json_value = if values.len() == 1 {
                serde_json::Value::String(values.into_iter().next().unwrap_or_default())
            } else {
                serde_json::Value::Array(
                    values.into_iter().map(serde_json::Value::String).collect(),
                )
            };
            claims.insert(name.to_string(), json_value);
        }
    }

    Ok(ValidatedSamlAcsResponse {
        claims: ExternalIdentityClaims {
            issuer,
            subject,
            claims,
        },
        response_id,
        assertion_id,
        expires_at,
    })
}

fn validate_saml_signature(
    xml: &str,
    response: Node<'_, '_>,
    assertion: Node<'_, '_>,
    provider: &InboundIdentityProvider,
) -> Result<(), QidError> {
    if provider.saml_signing_certificates.is_empty() {
        return Err(QidError::Unauthorized {
            message: "inbound SAML provider has no signing certificates".to_string(),
        });
    }
    let signatures = response
        .descendants()
        .filter(|node| is_element(*node, "Signature"))
        .collect::<Vec<_>>();
    if signatures.len() != 1 {
        return Err(QidError::BadRequest {
            message: "SAML Response must contain exactly one XML signature".to_string(),
        });
    }
    let signature = signatures[0];
    let reference_uri = signature
        .descendants()
        .find(|node| is_element(*node, "Reference"))
        .and_then(|node| node.attribute("URI"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Signature Reference URI is required".to_string(),
        })?;
    let response_id = response
        .attribute("ID")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Response ID is required".to_string(),
        })?;
    let assertion_id = assertion
        .attribute("ID")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion ID is required".to_string(),
        })?;
    if reference_uri != format!("#{response_id}") && reference_uri != format!("#{assertion_id}") {
        return Err(QidError::BadRequest {
            message: "SAML Signature Reference URI must target the Response or Assertion ID"
                .to_string(),
        });
    }
    let signature_method = signature
        .descendants()
        .find(|node| is_element(*node, "SignatureMethod"))
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML SignatureMethod Algorithm is required".to_string(),
        })?;
    let algorithm =
        qid_saml::SamlXmlSignatureAlgorithm::from_uri(signature_method).ok_or_else(|| {
            QidError::BadRequest {
                message: "SAML SignatureMethod Algorithm is not supported".to_string(),
            }
        })?;

    let mut last_error = None;
    for certificate in &provider.saml_signing_certificates {
        let public_key_pem = match qid_saml::cert_pem_to_public_key_pem_from_pem(certificate) {
            Ok(public_key_pem) => public_key_pem,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        match qid_saml::verify_saml_xml_signature(qid_saml::SamlSignatureInputs {
            document: xml,
            public_key_pem: public_key_pem.as_bytes(),
            profile: algorithm,
        }) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| QidError::Unauthorized {
        message: "SAML XML signature verification failed".to_string(),
    }))
}

fn validate_saml_response_protocol(
    response: Node<'_, '_>,
    assertion: Node<'_, '_>,
    expected_audience: &str,
    expected_acs_url: &str,
    now: u64,
    clock_skew_seconds: u64,
) -> Result<u64, QidError> {
    let status_code = response
        .descendants()
        .find(|node| is_element(*node, "StatusCode"))
        .and_then(|node| node.attribute("Value"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Response StatusCode is required".to_string(),
        })?;
    if status_code != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        return Err(QidError::BadRequest {
            message: "SAML Response status is not Success".to_string(),
        });
    }
    if response.attribute("Destination") != Some(expected_acs_url) {
        return Err(QidError::BadRequest {
            message: "SAML Response Destination does not match ACS URL".to_string(),
        });
    }
    if response.attribute("InResponseTo").is_some() {
        return Err(QidError::BadRequest {
            message:
                "SAML Response InResponseTo cannot be validated without an outstanding request"
                    .to_string(),
        });
    }
    let audiences = assertion
        .descendants()
        .filter(|node| is_element(*node, "Audience"))
        .filter_map(|node| node.text())
        .map(str::trim)
        .collect::<Vec<_>>();
    if !audiences.contains(&expected_audience) {
        return Err(QidError::BadRequest {
            message: "SAML Assertion Audience does not match realm issuer".to_string(),
        });
    }
    let confirmation = assertion
        .descendants()
        .find(|node| is_element(*node, "SubjectConfirmation"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion SubjectConfirmation is required".to_string(),
        })?;
    if confirmation.attribute("Method") != Some("urn:oasis:names:tc:SAML:2.0:cm:bearer") {
        return Err(QidError::BadRequest {
            message: "SAML Assertion SubjectConfirmation Method must be bearer".to_string(),
        });
    }
    let confirmation_data = confirmation
        .descendants()
        .find(|node| is_element(*node, "SubjectConfirmationData"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion SubjectConfirmationData is required".to_string(),
        })?;
    if confirmation_data.attribute("Recipient") != Some(expected_acs_url) {
        return Err(QidError::BadRequest {
            message: "SAML Assertion Recipient does not match ACS URL".to_string(),
        });
    }
    if confirmation_data.attribute("InResponseTo").is_some() {
        return Err(QidError::BadRequest {
            message:
                "SAML Assertion InResponseTo cannot be validated without an outstanding request"
                    .to_string(),
        });
    }
    let subject_confirmation_expires_at =
        confirmation_data
            .attribute("NotOnOrAfter")
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML SubjectConfirmationData NotOnOrAfter is required".to_string(),
            })?;
    let expires_at = validate_not_on_or_after(
        subject_confirmation_expires_at,
        now,
        clock_skew_seconds,
        "SAML SubjectConfirmationData",
    )?;
    if let Some(conditions) = assertion
        .descendants()
        .find(|node| is_element(*node, "Conditions"))
    {
        if let Some(not_before) = conditions.attribute("NotBefore") {
            validate_not_before(not_before, now, clock_skew_seconds, "SAML Conditions")?;
        }
        if let Some(not_on_or_after) = conditions.attribute("NotOnOrAfter") {
            validate_not_on_or_after(not_on_or_after, now, clock_skew_seconds, "SAML Conditions")?;
        }
    }
    Ok(expires_at)
}

fn reject_insecure_saml_response_xml(xml: &str) -> Result<(), QidError> {
    let lowered = xml.to_ascii_lowercase();
    if lowered.contains("<!doctype") || lowered.contains("<!entity") {
        return Err(QidError::BadRequest {
            message: "SAMLResponse XML must not contain DTD or entity declarations".to_string(),
        });
    }
    Ok(())
}

fn response_element<'a>(doc: &'a Document<'a>) -> Result<Node<'a, 'a>, QidError> {
    let response = doc.root_element();
    if !is_element(response, "Response") {
        return Err(QidError::BadRequest {
            message: "SAMLResponse root element must be Response".to_string(),
        });
    }
    Ok(response)
}

fn single_descendant<'a>(root: Node<'a, 'a>, name: &str) -> Result<Node<'a, 'a>, QidError> {
    let mut matches = root
        .descendants()
        .filter(|node| is_element(*node, name))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(QidError::BadRequest {
            message: format!("SAML Response must contain exactly one {name} element"),
        });
    }
    Ok(matches.remove(0))
}

fn direct_child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| is_element(*child, name))
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn descendant_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.descendants()
        .find(|child| is_element(*child, name))
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn is_element(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name
}

fn validate_not_before(value: &str, now: u64, skew: u64, context: &str) -> Result<(), QidError> {
    let timestamp = parse_saml_timestamp(value)?;
    if timestamp > now.saturating_add(skew) {
        return Err(QidError::BadRequest {
            message: format!("{context} is not yet valid"),
        });
    }
    Ok(())
}

fn validate_not_on_or_after(
    value: &str,
    now: u64,
    skew: u64,
    context: &str,
) -> Result<u64, QidError> {
    let timestamp = parse_saml_timestamp(value)?;
    if timestamp <= now.saturating_sub(skew) {
        return Err(QidError::BadRequest {
            message: format!("{context} has expired"),
        });
    }
    Ok(timestamp)
}

fn parse_saml_timestamp(value: &str) -> Result<u64, QidError> {
    if let Ok(epoch) = value.parse::<u64>() {
        return Ok(epoch);
    }
    parse_rfc3339_utc(value).ok_or_else(|| QidError::BadRequest {
        message: format!("SAML timestamp is invalid: {value}"),
    })
}

fn parse_rfc3339_utc(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i32>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    let time = time.split_once('.').map(|(head, _)| head).unwrap_or(time);
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let second = time_parts.next()?.parse::<u32>().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<u64> {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days >= 0).then_some(days as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT: &str = include_str!("../../../qid-saml/tests/data/test-sp.crt");
    const TEST_KEY: &str = include_str!("../../../qid-saml/tests/data/test-sp.key");

    fn provider() -> InboundIdentityProvider {
        InboundIdentityProvider {
            id: "partner-saml".to_string(),
            kind: crate::InboundProviderKind::Saml,
            issuer: "https://idp.partner.example/metadata".to_string(),
            enabled: true,
            domains: vec!["partner.example".to_string()],
            social_provider: None,
            client_id: None,
            client_secret: None,
            token_url: None,
            userinfo_url: None,
            jit_provisioning: true,
            account_linking: true,
            claim_mappings: Vec::new(),
            jwks_uri: None,
            jwks: None,
            saml_signing_certificates: vec![TEST_CERT.to_string()],
        }
    }

    fn unsigned_response(audience: &str) -> String {
        response_with_subject_confirmation_data(
            audience,
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1700000300""#,
        )
    }

    fn response_with_subject_confirmation_data(
        audience: &str,
        confirmation_data_attrs: &str,
    ) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp-1" Version="2.0" IssueInstant="1700000000" Destination="https://id.example.com/federation/corp/saml/acs">
  <saml:Issuer>https://idp.partner.example/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="assert-1" Version="2.0" IssueInstant="1700000000">
    <saml:Issuer>https://idp.partner.example/metadata</saml:Issuer>
    <!--SIGNATURE-->
    <saml:Subject>
      <saml:NameID>subject@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData {confirmation_data_attrs}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>subject@example.com</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#
        )
    }

    fn signed_response(audience: &str) -> String {
        let unsigned = unsigned_response(audience);
        let assertion_start = unsigned
            .find("<saml:Assertion")
            .expect("test response must contain assertion");
        let assertion_end = unsigned
            .find("</saml:Assertion>")
            .map(|pos| pos + "</saml:Assertion>".len())
            .expect("test response must contain assertion close");
        let assertion_xml = &unsigned[assertion_start..assertion_end];
        let signature = qid_saml::sign_saml_element_with_key(
            assertion_xml,
            "assert-1",
            qid_saml::SamlXmlSignatureAlgorithm::RsaSha256,
            TEST_KEY.as_bytes(),
        )
        .expect("test SAML response must sign");
        unsigned.replace("<!--SIGNATURE-->", &signature)
    }

    #[test]
    fn acs_validation_rejects_unsigned_saml_response() {
        let err = validate_saml_acs_response(
            &unsigned_response("https://id.example.com/realms/corp"),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .unwrap_err();
        assert!(err.message().contains("XML signature"));
    }

    #[test]
    fn acs_validation_accepts_signed_saml_response() {
        let validated = validate_saml_acs_response(
            &signed_response("https://id.example.com/realms/corp"),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .expect("signed SAML response must validate");
        assert_eq!(validated.claims.subject, "subject@example.com");
        assert_eq!(validated.response_id, "resp-1");
        assert_eq!(validated.assertion_id, "assert-1");
        assert_eq!(validated.expires_at, 1_700_000_300);
        assert_eq!(
            validated.claims.claims["email"],
            serde_json::json!("subject@example.com")
        );
    }

    #[test]
    fn acs_validation_rejects_wrong_audience() {
        let err = validate_saml_acs_response(
            &signed_response("https://other.example.com/realms/corp"),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .unwrap_err();
        assert!(err.message().contains("Audience"));
    }

    #[test]
    fn acs_validation_rejects_missing_subject_confirmation_expiry() {
        let unsigned = response_with_subject_confirmation_data(
            "https://id.example.com/realms/corp",
            r#"Recipient="https://id.example.com/federation/corp/saml/acs""#,
        );
        let assertion_start = unsigned
            .find("<saml:Assertion")
            .expect("test response must contain assertion");
        let assertion_end = unsigned
            .find("</saml:Assertion>")
            .map(|pos| pos + "</saml:Assertion>".len())
            .expect("test response must contain assertion close");
        let signature = qid_saml::sign_saml_element_with_key(
            &unsigned[assertion_start..assertion_end],
            "assert-1",
            qid_saml::SamlXmlSignatureAlgorithm::RsaSha256,
            TEST_KEY.as_bytes(),
        )
        .expect("test SAML response must sign");
        let signed = unsigned.replace("<!--SIGNATURE-->", &signature);
        let err = validate_saml_acs_response(
            &signed,
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .unwrap_err();
        assert!(err.message().contains("NotOnOrAfter"));
    }
}
