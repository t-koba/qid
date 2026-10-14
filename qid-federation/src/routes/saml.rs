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

const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

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
    if let Err(e) = record_saml_acs_replay(
        &state.assertion_replay_cache,
        &realm,
        &provider.id,
        &validated,
        util::now_seconds(),
        realm_config.protocols.saml.max_clock_skew_seconds,
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

/// Replay keys for one ACS presentation: the composite key preserves exact
/// duplicate detection, while the assertion-scoped key closes the relabelling
/// bypass where an assertion-only signature lets a new unsigned Response ID
/// mint a fresh composite key for the same assertion.
fn saml_replay_keys(
    realm: &str,
    provider_id: &str,
    validated: &ValidatedSamlAcsResponse,
) -> [String; 2] {
    [
        format!(
            "saml-acs:{realm}:{provider_id}:{}:{}",
            validated.response_id, validated.assertion_id
        ),
        format!(
            "saml-acs-assertion:{realm}:{provider_id}:{}",
            validated.assertion_id
        ),
    ]
}

/// Replay entries must outlive the whole acceptance window: validation
/// tolerates an expiry up to `skew_seconds` in the past, so the retention
/// deadline extends the nominal expiry by that skew.
fn saml_replay_deadline(validated: &ValidatedSamlAcsResponse, skew_seconds: u64) -> u64 {
    validated.expires_at.saturating_add(skew_seconds)
}

fn record_saml_acs_replay(
    cache: &qid_core::cache::DpopState,
    realm: &str,
    provider_id: &str,
    validated: &ValidatedSamlAcsResponse,
    now: u64,
    skew_seconds: u64,
) -> Result<(), QidError> {
    let deadline = saml_replay_deadline(validated, skew_seconds);
    for key in saml_replay_keys(realm, provider_id, validated) {
        cache.record_replay_key(
            &key,
            deadline,
            now,
            "SAML Response or Assertion ID has already been used (replay detected)",
        )?;
    }
    Ok(())
}

fn extract_saml_response_issuer(xml: &str) -> Result<String, QidError> {
    reject_insecure_saml_response_xml(xml)?;
    let doc = Document::parse(xml).map_err(|e| QidError::BadRequest {
        message: format!("SAMLResponse XML parse failed: {e}"),
    })?;
    let response = response_element(&doc)?;
    direct_child_text(response, SAML_ASSERTION_NS, "Issuer").ok_or_else(|| QidError::BadRequest {
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
    let assertion = single_descendant(response, SAML_ASSERTION_NS, "Assertion")?;
    let issuer = direct_child_text(response, SAML_ASSERTION_NS, "Issuer")
        .or_else(|| direct_child_text(assertion, SAML_ASSERTION_NS, "Issuer"))
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

    let subject = descendant_text(assertion, SAML_ASSERTION_NS, "NameID").ok_or_else(|| {
        QidError::BadRequest {
            message: "SAML Assertion Subject NameID is required".to_string(),
        }
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
        .filter(|node| is_element(*node, SAML_ASSERTION_NS, "Attribute"))
    {
        if let Some(name) = attribute.attribute("Name") {
            let values = attribute
                .children()
                .filter(|node| is_element(*node, SAML_ASSERTION_NS, "AttributeValue"))
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
        .filter(|node| is_element(*node, XMLDSIG_NS, "Signature"))
        .collect::<Vec<_>>();
    if signatures.len() != 1 {
        return Err(QidError::BadRequest {
            message: "SAML Response must contain exactly one XML signature".to_string(),
        });
    }
    let signature = signatures[0];
    let reference_uri = signature
        .descendants()
        .find(|node| is_element(*node, XMLDSIG_NS, "Reference"))
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
        .find(|node| is_element(*node, XMLDSIG_NS, "SignatureMethod"))
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
        .find(|node| is_element(*node, SAML_PROTOCOL_NS, "StatusCode"))
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
    let mut conditions = assertion
        .children()
        .filter(|node| is_element(*node, SAML_ASSERTION_NS, "Conditions"));
    let conditions = match (conditions.next(), conditions.next()) {
        (Some(conditions), None) => conditions,
        _ => {
            return Err(QidError::BadRequest {
                message: "SAML Assertion must contain exactly one direct Conditions element"
                    .to_string(),
            });
        }
    };
    // SAML AudienceRestriction groups combine with AND semantics: the realm
    // issuer must appear in every group. Only direct Audience children of a
    // direct AudienceRestriction group under Conditions count; stray Audience
    // elements elsewhere never satisfy the check.
    let mut restriction_count = 0;
    let mut one_time_use_seen = false;
    for condition in conditions.children().filter(|node| node.is_element()) {
        if is_element(condition, SAML_ASSERTION_NS, "AudienceRestriction") {
            restriction_count += 1;
            if condition
                .children()
                .filter(|node| node.is_element())
                .any(|node| !is_element(node, SAML_ASSERTION_NS, "Audience"))
            {
                return Err(QidError::BadRequest {
                    message: "SAML AudienceRestriction contains an unsupported element child"
                        .to_string(),
                });
            }
            let group = condition
                .children()
                .filter(|node| is_element(*node, SAML_ASSERTION_NS, "Audience"))
                .filter_map(|node| node.text())
                .map(str::trim)
                .collect::<Vec<_>>();
            if !group.contains(&expected_audience) {
                return Err(QidError::BadRequest {
                    message: "SAML Assertion Audience does not match realm issuer".to_string(),
                });
            }
        } else if is_element(condition, SAML_ASSERTION_NS, "OneTimeUse") {
            if one_time_use_seen
                || condition.attributes().len() != 0
                || condition.children().any(|node| {
                    node.is_element()
                        || (node.is_text() && !node.text().unwrap_or_default().trim().is_empty())
                })
            {
                return Err(QidError::BadRequest {
                    message: "SAML Conditions allows at most one empty OneTimeUse element"
                        .to_string(),
                });
            }
            // Every assertion is recorded for replay before any broker effects,
            // so OneTimeUse needs no additional consumption mechanism.
            one_time_use_seen = true;
        } else {
            return Err(QidError::BadRequest {
                message: format!(
                    "SAML Conditions contains an unsupported condition element: {}",
                    condition.tag_name().name()
                ),
            });
        }
    }
    if restriction_count == 0 {
        return Err(QidError::BadRequest {
            message: "SAML Assertion Audience does not match realm issuer".to_string(),
        });
    }
    let confirmation = assertion
        .descendants()
        .find(|node| is_element(*node, SAML_ASSERTION_NS, "SubjectConfirmation"))
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
        .find(|node| is_element(*node, SAML_ASSERTION_NS, "SubjectConfirmationData"))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion SubjectConfirmationData is required".to_string(),
        })?;
    if confirmation_data.attribute("NotBefore").is_some() {
        return Err(QidError::BadRequest {
            message:
                "SAML SubjectConfirmationData NotBefore is unsupported for bearer confirmation"
                    .to_string(),
        });
    }
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
    if let Some(not_before) = conditions.attribute("NotBefore") {
        validate_not_before(not_before, now, clock_skew_seconds, "SAML Conditions")?;
    }
    if let Some(not_on_or_after) = conditions.attribute("NotOnOrAfter") {
        validate_not_on_or_after(not_on_or_after, now, clock_skew_seconds, "SAML Conditions")?;
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
    if !is_element(response, SAML_PROTOCOL_NS, "Response") {
        return Err(QidError::BadRequest {
            message: "SAMLResponse root element must be Response".to_string(),
        });
    }
    Ok(response)
}

fn single_descendant<'a>(
    root: Node<'a, 'a>,
    namespace: &str,
    name: &str,
) -> Result<Node<'a, 'a>, QidError> {
    let mut matches = root
        .descendants()
        .filter(|node| is_element(*node, namespace, name))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(QidError::BadRequest {
            message: format!("SAML Response must contain exactly one {name} element"),
        });
    }
    Ok(matches.remove(0))
}

fn direct_child_text(node: Node<'_, '_>, namespace: &str, name: &str) -> Option<String> {
    node.children()
        .find(|child| is_element(*child, namespace, name))
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn descendant_text(node: Node<'_, '_>, namespace: &str, name: &str) -> Option<String> {
    node.descendants()
        .find(|child| is_element(*child, namespace, name))
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn is_element(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.has_tag_name((namespace, name))
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
    // Retain unsigned Unix epoch seconds as a separate accepted representation.
    if let Ok(epoch) = value.parse::<u64>() {
        return Ok(epoch);
    }
    parse_rfc3339_utc(value).ok_or_else(|| QidError::BadRequest {
        message: format!("SAML timestamp is invalid: {value}"),
    })
}

fn parse_rfc3339_utc(value: &str) -> Option<u64> {
    // SAML timestamps here are UTC-only; require the existing `Z` form.
    if !value.ends_with('Z') {
        return None;
    }
    // Unix-second conversion cannot preserve leap-second instants, so reject
    // second 60 before the RFC3339 parser can normalize it.
    let seconds = value.as_bytes().get(17..19)?;
    if !seconds.iter().all(u8::is_ascii_digit) || seconds[0] > b'5' {
        return None;
    }
    let timestamp =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(timestamp.unix_timestamp()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_timestamp_parser_keeps_epoch_seconds_and_validates_rfc3339() {
        assert!(matches!(
            parse_saml_timestamp("1700000000"),
            Ok(1_700_000_000)
        ));
        assert!(matches!(
            parse_saml_timestamp("2024-02-29T23:59:59.123Z"),
            Ok(1_709_251_199)
        ));
        assert!(matches!(
            parse_saml_timestamp("2016-12-31T23:59:59Z"),
            Ok(1_483_228_799)
        ));
        assert!(matches!(
            parse_saml_timestamp("2017-01-01T00:00:00Z"),
            Ok(1_483_228_800)
        ));
        assert!(matches!(
            parse_saml_timestamp("2016-12-31T23:59:59.999999999Z"),
            Ok(1_483_228_799)
        ));

        for invalid in [
            "2026-02-30T00:00:00Z",
            "2026-01-01-extraT00:00:00Z",
            "2026-01-01T00:00:00:garbageZ",
            "2026-01-01T00:00:00.not-a-fractionZ",
            "2147483647-12-31T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2026-03-02T00:00:00+00:00",
            "2024-02-29T23:59:60Z",
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:60.1Z",
            "2016-12-31T23:59:60.999999999Z",
        ] {
            assert!(
                parse_saml_timestamp(invalid).is_err(),
                "invalid timestamp must be rejected: {invalid}"
            );
        }
    }

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
        response_with_conditions(
            &format!(
                r#"<saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#
            ),
            confirmation_data_attrs,
            "",
        )
    }

    fn response_with_conditions(
        conditions_xml: &str,
        confirmation_data_attrs: &str,
        extra_xml: &str,
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
    {conditions_xml}
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>subject@example.com</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>{extra_xml}
  </saml:Assertion>
</samlp:Response>"#
        )
    }

    fn sign_response(unsigned: &str) -> String {
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
        unsigned.replace("<!--SIGNATURE-->", &signature)
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

    fn signed_response_with_extra_condition(condition: &str) -> String {
        let unsigned = unsigned_response("https://id.example.com/realms/corp").replace(
            "</saml:Conditions>",
            &format!("{condition}</saml:Conditions>"),
        );
        sign_response(&unsigned)
    }

    fn validate_test_response(xml: &str) -> Result<ValidatedSamlAcsResponse, QidError> {
        validate_saml_acs_response(
            xml,
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
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
    fn element_matching_uses_expanded_names_not_prefixes() {
        for (namespace, names) in [
            (SAML_PROTOCOL_NS, &["Response", "StatusCode"][..]),
            (
                SAML_ASSERTION_NS,
                &[
                    "Assertion",
                    "Issuer",
                    "Conditions",
                    "OneTimeUse",
                    "AudienceRestriction",
                    "Audience",
                    "SubjectConfirmation",
                    "SubjectConfirmationData",
                    "NameID",
                    "Attribute",
                    "AttributeValue",
                ][..],
            ),
            (
                XMLDSIG_NS,
                &["Signature", "Reference", "SignatureMethod"][..],
            ),
        ] {
            for name in names {
                for xml in [
                    format!(r#"<alternate:{name} xmlns:alternate="{namespace}"/>"#),
                    format!(r#"<{name} xmlns="{namespace}"/>"#),
                ] {
                    let doc = Document::parse(&xml).unwrap();
                    assert!(is_element(doc.root_element(), namespace, name));
                }
                for xml in [
                    format!(r#"<alternate:{name} xmlns:alternate="urn:example:not-saml"/>"#),
                    format!("<{name}/>"),
                ] {
                    let doc = Document::parse(&xml).unwrap();
                    assert!(!is_element(doc.root_element(), namespace, name));
                }
            }
        }
    }

    #[test]
    fn issuer_extraction_requires_saml_namespaces() {
        let xml = unsigned_response("https://id.example.com/realms/corp");
        for (namespace, expected_error) in [
            (SAML_PROTOCOL_NS, "root element"),
            (SAML_ASSERTION_NS, "Issuer is required"),
        ] {
            let foreign = xml.replace(namespace, "urn:example:not-saml");
            let err = extract_saml_response_issuer(&foreign).unwrap_err();
            assert!(err.message().contains(expected_error), "{err}");
        }
        let unqualified = xml.replace("samlp:", "").replace("saml:", "");
        assert!(extract_saml_response_issuer(&unqualified).is_err());
    }

    #[test]
    fn acs_validation_accepts_alternate_namespace_prefixes() {
        let unsigned = unsigned_response("https://id.example.com/realms/corp")
            .replace("samlp:", "protocol:")
            .replace("xmlns:samlp=", "xmlns:protocol=")
            .replace("saml:", "identity:")
            .replace("xmlns:saml=", "xmlns:identity=");
        let start = unsigned.find("<identity:Assertion").unwrap();
        let end = unsigned.find("</identity:Assertion>").unwrap() + "</identity:Assertion>".len();
        let signature = qid_saml::sign_saml_element_with_key(
            &unsigned[start..end],
            "assert-1",
            qid_saml::SamlXmlSignatureAlgorithm::RsaSha256,
            TEST_KEY.as_bytes(),
        )
        .unwrap();
        let signed = unsigned.replace("<!--SIGNATURE-->", &signature);
        assert_eq!(
            extract_saml_response_issuer(&signed).unwrap(),
            provider().issuer
        );
        let validated = validate_saml_acs_response(
            &signed,
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .expect("namespace URIs, not prefixes, identify SAML and XMLDSig elements");
        assert_eq!(validated.claims.subject, "subject@example.com");
        assert_eq!(
            validated.claims.claims["email"],
            serde_json::json!("subject@example.com")
        );
    }

    #[test]
    fn acs_validation_ignores_foreign_namespace_claims() {
        let unsigned = unsigned_response("https://id.example.com/realms/corp")
            .replace(
                "<saml:NameID>",
                r#"<foreign:NameID xmlns:foreign="urn:example:not-saml">foreign-subject</foreign:NameID><saml:NameID>"#,
            )
            .replace(
                r#"<saml:Attribute Name="email">"#,
                r#"<foreign:Attribute xmlns:foreign="urn:example:not-saml" Name="injected"><foreign:AttributeValue>foreign-claim</foreign:AttributeValue></foreign:Attribute><saml:Attribute Name="email"><foreign:AttributeValue xmlns:foreign="urn:example:not-saml">foreign-email</foreign:AttributeValue>"#,
            );
        let validated = validate_saml_acs_response(
            &sign_response(&unsigned),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .expect("foreign claims must not shadow SAML assertion claims");
        assert_eq!(validated.claims.subject, "subject@example.com");
        assert_eq!(
            validated.claims.claims["email"],
            serde_json::json!("subject@example.com")
        );
        assert!(!validated.claims.claims.contains_key("injected"));
    }

    #[test]
    fn acs_validation_requires_xmldsig_namespaces() {
        let signed = signed_response("https://id.example.com/realms/corp");
        for (name, expected_error) in [
            ("Signature", "exactly one XML signature"),
            ("Reference", "Reference URI is required"),
            ("SignatureMethod", "SignatureMethod Algorithm is required"),
        ] {
            let foreign = signed.replacen(
                &format!("<ds:{name} "),
                &format!(r#"<ds:{name} xmlns:ds="urn:example:not-saml" "#),
                1,
            );
            // Signature already declares ds, so replace that declaration
            // rather than introducing a duplicate namespace attribute.
            let foreign = foreign.replace(
                r#"xmlns:ds="urn:example:not-saml" xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#,
                r#"xmlns:ds="urn:example:not-saml""#,
            );
            let err = validate_saml_acs_response(
                &foreign,
                &provider(),
                "https://id.example.com/realms/corp",
                "https://id.example.com/federation/corp/saml/acs",
                1_700_000_000,
                60,
            )
            .unwrap_err();
            assert!(err.message().contains(expected_error), "{name}: {err}");
        }
    }

    #[test]
    fn acs_validation_rejects_wrong_namespace_audience_elements() {
        for (name, suffix, expected_error) in [
            ("Conditions", " ", "exactly one direct Conditions"),
            ("AudienceRestriction", ">", "unsupported condition element"),
            ("Audience", ">", "AudienceRestriction"),
        ] {
            // Rebinding Conditions also rebinds its AudienceRestriction and
            // Audience descendants. The other cases exercise each boundary.
            let unsigned = unsigned_response("https://id.example.com/realms/corp").replacen(
                &format!("<saml:{name}{suffix}"),
                &format!(r#"<saml:{name} xmlns:saml="urn:example:not-saml"{suffix}"#),
                1,
            );
            let signed = sign_response(&unsigned);
            let public_key = qid_saml::cert_pem_to_public_key_pem_from_pem(TEST_CERT).unwrap();
            qid_saml::verify_saml_xml_signature(qid_saml::SamlSignatureInputs {
                document: &signed,
                public_key_pem: public_key.as_bytes(),
                profile: qid_saml::SamlXmlSignatureAlgorithm::RsaSha256,
            })
            .expect("wrong-namespace fixture must have a valid signature");
            let err = validate_saml_acs_response(
                &signed,
                &provider(),
                "https://id.example.com/realms/corp",
                "https://id.example.com/federation/corp/saml/acs",
                1_700_000_000,
                60,
            )
            .expect_err("foreign namespace must not satisfy the audience requirement");
            assert!(err.message().contains(expected_error), "{name}: {err}");
        }
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
    fn acs_validation_rejects_excluding_audience_restriction_group() {
        // AND semantics: one group for this realm plus one for another realm
        // must fail, even though the realm issuer appears in the assertion.
        let unsigned = response_with_conditions(
            r#"<saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300"><saml:AudienceRestriction><saml:Audience>https://id.example.com/realms/corp</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction><saml:Audience>https://other.example.com/realms/corp</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1700000300""#,
            "",
        );
        let err = validate_saml_acs_response(
            &sign_response(&unsigned),
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
    fn acs_validation_ignores_audience_outside_restriction_groups() {
        // A matching Audience outside Conditions/AudienceRestriction must not
        // satisfy the check when the only real group excludes this realm.
        let unsigned = response_with_conditions(
            r#"<saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300"><saml:AudienceRestriction><saml:Audience>https://other.example.com/realms/corp</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1700000300""#,
            r#"<saml:Audience xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://id.example.com/realms/corp</saml:Audience>"#,
        );
        let err = validate_saml_acs_response(
            &sign_response(&unsigned),
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
    fn acs_validation_accepts_repeated_matching_audience_groups() {
        // Every group contains this realm, so AND semantics are satisfied.
        let unsigned = response_with_conditions(
            r#"<saml:Conditions NotBefore="1699999990" NotOnOrAfter="1700000300"><saml:AudienceRestriction><saml:Audience>https://id.example.com/realms/corp</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction><saml:Audience>https://id.example.com/realms/corp</saml:Audience><saml:Audience>https://partner.example.com/app</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1700000300""#,
            "",
        );
        let validated = validate_saml_acs_response(
            &sign_response(&unsigned),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .expect("all audience groups match this realm");
        assert_eq!(validated.claims.subject, "subject@example.com");
    }

    #[test]
    fn acs_validation_rejects_custom_generic_condition() {
        let signed = signed_response_with_extra_condition(
            r#"<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:custom="urn:example:custom-condition" xsi:type="custom:ApprovalRequired"/>"#,
        );
        let err = validate_test_response(&signed).unwrap_err();
        assert!(
            err.message()
                .contains("unsupported condition element: Condition"),
            "{err}"
        );
    }

    #[test]
    fn acs_validation_rejects_proxy_restriction() {
        let signed = signed_response_with_extra_condition(
            r#"<saml:ProxyRestriction Count="0"><saml:Audience>https://id.example.com/realms/corp</saml:Audience></saml:ProxyRestriction>"#,
        );
        let err = validate_test_response(&signed).unwrap_err();
        assert!(
            err.message()
                .contains("unsupported condition element: ProxyRestriction"),
            "{err}"
        );
    }

    #[test]
    fn acs_validation_rejects_condition_namespace_lookalikes() {
        for name in [
            "AudienceRestriction",
            "OneTimeUse",
            "Condition",
            "ProxyRestriction",
        ] {
            for child in [
                format!(r#"<foreign:{name} xmlns:foreign="urn:example:not-saml"/>"#),
                format!("<{name}/>"),
            ] {
                let err = validate_test_response(&signed_response_with_extra_condition(&child))
                    .unwrap_err();
                assert!(
                    err.message().contains("unsupported condition element"),
                    "{child}: {err}"
                );
            }
        }
        for child in [
            "<saml:Audience/>",
            "<saml:Conditions/>",
            "<saml:UnknownCondition/>",
        ] {
            let err =
                validate_test_response(&signed_response_with_extra_condition(child)).unwrap_err();
            assert!(
                err.message().contains("unsupported condition element"),
                "{child}: {err}"
            );
        }
    }

    #[test]
    fn acs_validation_requires_exactly_one_direct_conditions() {
        let conditions = r#"<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://id.example.com/realms/corp</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#;
        for conditions_xml in [
            String::new(),
            format!("{conditions}{conditions}"),
            format!("<saml:Advice>{conditions}</saml:Advice>"),
        ] {
            let unsigned = response_with_conditions(
                &conditions_xml,
                r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1700000300""#,
                "",
            );
            let err = validate_test_response(&sign_response(&unsigned)).unwrap_err();
            assert!(
                err.message().contains("exactly one direct Conditions"),
                "{conditions_xml}: {err}"
            );
        }
    }

    #[test]
    fn acs_validation_ignores_nested_conditions_lookalikes() {
        // A nested group and its expired time bound must not shadow the direct
        // Conditions element that actually governs this assertion.
        let unsigned = unsigned_response("https://id.example.com/realms/corp").replace(
            "<saml:Conditions NotBefore=",
            r#"<saml:Advice><saml:Conditions NotOnOrAfter="1"><saml:AudienceRestriction><saml:Audience>https://other.example.com/realms/corp</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Advice><saml:Conditions NotBefore="#,
        );
        validate_test_response(&sign_response(&unsigned))
            .expect("only direct Conditions determines audience and time bounds");
    }

    #[test]
    fn acs_validation_rejects_non_audience_restriction_children() {
        for child in [
            r#"<foreign:Audience xmlns:foreign="urn:example:not-saml">https://id.example.com/realms/corp</foreign:Audience>"#,
            "<Audience>https://id.example.com/realms/corp</Audience>",
            "<saml:OneTimeUse/>",
        ] {
            let unsigned = unsigned_response("https://id.example.com/realms/corp").replace(
                "</saml:AudienceRestriction>",
                &format!("{child}</saml:AudienceRestriction>"),
            );
            let err = validate_test_response(&sign_response(&unsigned)).unwrap_err();
            assert!(
                err.message()
                    .contains("AudienceRestriction contains an unsupported element child"),
                "{child}: {err}"
            );
        }
    }

    #[test]
    fn acs_validation_rejects_nonempty_or_duplicate_one_time_use() {
        for condition in [
            r#"<saml:OneTimeUse Count="1"/>"#,
            r#"<saml:OneTimeUse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="saml:OneTimeUseType"/>"#,
            "<saml:OneTimeUse><saml:Audience/></saml:OneTimeUse>",
            "<saml:OneTimeUse>not empty</saml:OneTimeUse>",
            "<saml:OneTimeUse> <!--comment-->not empty</saml:OneTimeUse>",
            "<saml:OneTimeUse><![CDATA[not empty]]></saml:OneTimeUse>",
            "<saml:OneTimeUse/><saml:OneTimeUse/>",
        ] {
            let err = validate_test_response(&signed_response_with_extra_condition(condition))
                .unwrap_err();
            assert!(
                err.message().contains("at most one empty OneTimeUse"),
                "{condition}: {err}"
            );
        }
    }

    #[test]
    fn acs_validation_accepts_one_time_use_and_recorder_rejects_replay() {
        for condition in [
            "<saml:OneTimeUse/>",
            "<saml:OneTimeUse> \n\t </saml:OneTimeUse>",
            r#"<once:OneTimeUse xmlns:once="urn:oasis:names:tc:SAML:2.0:assertion"/>"#,
            r#"<OneTimeUse xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>"#,
        ] {
            let signed = signed_response_with_extra_condition(condition);
            let first = validate_test_response(&signed)
                .expect("AudienceRestriction with an empty OneTimeUse must validate");
            let cache = qid_core::cache::DpopState::new();
            record_saml_acs_replay(&cache, "corp", &provider().id, &first, 1_700_000_000, 60)
                .expect("first presentation must record before broker effects");
            let second = validate_test_response(&signed)
                .expect("the signed response still meets protocol checks");
            let err =
                record_saml_acs_replay(&cache, "corp", &provider().id, &second, 1_700_000_000, 60)
                    .unwrap_err();
            assert!(
                err.message().contains("already been used"),
                "{condition}: {err}"
            );
        }
    }

    #[test]
    fn acs_validation_preserves_conditions_time_bounds() {
        for (old, new, expected_error) in [
            (
                r#"NotBefore="1699999990""#,
                r#"NotBefore="1700000061""#,
                "SAML Conditions is not yet valid",
            ),
            (
                r#"NotOnOrAfter="1700000300"><saml:AudienceRestriction>"#,
                r#"NotOnOrAfter="1699999940"><saml:AudienceRestriction>"#,
                "SAML Conditions has expired",
            ),
        ] {
            let unsigned =
                unsigned_response("https://id.example.com/realms/corp").replace(old, new);
            let err = validate_test_response(&sign_response(&unsigned)).unwrap_err();
            assert!(err.message().contains(expected_error), "{err}");
        }
    }

    /// Test cache with a manually advanced clock for deterministic TTL probes.
    struct ManualClockCache {
        now: std::sync::Mutex<u64>,
        store: std::sync::Mutex<std::collections::HashMap<String, (Vec<u8>, u64)>>,
    }

    impl ManualClockCache {
        fn new(now: u64) -> Self {
            Self {
                now: std::sync::Mutex::new(now),
                store: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// Move the manual clock forward; entries expire lazily on access.
        fn advance(&self, now: u64) {
            *self.now.lock().unwrap() = now;
        }
    }

    impl qid_core::cache::SharedCache for ManualClockCache {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            let now = *self.now.lock().unwrap();
            let store = self.store.lock().unwrap();
            store
                .get(key)
                .filter(|(_, expires_at)| *expires_at > now)
                .map(|(value, _)| value.clone())
        }

        fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
            let now = *self.now.lock().unwrap();
            self.store
                .lock()
                .unwrap()
                .insert(key.to_string(), (value, now.saturating_add(ttl_seconds)));
        }

        fn set_if_absent(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl_seconds: u64,
        ) -> qid_core::QidResult<bool> {
            if self.get(key).is_some() {
                return Ok(false);
            }
            self.set(key, value, ttl_seconds);
            Ok(true)
        }

        fn delete(&self, key: &str) {
            self.store.lock().unwrap().remove(key);
        }
    }

    #[test]
    fn acs_replay_survives_through_skew_acceptance_window() {
        // Nominal expiry 1100 with 60s skew: acceptance at 1099 records, and an
        // identical presentation at 1102 still validates (within skew) so it
        // must still be rejected as replay even though raw expiry has passed.
        let audience = "https://id.example.com/realms/corp";
        let acs_url = "https://id.example.com/federation/corp/saml/acs";
        let provider = provider();
        let unsigned = response_with_conditions(
            &format!(
                r#"<saml:Conditions NotBefore="1000" NotOnOrAfter="1100"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#
            ),
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotOnOrAfter="1100""#,
            "",
        );
        let signed = sign_response(&unsigned);
        let first = validate_saml_acs_response(&signed, &provider, audience, acs_url, 1_099, 60)
            .expect("presentation before nominal expiry must validate");
        assert_eq!(first.expires_at, 1_100);
        let inner = std::sync::Arc::new(ManualClockCache::new(1_099));
        let cache = qid_core::cache::DpopState::with_cache(inner.clone());
        record_saml_acs_replay(&cache, "corp", &provider.id, &first, 1_099, 60)
            .expect("first presentation must record");
        inner.advance(1_102);
        let second = validate_saml_acs_response(&signed, &provider, audience, acs_url, 1_102, 60)
            .expect("identical response within skew must still validate");
        let err =
            record_saml_acs_replay(&cache, "corp", &provider.id, &second, 1_102, 60).unwrap_err();
        assert!(err.message().contains("already been used"));
    }

    #[test]
    fn acs_replay_detects_same_assertion_under_new_response_id() {
        let audience = "https://id.example.com/realms/corp";
        let acs_url = "https://id.example.com/federation/corp/saml/acs";
        let provider = provider();
        let first = validate_saml_acs_response(
            &signed_response(audience),
            &provider,
            audience,
            acs_url,
            1_700_000_000,
            60,
        )
        .expect("first presentation must validate");
        let cache = qid_core::cache::DpopState::new();
        record_saml_acs_replay(&cache, "corp", &provider.id, &first, 1_700_000_000, 60)
            .expect("first presentation must record");
        // Same signed assertion, only the unsigned Response ID relabelled.
        let relabelled = signed_response(audience).replace("ID=\"resp-1\"", "ID=\"resp-2\"");
        let second = validate_saml_acs_response(
            &relabelled,
            &provider,
            audience,
            acs_url,
            1_700_000_000,
            60,
        )
        .expect("relabelled response still validates the same assertion");
        assert_eq!(second.assertion_id, first.assertion_id);
        assert_ne!(second.response_id, first.response_id);
        let err = record_saml_acs_replay(&cache, "corp", &provider.id, &second, 1_700_000_000, 60)
            .unwrap_err();
        assert!(err.message().contains("already been used"));
    }

    #[test]
    fn acs_validation_rejects_subject_confirmation_not_before() {
        let unsigned = response_with_subject_confirmation_data(
            "https://id.example.com/realms/corp",
            r#"Recipient="https://id.example.com/federation/corp/saml/acs" NotBefore="1700000100" NotOnOrAfter="1700000300""#,
        );
        let err = validate_saml_acs_response(
            &sign_response(&unsigned),
            &provider(),
            "https://id.example.com/realms/corp",
            "https://id.example.com/federation/corp/saml/acs",
            1_700_000_000,
            60,
        )
        .unwrap_err();
        assert!(err.message().contains("SubjectConfirmationData NotBefore"));
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
