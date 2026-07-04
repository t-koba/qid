use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlRelayStatePolicy {
    pub max_len: usize,
    pub allowed_prefixes: Vec<String>,
}

impl Default for SamlRelayStatePolicy {
    fn default() -> Self {
        Self {
            max_len: 80,
            allowed_prefixes: vec!["/".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlResponseProfile {
    pub response_id: Option<String>,
    pub assertion_ids: Vec<String>,
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlBearerAssertion {
    pub assertion_id: String,
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub expires_at: u64,
    pub auth_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlSubject {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlAssertionRequest {
    pub issuer: String,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub request_id: Option<String>,
    pub subject: SamlSubject,
    pub name_id_format: String,
    pub issued_at: u64,
    pub not_on_or_after: u64,
    pub session_index: Option<String>,
    #[serde(default)]
    pub attribute_release_policy: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlIssuedResponse {
    pub response_id: String,
    pub assertion_id: String,
    pub xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlIssuedLogoutResponse {
    pub response_id: String,
    pub in_response_to: String,
    pub destination: String,
    pub xml: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SamlPostBindingForm {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub assertion_consumer_service_url: Option<String>,
    pub destination: Option<String>,
    pub protocol_binding: Option<String>,
    pub name_id_policy_format: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub relay_state: Option<String>,
    pub raw_xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlLogoutRequest {
    pub id: String,
    pub issuer: String,
    pub destination: Option<String>,
    pub name_id: Option<String>,
    pub session_indexes: Vec<String>,
    pub relay_state: Option<String>,
    pub raw_xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlXmlSignatureProfile {
    pub reference_uri: Option<String>,
    pub signature_method: Option<String>,
    pub digest_method: Option<String>,
    pub signing_certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlBrowserSubject {
    pub session: Session,
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlPostResponse {
    pub acs_url: String,
    pub relay_state: Option<String>,
    pub saml_response: String,
    pub html: String,
}

pub fn validate_relay_state(
    relay_state: Option<&str>,
    policy: &SamlRelayStatePolicy,
) -> QidResult<()> {
    let Some(relay_state) = relay_state else {
        return Ok(());
    };
    if relay_state.len() > policy.max_len {
        return Err(QidError::BadRequest {
            message: "SAML RelayState exceeds configured length".to_string(),
        });
    }
    if relay_state.contains('\n') || relay_state.contains('\r') {
        return Err(QidError::BadRequest {
            message: "SAML RelayState must not contain control line breaks".to_string(),
        });
    }
    if policy
        .allowed_prefixes
        .iter()
        .any(|prefix| relay_state.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(QidError::BadRequest {
            message: "SAML RelayState is not allowed".to_string(),
        })
    }
}

pub fn inspect_saml_response_profile(xml: &str) -> QidResult<SamlResponseProfile> {
    reject_insecure_saml_xml(xml)?;
    let response_count = count_start_tags(xml, "Response");
    if response_count != 1 {
        return Err(QidError::BadRequest {
            message: "SAML response must contain exactly one Response element".to_string(),
        });
    }
    let assertion_ids = element_ids(xml, "Assertion");
    if assertion_ids.len() > 1 {
        return Err(QidError::BadRequest {
            message: "SAML response must not contain multiple Assertion elements".to_string(),
        });
    }
    Ok(SamlResponseProfile {
        response_id: attr_value_after(xml, "Response", "ID"),
        assertion_ids,
        destination: attr_value_after(xml, "Response", "Destination"),
        in_response_to: attr_value_after(xml, "Response", "InResponseTo"),
    })
}

pub fn validate_saml_bearer_assertion(
    xml: &str,
    expected_audience: &str,
    now_epoch: u64,
    clock_skew_seconds: u64,
) -> QidResult<SamlBearerAssertion> {
    reject_insecure_saml_xml(xml)?;
    if count_start_tags(xml, "Response") > 0 {
        return Err(QidError::BadRequest {
            message: "SAML bearer grant requires a bare Assertion, not a Response".to_string(),
        });
    }
    if count_start_tags(xml, "Assertion") != 1 {
        return Err(QidError::BadRequest {
            message: "SAML bearer assertion must contain exactly one Assertion".to_string(),
        });
    }
    let assertion_start =
        tag_positions(xml, "Assertion")
            .next()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML bearer Assertion is required".to_string(),
            })?;
    let assertion_tag =
        start_tag_body(&xml[assertion_start..]).ok_or_else(|| QidError::BadRequest {
            message: "SAML bearer Assertion start tag is malformed".to_string(),
        })?;
    let assertion_id = attr_value(&assertion_tag, "ID").ok_or_else(|| QidError::BadRequest {
        message: "SAML bearer Assertion ID is required".to_string(),
    })?;
    let assertion_body = element_body(xml, assertion_start, "Assertion")?;
    let profile = inspect_xml_signature_profile(xml, "Assertion")?;
    if profile.reference_uri.as_deref() != Some(&format!("#{assertion_id}")) {
        return Err(QidError::BadRequest {
            message: "SAML bearer Assertion signature must reference the Assertion ID".to_string(),
        });
    }
    let signing_cert =
        profile
            .signing_certificate
            .as_ref()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML bearer Assertion signature must include an X509Certificate"
                    .to_string(),
            })?;
    // Production-grade W3C XMLDSig verification: extract the public
    // key from the X.509 certificate embedded in the SAML signature
    // and verify the canonicalised SignedInfo. This is the symmetric
    // counterpart of the IdP-side signature generation.
    let algorithm = profile
        .signature_method
        .as_deref()
        .and_then(crate::xmldsig::SamlXmlSignatureAlgorithm::from_uri)
        .unwrap_or(crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256);
    let public_key_pem = crate::xmldsig::cert_pem_to_public_key_pem_from_pem(signing_cert)?;
    crate::xmldsig::verify_saml_xml_signature(crate::xmldsig::SamlSignatureInputs {
        document: xml,
        public_key_pem: public_key_pem.as_bytes(),
        profile: algorithm,
    })?;
    let issuer = text_values(assertion_body, "Issuer")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML bearer Assertion Issuer is required".to_string(),
        })?;
    let subject = text_values(assertion_body, "NameID")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML bearer Assertion Subject NameID is required".to_string(),
        })?;
    let audiences = text_values(assertion_body, "Audience");
    if !audiences
        .iter()
        .any(|audience| audience == expected_audience)
    {
        return Err(QidError::BadRequest {
            message: "SAML bearer Assertion audience does not match token endpoint".to_string(),
        });
    }
    let subject_confirmation = tag_positions(assertion_body, "SubjectConfirmation")
        .find_map(|start| start_tag_body(&assertion_body[start..]))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML bearer Assertion SubjectConfirmation is required".to_string(),
        })?;
    if attr_value(&subject_confirmation, "Method").as_deref() != Some(BEARER_CONFIRMATION_METHOD) {
        return Err(QidError::BadRequest {
            message: "SAML bearer Assertion SubjectConfirmation Method must be bearer".to_string(),
        });
    }
    let confirmation_data = tag_positions(assertion_body, "SubjectConfirmationData")
        .find_map(|start| start_tag_body(&assertion_body[start..]))
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML bearer Assertion SubjectConfirmationData is required".to_string(),
        })?;
    if attr_value(&confirmation_data, "Recipient").as_deref() != Some(expected_audience) {
        return Err(QidError::BadRequest {
            message: "SAML bearer Assertion recipient does not match token endpoint".to_string(),
        });
    }
    let expires_at = parse_required_epoch_attr(
        &confirmation_data,
        "NotOnOrAfter",
        "SAML bearer Assertion SubjectConfirmationData NotOnOrAfter is required",
    )?;
    if expires_at <= now_epoch.saturating_sub(clock_skew_seconds) {
        return Err(QidError::BadRequest {
            message: "SAML bearer Assertion has expired".to_string(),
        });
    }
    if let Some(conditions_tag) = tag_positions(assertion_body, "Conditions")
        .find_map(|start| start_tag_body(&assertion_body[start..]))
    {
        if let Some(not_before) = parse_optional_epoch_attr(&conditions_tag, "NotBefore")?
            && not_before > now_epoch + clock_skew_seconds
        {
            return Err(QidError::BadRequest {
                message: "SAML bearer Assertion is not yet valid".to_string(),
            });
        }
        if let Some(condition_expiry) = parse_optional_epoch_attr(&conditions_tag, "NotOnOrAfter")?
            && condition_expiry <= now_epoch.saturating_sub(clock_skew_seconds)
        {
            return Err(QidError::BadRequest {
                message: "SAML bearer Assertion conditions have expired".to_string(),
            });
        }
    }
    let auth_time = tag_positions(assertion_body, "AuthnStatement")
        .find_map(|start| start_tag_body(&assertion_body[start..]))
        .and_then(|tag| attr_value(&tag, "AuthnInstant"))
        .and_then(|value| value.parse::<u64>().ok());
    Ok(SamlBearerAssertion {
        assertion_id,
        issuer,
        subject,
        audience: expected_audience.to_string(),
        expires_at,
        auth_time,
    })
}

pub fn select_name_id_format(sp: &SamlServiceProviderMetadata, preferred: Option<&str>) -> String {
    if let Some(preferred) = preferred
        && sp.name_id_formats.iter().any(|format| format == preferred)
    {
        return preferred.to_string();
    }
    if sp
        .name_id_formats
        .iter()
        .any(|format| format == EMAIL_NAME_ID_FORMAT)
    {
        EMAIL_NAME_ID_FORMAT.to_string()
    } else if sp
        .name_id_formats
        .iter()
        .any(|format| format == PERSISTENT_NAME_ID_FORMAT)
    {
        PERSISTENT_NAME_ID_FORMAT.to_string()
    } else {
        EMAIL_NAME_ID_FORMAT.to_string()
    }
}

pub fn name_id_value(subject: &SamlSubject, format: &str) -> QidResult<String> {
    match format {
        EMAIL_NAME_ID_FORMAT => subject.email.clone().ok_or_else(|| QidError::BadRequest {
            message: "SAML email NameID requires subject email".to_string(),
        }),
        PERSISTENT_NAME_ID_FORMAT => Ok(subject.user_id.clone()),
        _ => Err(QidError::BadRequest {
            message: format!("unsupported SAML NameID format {format}"),
        }),
    }
}

/// Compute a pairwise-id per SAML Subject Identifier Attributes Profile.
/// Uses SHA-256 of (user_id, "@", sp_entity_id) truncated to a base64
/// string, ensuring the identifier is unique per SP but not correlatable.
fn compute_pairwise_id(user_id: &str, sp_entity_id: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"@");
    hasher.update(sp_entity_id.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16])
}

pub fn build_saml_response(req: &SamlAssertionRequest) -> QidResult<SamlIssuedResponse> {
    if req.not_on_or_after <= req.issued_at {
        return Err(QidError::BadRequest {
            message: "SAML assertion expiry must be after issue time".to_string(),
        });
    }
    let response_id = saml_id("resp", &format!("{}:{}", req.issuer, req.issued_at));
    let assertion_id = saml_id(
        "assert",
        &format!(
            "{}:{}:{}",
            req.subject.user_id, req.sp_entity_id, req.issued_at
        ),
    );
    let issue_instant = saml_time(req.issued_at);
    let not_on_or_after = saml_time(req.not_on_or_after);
    let name_id = xml_escape(&name_id_value(&req.subject, &req.name_id_format)?);
    let name_id_format = xml_escape(&req.name_id_format);
    let issuer = xml_escape(&req.issuer);
    let sp_entity_id = xml_escape(&req.sp_entity_id);
    let acs_url = xml_escape(&req.acs_url);
    let request_id_attr = req
        .request_id
        .as_ref()
        .map(|id| format!(r#" InResponseTo="{}""#, xml_escape(id)))
        .unwrap_or_default();
    let session_index_attr = req
        .session_index
        .as_ref()
        .map(|id| format!(r#" SessionIndex="{}""#, xml_escape(id)))
        .unwrap_or_default();
    let pairwise_id = compute_pairwise_id(&req.subject.user_id, &req.sp_entity_id);
    let allowed = |name: &str| -> bool {
        req.attribute_release_policy.is_empty()
            || req.attribute_release_policy.contains(&name.to_string())
    };
    let mut attributes = String::new();
    // SAML Subject Identifier Attributes Profile (subject-id / pairwise-id)
    if allowed("subject-id") {
        push_attribute(
            &mut attributes,
            "urn:oasis:names:tc:SAML:attribute:subject-id",
            &req.subject.user_id,
        );
    }
    if allowed("pairwise-id") {
        push_attribute(
            &mut attributes,
            "urn:oasis:names:tc:SAML:attribute:pairwise-id",
            &pairwise_id,
        );
    }
    if let Some(email) = &req.subject.email
        && allowed("email")
    {
        push_attribute(&mut attributes, "email", email);
    }
    if let Some(display_name) = &req.subject.display_name
        && allowed("displayName")
    {
        push_attribute(&mut attributes, "displayName", display_name);
    }
    if !req.subject.groups.is_empty() && allowed("groups") {
        attributes.push_str(r#"<saml:Attribute Name="groups">"#);
        for group in &req.subject.groups {
            attributes.push_str(&format!(
                r#"<saml:AttributeValue>{}</saml:AttributeValue>"#,
                xml_escape(group)
            ));
        }
        attributes.push_str("</saml:Attribute>");
    }
    let attribute_statement = if attributes.is_empty() {
        String::new()
    } else {
        format!("<saml:AttributeStatement>{attributes}</saml:AttributeStatement>")
    };
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{acs_url}"{request_id_attr}>
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="{BEARER_CONFIRMATION_METHOD}">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"{request_id_attr}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction><saml:Audience>{sp_entity_id}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}"{session_index_attr}>
      <saml:AuthnContext><saml:AuthnContextClassRef>{PASSWORD_PROTECTED_TRANSPORT_AUTHN_CONTEXT}</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    {attribute_statement}
  </saml:Assertion>
</samlp:Response>"#
    );
    reject_insecure_saml_xml(&xml)?;
    metrics::counter!("qid_saml_assertions_issued_total").increment(1);
    Ok(SamlIssuedResponse {
        response_id,
        assertion_id,
        xml,
    })
}

pub fn build_saml_logout_response(
    issuer: &str,
    destination: &str,
    in_response_to: &str,
    issued_at: u64,
) -> QidResult<SamlIssuedLogoutResponse> {
    if destination.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML LogoutResponse destination is required".to_string(),
        });
    }
    if in_response_to.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML LogoutResponse InResponseTo is required".to_string(),
        });
    }
    let response_id = saml_id(
        "logout_resp",
        &format!("{issuer}:{destination}:{in_response_to}:{issued_at}"),
    );
    let issue_instant = saml_time(issued_at);
    let destination_value = destination.to_string();
    let in_response_to_value = in_response_to.to_string();
    let issuer = xml_escape(issuer);
    let destination = xml_escape(destination);
    let in_response_to = xml_escape(in_response_to);
    let xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>"#
    );
    reject_insecure_saml_xml(&xml)?;
    Ok(SamlIssuedLogoutResponse {
        response_id,
        in_response_to: in_response_to_value,
        destination: destination_value,
        xml,
    })
}

#[derive(Debug, Clone)]
pub struct SamlIssuedLogoutRequest {
    pub request_id: String,
    pub xml: String,
}

pub fn build_saml_logout_request(
    issuer: &str,
    destination: &str,
    name_id: &str,
    name_id_format: &str,
    session_indexes: &[String],
    issued_at: u64,
) -> QidResult<SamlIssuedLogoutRequest> {
    if destination.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest destination is required".to_string(),
        });
    }
    if name_id.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest NameID is required".to_string(),
        });
    }
    let request_id = saml_id(
        "logout_req",
        &format!("{issuer}:{destination}:{name_id}:{issued_at}"),
    );
    let issue_instant = saml_time(issued_at);
    let _destination_value = destination.to_string();
    let issuer = xml_escape(issuer);
    let destination = xml_escape(destination);
    let name_id = xml_escape(name_id);
    let name_id_format = xml_escape(name_id_format);

    let mut session_indexes_xml = String::new();
    for session_index in session_indexes {
        session_indexes_xml.push_str(&format!(
            r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#,
            xml_escape(session_index)
        ));
    }

    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>
  {session_indexes_xml}
</samlp:LogoutRequest>"#
    );
    reject_insecure_saml_xml(&xml)?;
    Ok(SamlIssuedLogoutRequest { request_id, xml })
}

pub fn parse_post_binding_authn_request(
    form: &SamlPostBindingForm,
    relay_state_policy: &SamlRelayStatePolicy,
) -> QidResult<SamlAuthnRequest> {
    validate_relay_state(form.relay_state.as_deref(), relay_state_policy)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(form.saml_request.as_bytes())
        .map_err(|_| QidError::BadRequest {
            message: "SAMLRequest must be valid base64".to_string(),
        })?;
    let xml = String::from_utf8(bytes).map_err(|_| QidError::BadRequest {
        message: "SAMLRequest must decode to UTF-8 XML".to_string(),
    })?;
    inspect_saml_authn_request(&xml, form.relay_state.clone())
}

pub fn inspect_saml_authn_request(
    xml: &str,
    relay_state: Option<String>,
) -> QidResult<SamlAuthnRequest> {
    reject_insecure_saml_xml(xml)?;
    if count_start_tags(xml, "AuthnRequest") != 1 {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest must contain exactly one AuthnRequest element".to_string(),
        });
    }
    let authn_start =
        tag_positions(xml, "AuthnRequest")
            .next()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML AuthnRequest is required".to_string(),
            })?;
    let tag_body = start_tag_body(&xml[authn_start..]).ok_or_else(|| QidError::BadRequest {
        message: "SAML AuthnRequest start tag is malformed".to_string(),
    })?;
    let id = attr_value(&tag_body, "ID").ok_or_else(|| QidError::BadRequest {
        message: "SAML AuthnRequest ID is required".to_string(),
    })?;
    let open_end = authn_start
        + xml[authn_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML AuthnRequest start tag is malformed".to_string(),
            })?
        + 1;
    let close_start =
        find_close_tag(&xml[open_end..], "AuthnRequest").ok_or_else(|| QidError::BadRequest {
            message: "SAML AuthnRequest close tag is missing".to_string(),
        })?;
    let body = &xml[open_end..open_end + close_start];
    let issuer = text_values(body, "Issuer")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML AuthnRequest Issuer is required".to_string(),
        })?;
    let name_id_policy_format = tag_positions(body, "NameIDPolicy")
        .next()
        .and_then(|start| start_tag_body(&body[start..]))
        .and_then(|body| attr_value(&body, "Format"));
    Ok(SamlAuthnRequest {
        id,
        issuer,
        assertion_consumer_service_url: attr_value(&tag_body, "AssertionConsumerServiceURL"),
        destination: attr_value(&tag_body, "Destination"),
        protocol_binding: attr_value(&tag_body, "ProtocolBinding"),
        name_id_policy_format,
        force_authn: parse_saml_bool_attr(&tag_body, "ForceAuthn")?,
        is_passive: parse_saml_bool_attr(&tag_body, "IsPassive")?,
        relay_state,
        raw_xml: xml.to_string(),
    })
}

pub fn validate_authn_request_for_sp(
    req: &SamlAuthnRequest,
    sp: &SamlServiceProviderMetadata,
    expected_destination: Option<&str>,
) -> QidResult<()> {
    if req.issuer != sp.entity_id {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest issuer does not match SP metadata".to_string(),
        });
    }
    if let Some(expected_destination) = expected_destination
        && req.destination.as_deref() != Some(expected_destination)
    {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest destination does not match this SSO endpoint".to_string(),
        });
    }
    if let Some(protocol_binding) = &req.protocol_binding
        && protocol_binding != HTTP_POST_BINDING
        && protocol_binding != ARTIFACT_BINDING
    {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest ProtocolBinding must be HTTP-POST or HTTP-Artifact"
                .to_string(),
        });
    }
    if req
        .assertion_consumer_service_url
        .as_deref()
        .is_some_and(|acs| acs != sp.acs_url)
    {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest ACS URL does not match SP metadata".to_string(),
        });
    }
    if let Some(format) = &req.name_id_policy_format
        && !sp.name_id_formats.is_empty()
        && !sp.name_id_formats.iter().any(|known| known == format)
    {
        return Err(QidError::BadRequest {
            message: "SAML AuthnRequest requested unsupported NameID format".to_string(),
        });
    }
    validate_authn_request_signature_profile(req, sp)?;
    Ok(())
}

pub fn parse_post_binding_logout_request(
    form: &SamlPostBindingForm,
    relay_state_policy: &SamlRelayStatePolicy,
) -> QidResult<SamlLogoutRequest> {
    validate_relay_state(form.relay_state.as_deref(), relay_state_policy)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(form.saml_request.as_bytes())
        .map_err(|_| QidError::BadRequest {
            message: "SAMLRequest must be valid base64".to_string(),
        })?;
    let xml = String::from_utf8(bytes).map_err(|_| QidError::BadRequest {
        message: "SAMLRequest must decode to UTF-8 XML".to_string(),
    })?;
    inspect_saml_logout_request(&xml, form.relay_state.clone())
}

pub fn inspect_saml_logout_request(
    xml: &str,
    relay_state: Option<String>,
) -> QidResult<SamlLogoutRequest> {
    reject_insecure_saml_xml(xml)?;
    if count_start_tags(xml, "LogoutRequest") != 1 {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest must contain exactly one LogoutRequest element"
                .to_string(),
        });
    }
    let logout_start =
        tag_positions(xml, "LogoutRequest")
            .next()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML LogoutRequest is required".to_string(),
            })?;
    let tag_body = start_tag_body(&xml[logout_start..]).ok_or_else(|| QidError::BadRequest {
        message: "SAML LogoutRequest start tag is malformed".to_string(),
    })?;
    let id = attr_value(&tag_body, "ID").ok_or_else(|| QidError::BadRequest {
        message: "SAML LogoutRequest ID is required".to_string(),
    })?;
    let open_end = logout_start
        + xml[logout_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML LogoutRequest start tag is malformed".to_string(),
            })?
        + 1;
    let close_start =
        find_close_tag(&xml[open_end..], "LogoutRequest").ok_or_else(|| QidError::BadRequest {
            message: "SAML LogoutRequest close tag is missing".to_string(),
        })?;
    let body = &xml[open_end..open_end + close_start];
    let issuer = text_values(body, "Issuer")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML LogoutRequest Issuer is required".to_string(),
        })?;
    Ok(SamlLogoutRequest {
        id,
        issuer,
        destination: attr_value(&tag_body, "Destination"),
        name_id: text_values(body, "NameID").into_iter().next(),
        session_indexes: text_values(body, "SessionIndex"),
        relay_state,
        raw_xml: xml.to_string(),
    })
}

pub fn validate_logout_request_for_sp(
    req: &SamlLogoutRequest,
    sp: &SamlServiceProviderMetadata,
    expected_destination: Option<&str>,
) -> QidResult<SamlXmlSignatureProfile> {
    if req.issuer != sp.entity_id {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest issuer does not match SP metadata".to_string(),
        });
    }
    if let Some(expected_destination) = expected_destination
        && req.destination.as_deref() != Some(expected_destination)
    {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest destination does not match this SLO endpoint".to_string(),
        });
    }
    let profile = inspect_xml_signature_profile(&req.raw_xml, "LogoutRequest")?;
    if profile.reference_uri.as_deref() != Some(&format!("#{}", req.id)) {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest signature must reference the LogoutRequest ID".to_string(),
        });
    }
    let signing_certificate =
        profile
            .signing_certificate
            .as_ref()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML LogoutRequest signature must include an X509Certificate".to_string(),
            })?;
    if !sp
        .signing_certificates
        .iter()
        .any(|trusted| trusted == signing_certificate)
    {
        return Err(QidError::BadRequest {
            message: "SAML LogoutRequest signing certificate is not trusted".to_string(),
        });
    }
    // Production-grade W3C XMLDSig verification. Same code path as
    // the AuthnRequest / Assertion validators; provided for symmetry
    // so the SLO endpoint is as strict as the SSO endpoint.
    let algorithm = profile
        .signature_method
        .as_deref()
        .and_then(crate::xmldsig::SamlXmlSignatureAlgorithm::from_uri)
        .unwrap_or(crate::xmldsig::SamlXmlSignatureAlgorithm::RsaSha256);
    let public_key_pem = crate::xmldsig::cert_pem_to_public_key_pem_from_pem(signing_certificate)?;
    crate::xmldsig::verify_saml_xml_signature(crate::xmldsig::SamlSignatureInputs {
        document: &req.raw_xml,
        public_key_pem: public_key_pem.as_bytes(),
        profile: algorithm,
    })?;
    Ok(profile)
}

pub fn build_assertion_request_from_authn(
    req: &SamlAuthnRequest,
    sp: &SamlServiceProviderMetadata,
    idp_issuer: &str,
    subject: SamlSubject,
    issued_at: u64,
    ttl_seconds: u64,
    session_index: Option<String>,
) -> QidResult<SamlAssertionRequest> {
    if ttl_seconds == 0 {
        return Err(QidError::BadRequest {
            message: "SAML assertion ttl must be positive".to_string(),
        });
    }
    validate_authn_request_for_sp(req, sp, None)?;
    Ok(SamlAssertionRequest {
        issuer: idp_issuer.to_string(),
        sp_entity_id: sp.entity_id.clone(),
        acs_url: req
            .assertion_consumer_service_url
            .clone()
            .unwrap_or_else(|| sp.acs_url.clone()),
        request_id: Some(req.id.clone()),
        subject,
        name_id_format: select_name_id_format(sp, req.name_id_policy_format.as_deref()),
        issued_at,
        not_on_or_after: issued_at + ttl_seconds,
        session_index,
        attribute_release_policy: sp.attribute_release_policy.clone(),
    })
}

pub fn subject_from_browser_session(subject: &SamlBrowserSubject) -> SamlSubject {
    SamlSubject {
        user_id: subject.user.id.clone(),
        email: subject.user.email.clone(),
        display_name: subject.user.display_name.clone(),
        groups: vec![],
    }
}

pub fn build_saml_post_response(
    issued: &SamlIssuedResponse,
    acs_url: &str,
    relay_state: Option<&str>,
) -> SamlPostResponse {
    build_saml_post_response_xml(&issued.xml, acs_url, relay_state)
}

pub fn build_saml_logout_post_response(
    issued: &SamlIssuedLogoutResponse,
    slo_url: &str,
    relay_state: Option<&str>,
) -> SamlPostResponse {
    build_saml_post_response_xml(&issued.xml, slo_url, relay_state)
}

pub fn build_saml_post_response_xml(
    xml: &str,
    destination_url: &str,
    relay_state: Option<&str>,
) -> SamlPostResponse {
    let saml_response = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
    let relay_state_input = relay_state
        .map(|value| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                xml_escape(value)
            )
        })
        .unwrap_or_default();
    let html = format!(
        r#"<!doctype html>
<html>
  <body onload="document.forms[0].submit()">
    <form method="post" action="{acs_url}">
      <input type="hidden" name="SAMLResponse" value="{saml_response}"/>
      {relay_state_input}
      <noscript><button type="submit">Continue</button></noscript>
    </form>
  </body>
</html>"#,
        acs_url = xml_escape(destination_url),
        saml_response = xml_escape(&saml_response),
        relay_state_input = relay_state_input,
    );
    SamlPostResponse {
        acs_url: destination_url.to_string(),
        relay_state: relay_state.map(ToString::to_string),
        saml_response,
        html,
    }
}

#[derive(Debug, Clone)]
pub struct SamlRedirectResponse {
    pub redirect_url: String,
}

pub fn build_saml_logout_redirect_request(
    issued: &SamlIssuedLogoutRequest,
    destination_url: &str,
    relay_state: Option<&str>,
) -> SamlRedirectResponse {
    let saml_request = base64::engine::general_purpose::STANDARD.encode(issued.xml.as_bytes());
    let relay_state_param = relay_state
        .map(|value| format!("&RelayState={}", urlencoding::encode(value)))
        .unwrap_or_default();
    let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    let redirect_url = format!(
        "{}?SAMLRequest={}&SigAlg={}{}",
        destination_url,
        urlencoding::encode(&saml_request),
        urlencoding::encode(sig_alg),
        relay_state_param
    );
    SamlRedirectResponse { redirect_url }
}

pub fn build_saml_logout_redirect_response(
    issued: &SamlIssuedLogoutResponse,
    destination_url: &str,
    relay_state: Option<&str>,
) -> SamlRedirectResponse {
    let saml_response = base64::engine::general_purpose::STANDARD.encode(issued.xml.as_bytes());
    let relay_state_param = relay_state
        .map(|value| format!("&RelayState={}", urlencoding::encode(value)))
        .unwrap_or_default();
    let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    let redirect_url = format!(
        "{}?SAMLResponse={}&SigAlg={}{}",
        destination_url,
        urlencoding::encode(&saml_response),
        urlencoding::encode(sig_alg),
        relay_state_param
    );
    SamlRedirectResponse { redirect_url }
}
