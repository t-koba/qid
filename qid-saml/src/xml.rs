use crate::SamlXmlSignatureProfile;
use qid_core::error::{QidError, QidResult};
use std::collections::BTreeSet;

pub(crate) fn reject_insecure_saml_xml(xml: &str) -> QidResult<()> {
    for tag in &["SignatureMethod", "DigestMethod"] {
        for start in tag_positions(xml, tag) {
            if let Some(tag_body) = start_tag_body(&xml[start..])
                && let Some(alg) = attr_value(&tag_body, "Algorithm")
            {
                reject_unsupported_signature_algorithm(&alg)?;
            }
        }
    }
    let mut ids = BTreeSet::new();
    for attr in ["ID", "Id", "id"] {
        for value in attr_values(xml, attr) {
            if !ids.insert(value.clone()) {
                return Err(QidError::BadRequest {
                    message: format!("duplicate SAML XML ID {value}"),
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn saml_id(prefix: &str, material: &str) -> String {
    format!("{prefix}_{}", qid_core::util::sha256_base64url(material))
}

pub(crate) fn saml_time(epoch_seconds: u64) -> String {
    format!("{epoch_seconds}")
}

pub(crate) fn push_attribute(xml: &mut String, name: &str, value: &str) {
    xml.push_str(&format!(
        r#"<saml:Attribute Name="{}"><saml:AttributeValue>{}</saml:AttributeValue></saml:Attribute>"#,
        xml_escape(name),
        xml_escape(value)
    ));
}

pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn parse_saml_bool_attr(tag_body: &str, attr: &str) -> QidResult<bool> {
    match attr_value(tag_body, attr).as_deref() {
        Some("true") | Some("1") => Ok(true),
        Some("false") | Some("0") | None => Ok(false),
        Some(_) => Err(QidError::BadRequest {
            message: format!("SAML {attr} must be a boolean value"),
        }),
    }
}

pub(crate) fn insert_after_first_child(
    xml: &str,
    parent_tag: &str,
    child_tag: &str,
    insertion: &str,
) -> Option<String> {
    let parent_start = tag_positions(xml, parent_tag).next()?;
    let parent_open_end = parent_start + xml[parent_start..].find('>')? + 1;
    let child_relative = tag_positions(&xml[parent_open_end..], child_tag).next()?;
    let child_start = parent_open_end + child_relative;
    let child_open_end = child_start + xml[child_start..].find('>')? + 1;
    let close_relative = find_close_tag(&xml[child_open_end..], child_tag)?;
    let insert_at =
        child_open_end + close_relative + close_tag_len(&xml[child_open_end + close_relative..])?;
    Some(format!(
        "{}{}{}",
        &xml[..insert_at],
        insertion,
        &xml[insert_at..]
    ))
}

pub(crate) fn close_tag_len(fragment: &str) -> Option<usize> {
    Some(fragment.find('>')? + 1)
}

pub(crate) fn find_service_location(xml: &str, tag: &str, binding: &str) -> Option<String> {
    for start in tag_positions(xml, tag) {
        let tag_body = start_tag_body(&xml[start..])?;
        if attr_value(&tag_body, "Binding").as_deref() == Some(binding) {
            return attr_value(&tag_body, "Location");
        }
    }
    None
}

pub(crate) fn inspect_xml_signature_profile(
    xml: &str,
    signed_element: &str,
) -> QidResult<SamlXmlSignatureProfile> {
    reject_insecure_saml_xml(xml)?;

    // Prefer DOM-based parsing (eliminates parser-differential between
    // signature verification and claim extraction).  Fall back to the
    // hand-written string scanner when the XML is not well-formed
    // (e.g. legacy generators that embed raw '<' in attribute values).
    if let Ok(doc) = crate::saml_document::SamlDocument::parse(xml) {
        let profile = doc.inspect_signature_profile(signed_element)?;
        return Ok(profile);
    }

    // String-scanner fallback path.
    let signed_start =
        tag_positions(xml, signed_element)
            .next()
            .ok_or_else(|| QidError::BadRequest {
                message: format!("SAML signed element {signed_element} is required"),
            })?;
    let signed_tag_body =
        start_tag_body(&xml[signed_start..]).ok_or_else(|| QidError::BadRequest {
            message: format!("SAML signed element {signed_element} start tag is malformed"),
        })?;
    let signed_open_end = signed_start + signed_tag_body.len();
    let element_id = attr_value(&signed_tag_body, "ID").ok_or_else(|| QidError::BadRequest {
        message: format!("SAML signed element {signed_element} must have an ID attribute"),
    })?;
    let signed_close_start =
        find_close_tag(&xml[signed_open_end..], signed_element).ok_or_else(|| {
            QidError::BadRequest {
                message: format!("SAML signed element {signed_element} close tag is missing"),
            }
        })?;
    let signed_body = &xml[signed_open_end..signed_open_end + signed_close_start];
    let signatures: Vec<_> = tag_positions(signed_body, "Signature").collect();
    if signatures.len() != 1 {
        return Err(QidError::BadRequest {
            message: "SAML signed element must contain exactly one Signature".to_string(),
        });
    }
    // XSW (XML Signature Wrapping) hardening: the only Signature element
    // inside the signed parent must be the one whose Reference URI matches
    // this element's ID.
    for forbidden in ["Assertion", "Extensions", "Statement"] {
        if tag_positions(signed_body, forbidden).count() > 0 {
            return Err(QidError::BadRequest {
                message: format!(
                    "SAML signed {signed_element} contains forbidden sibling element {forbidden}"
                ),
            });
        }
    }
    let signature_start = signatures[0];
    let signature_open_end = signature_start
        + signed_body[signature_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML Signature start tag is malformed".to_string(),
            })?
        + 1;
    let signature_close_start = find_close_tag(&signed_body[signature_open_end..], "Signature")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML Signature close tag is missing".to_string(),
        })?;
    let signature_xml = &signed_body[signature_start..signature_open_end + signature_close_start];
    let reference_uri =
        first_tag_attr(signature_xml, "Reference", "URI").ok_or_else(|| QidError::BadRequest {
            message: "SAML Signature Reference URI is required".to_string(),
        })?;
    if reference_uri != format!("#{element_id}") {
        return Err(QidError::BadRequest {
            message: format!("SAML Signature Reference URI must match the {signed_element} ID"),
        });
    }
    let signature_method = first_tag_attr(signature_xml, "SignatureMethod", "Algorithm")
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML SignatureMethod Algorithm is required".to_string(),
        })?;
    let digest_method =
        first_tag_attr(signature_xml, "DigestMethod", "Algorithm").ok_or_else(|| {
            QidError::BadRequest {
                message: "SAML DigestMethod Algorithm is required".to_string(),
            }
        })?;
    reject_unsupported_signature_algorithm(&signature_method)?;
    reject_unsupported_signature_algorithm(&digest_method)?;
    Ok(SamlXmlSignatureProfile {
        reference_uri: Some(reference_uri),
        signature_method: Some(signature_method),
        digest_method: Some(digest_method),
        signing_certificate: text_values(signature_xml, "X509Certificate")
            .into_iter()
            .next()
            .map(|value| value.split_whitespace().collect::<String>()),
    })
}

/// DOM-based claim extraction: text content of the first element matching
/// `tag`. Returns `None` when the XML is not well-formed (falls back to
/// string scanner transparently).
pub(crate) fn dom_element_text(xml: &str, tag: &str) -> Option<String> {
    crate::saml_document::SamlDocument::parse(xml)
        .ok()
        .and_then(|doc| doc.element_text(tag))
}

/// DOM-based attribute extraction: attribute value from the first element
/// matching `tag`. Returns `None` when the XML is not well-formed.
pub(crate) fn dom_element_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    crate::saml_document::SamlDocument::parse(xml)
        .ok()
        .and_then(|doc| doc.element_attr(tag, attr))
}

pub(crate) fn reject_unsupported_signature_algorithm(algorithm: &str) -> QidResult<()> {
    let lowered = algorithm.to_ascii_lowercase();
    // Only allow SHA-2 family (SHA-256, SHA-384, SHA-512) algorithms
    if lowered.contains("md5") || lowered.contains("sha1") || lowered.contains("hmac") {
        return Err(QidError::BadRequest {
            message: "SAML signature algorithm is not allowed".to_string(),
        });
    }
    let valid =
        lowered.contains("sha256") || lowered.contains("sha384") || lowered.contains("sha512");
    if !valid {
        return Err(QidError::BadRequest {
            message: "SAML signature algorithm is not allowed".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn first_tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = tag_positions(xml, tag).next()?;
    let tag_body = start_tag_body(&xml[start..])?;
    attr_value(&tag_body, attr)
}

pub(crate) fn key_descriptor_certificates(xml: &str, use_filter: Option<&str>) -> Vec<String> {
    let mut certificates = Vec::new();
    for start in tag_positions(xml, "KeyDescriptor") {
        let Some(tag_body) = start_tag_body(&xml[start..]) else {
            continue;
        };
        if let Some(use_filter) = use_filter
            && attr_value(&tag_body, "use").as_deref() != Some(use_filter)
        {
            continue;
        }
        let Some(open_end) = xml[start..].find('>') else {
            continue;
        };
        let content_start = start + open_end + 1;
        let Some(close_start) = find_close_tag(&xml[content_start..], "KeyDescriptor") else {
            continue;
        };
        let descriptor = &xml[content_start..content_start + close_start];
        certificates.extend(
            text_values(descriptor, "X509Certificate")
                .into_iter()
                .map(|value| value.split_whitespace().collect::<String>())
                .filter(|value| !value.is_empty()),
        );
    }
    certificates
}

pub(crate) fn entity_category_values(xml: &str) -> Vec<String> {
    let mut categories = BTreeSet::new();
    for start in tag_positions(xml, "Attribute") {
        let Some(tag_body) = start_tag_body(&xml[start..]) else {
            continue;
        };
        let Some(name) = attr_value(&tag_body, "Name") else {
            continue;
        };
        if name != "http://macedir.org/entity-category" {
            continue;
        }
        let Some(open_end) = xml[start..].find('>') else {
            continue;
        };
        let content_start = start + open_end + 1;
        let Some(close_start) = find_close_tag(&xml[content_start..], "Attribute") else {
            continue;
        };
        let attribute_xml = &xml[content_start..content_start + close_start];
        for value in text_values(attribute_xml, "AttributeValue") {
            let normalized = value.trim().to_string();
            if !normalized.is_empty() {
                categories.insert(normalized);
            }
        }
    }
    categories.into_iter().collect()
}

pub(crate) fn entity_descriptor_xml_fragments(xml: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    for start in tag_positions(xml, "EntityDescriptor") {
        let Some(open_end) = xml[start..].find('>') else {
            continue;
        };
        let content_start = start + open_end + 1;
        let Some(close_start) = find_close_tag(&xml[content_start..], "EntityDescriptor") else {
            continue;
        };
        let end = content_start
            + close_start
            + close_tag_len(&xml[content_start + close_start..]).unwrap_or(0);
        if end > start {
            fragments.push(xml[start..end].to_string());
        }
    }
    fragments
}

pub(crate) fn attr_value_after(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = tag_positions(xml, tag).next()?;
    let tag_body = start_tag_body(&xml[start..])?;
    attr_value(&tag_body, attr)
}

pub(crate) fn element_body<'a>(
    xml: &'a str,
    element_start: usize,
    tag: &str,
) -> QidResult<&'a str> {
    let open_end = element_start
        + xml[element_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: format!("SAML {tag} start tag is malformed"),
            })?
        + 1;
    let close_start =
        find_close_tag(&xml[open_end..], tag).ok_or_else(|| QidError::BadRequest {
            message: format!("SAML {tag} close tag is missing"),
        })?;
    Ok(&xml[open_end..open_end + close_start])
}

pub(crate) fn parse_required_epoch_attr(
    tag_body: &str,
    attr: &str,
    missing_message: &str,
) -> QidResult<u64> {
    let value = attr_value(tag_body, attr).ok_or_else(|| QidError::BadRequest {
        message: missing_message.to_string(),
    })?;
    value.parse::<u64>().map_err(|_| QidError::BadRequest {
        message: format!("SAML {attr} must be epoch seconds"),
    })
}

pub(crate) fn parse_optional_epoch_attr(tag_body: &str, attr: &str) -> QidResult<Option<u64>> {
    let Some(value) = attr_value(tag_body, attr) else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| QidError::BadRequest {
            message: format!("SAML {attr} must be epoch seconds"),
        })
}

pub(crate) fn attr_values(xml: &str, attr: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(attr) {
        let before = rest.as_bytes()[..pos].last().copied();
        let after = rest.as_bytes()[pos + attr.len()..].first().copied();
        let is_attr_boundary = before
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'<'))
            && after == Some(b'=');
        if !is_attr_boundary {
            rest = &rest[pos + attr.len()..];
            continue;
        }
        rest = &rest[pos + attr.len() + 1..];
        let Some(stripped) = rest.strip_prefix('"') else {
            continue;
        };
        rest = stripped;
        let Some(end) = rest.find('"') else {
            break;
        };
        values.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    values
}

pub(crate) fn attr_value(tag_body: &str, attr: &str) -> Option<String> {
    attr_values(tag_body, attr).into_iter().next()
}

pub(crate) fn text_values(xml: &str, tag: &str) -> Vec<String> {
    let mut values = Vec::new();
    for start in tag_positions(xml, tag) {
        let Some(open_end) = xml[start..].find('>') else {
            continue;
        };
        let content_start = start + open_end + 1;
        let Some(close_start) = find_close_tag(&xml[content_start..], tag) else {
            continue;
        };
        values.push(
            xml[content_start..content_start + close_start]
                .trim()
                .to_string(),
        );
    }
    values
}

pub(crate) fn element_ids(xml: &str, tag: &str) -> Vec<String> {
    tag_positions(xml, tag)
        .filter_map(|start| {
            let tag_body = start_tag_body(&xml[start..])?;
            attr_value(&tag_body, "ID")
        })
        .collect()
}

pub(crate) fn count_start_tags(xml: &str, tag: &str) -> usize {
    tag_positions(xml, tag).count()
}

pub(crate) fn tag_positions<'a>(xml: &'a str, tag: &'a str) -> impl Iterator<Item = usize> + 'a {
    xml.match_indices('<').filter_map(move |(idx, _)| {
        let rest = &xml[idx + 1..];
        if rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('!') {
            return None;
        }
        let name_end = rest
            .find(|ch: char| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        let local = name
            .rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(name);
        (local == tag).then_some(idx)
    })
}

pub(crate) fn start_tag_body(fragment: &str) -> Option<String> {
    let end = fragment.find('>')?;
    Some(fragment[..=end].to_string())
}

pub(crate) fn find_close_tag(fragment: &str, tag: &str) -> Option<usize> {
    let mut depth = 1u32;
    let mut offset = 0usize;
    loop {
        let remaining = &fragment[offset..];
        let lt_pos = remaining.find('<')?;
        let after_lt = &remaining[lt_pos + 1..];
        if let Some(name_part) = after_lt.strip_prefix('/') {
            let name_end = name_part
                .find(|ch: char| ch.is_ascii_whitespace() || ch == '>')
                .unwrap_or(name_part.len());
            let name = &name_part[..name_end];
            let local = name
                .rsplit_once(':')
                .map(|(_, local)| local)
                .unwrap_or(name);
            if local == tag {
                depth -= 1;
                if depth == 0 {
                    return Some(offset + lt_pos);
                }
            }
            let close_tag_end = name_part.find('>')?;
            offset += lt_pos + 2 + close_tag_end + 1;
        } else if after_lt.starts_with('?') || after_lt.starts_with('!') {
            let end = after_lt.find('>')?;
            offset += lt_pos + 1 + end + 1;
        } else {
            let name_end = after_lt
                .find(|ch: char| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
                .unwrap_or(after_lt.len());
            let name = &after_lt[..name_end];
            let local = name
                .rsplit_once(':')
                .map(|(_, local)| local)
                .unwrap_or(name);
            let tag_end = after_lt.find('>')?;
            let is_self_closing = after_lt[..tag_end].ends_with('/');
            if local == tag && !is_self_closing {
                depth += 1;
            }
            offset += lt_pos + 1 + tag_end + 1;
        }
    }
}
