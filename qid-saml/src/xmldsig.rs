//! Custom signing and serialization helpers; not a general W3C XMLDSig signer.
//! Inbound verification uses bergshamra through the separate verification module.

use base64::Engine;
use qid_core::error::{QidError, QidResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Exact XMLDSig algorithm URIs accepted by the verifier. Matching is by
/// equality: invented URIs that merely contain these strings are rejected.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const EXC_C14N_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Signature algorithms accepted by this module's limited profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlXmlSignatureAlgorithm {
    /// RSA with SHA-256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`).
    RsaSha256,
    /// ECDSA with SHA-256 (`http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`).
    EcdsaSha256,
}

impl SamlXmlSignatureAlgorithm {
    /// Parse the XMLDSig `SignatureMethod` URI accepted by qid.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(Self::EcdsaSha256),
            _ => None,
        }
    }
}

fn reject_insecure(document: &str) -> QidResult<()> {
    for algorithm in signature_algorithm_values(document) {
        let lowered = algorithm.to_ascii_lowercase();
        if lowered.contains("sha1") || lowered.contains("md5") {
            return Err(QidError::BadRequest {
                message: "SAML XMLDSig rejects SHA-1/MD5 signatures or digests".to_string(),
            });
        }
    }
    Ok(())
}

fn signature_algorithm_values(document: &str) -> Vec<String> {
    let mut values = Vec::new();
    for tag in ["SignatureMethod", "DigestMethod"] {
        let mut rest = document;
        while let Some(start) = find_open_tag(rest, tag) {
            let tag_end = rest[start..]
                .find('>')
                .map(|offset| start + offset)
                .unwrap_or(rest.len());
            let open_tag = &rest[start..tag_end];
            if let Some(value) = extract_attr_from_open_tag(open_tag, "Algorithm") {
                values.push(value);
            }
            rest = &rest[tag_end..];
            if rest.is_empty() {
                break;
            }
        }
    }
    values
}

fn extract_attr_from_open_tag(open_tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let pos = open_tag.find(&needle)? + needle.len();
    let rest = &open_tag[pos..];
    let stop = rest.find('"')?;
    Some(rest[..stop].to_string())
}

fn find_open_tag(document: &str, name: &str) -> Option<usize> {
    let needle1 = format!("<{name}");
    let needle2 = format!("<ds:{name}");
    document.find(&needle1).or_else(|| document.find(&needle2))
}

fn extract_ns_prefixes(signature: &str) -> Vec<(String, String)> {
    let mut prefixes = Vec::new();
    // Scan for xmlns:prefix="uri" patterns in the signature element
    for part in signature.split("xmlns:") {
        if let Some(eq_pos) = part.find('=') {
            let prefix = part[..eq_pos].trim().to_string();
            if prefix.is_empty() || prefix.contains('>') || prefix.contains(' ') {
                continue;
            }
            let after_eq = &part[eq_pos + 1..];
            if let Some(uri_start) = after_eq.find('"') {
                let uri = &after_eq[uri_start + 1..];
                if let Some(uri_end) = uri.find('"') {
                    prefixes.push((prefix, uri[..uri_end].to_string()));
                }
            }
        }
    }
    // Always include well-known SAML namespace prefixes
    let known = [
        ("ds", "http://www.w3.org/2000/09/xmldsig#"),
        ("saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
        ("samlp", "urn:oasis:names:tc:SAML:2.0:protocol"),
        ("xenc", "http://www.w3.org/2001/04/xmlenc#"),
    ];
    for (prefix, uri) in &known {
        if !prefixes.iter().any(|(p, _)| p == prefix) {
            prefixes.push((prefix.to_string(), uri.to_string()));
        }
    }
    prefixes
}

/// Serialize an element using qid's custom, limited C14N-10-mode profile for
/// digest or signature computation. This is not a W3C XML C14N implementation:
/// it sorts attributes and drops comments/declarations, but also rewrites
/// qualified element names to local names. It is not suitable for arbitrary
/// XMLDSig documents or a claim of standards interoperability.
///
/// Use only with the limited SAML profile handled by this module.
pub fn canonicalize_saml_element(element: &str) -> QidResult<String> {
    let mut out = String::with_capacity(element.len());
    let trimmed = element.trim();
    let declared_prefixes = &mut BTreeSet::new();
    canonicalize_into(trimmed, &mut out, declared_prefixes)?;
    Ok(out)
}

/// Serialize using qid's custom exclusive-mode profile, not the W3C Exclusive
/// XML Canonicalization algorithm. This mode preserves element-name prefixes
/// and emits `xmlns:prefix` declarations for prefixes found in element names.
///
/// `ns_prefixes` supplies namespace bindings for that serialization. This
/// helper does not establish general XMLDSig or namespace-prefix
/// interoperability.
pub fn canonicalize_exclusive(
    element: &str,
    ns_prefixes: &[(String, String)],
) -> QidResult<String> {
    let mut out = String::with_capacity(element.len());
    let trimmed = element.trim();
    let declared_prefixes = &mut BTreeSet::new();
    let used_prefixes = &mut BTreeSet::new();
    canonicalize_into_with_prefixes(trimmed, &mut out, declared_prefixes, used_prefixes)?;
    // Emit xmlns declarations only for used prefixes into the first opening tag
    let mut ns_decls = String::new();
    for (prefix, uri) in ns_prefixes {
        if used_prefixes.contains(prefix.as_str()) {
            ns_decls.push_str(&format!(" xmlns:{}=\"{}\"", prefix, uri));
        }
    }
    if !ns_decls.is_empty() {
        // Insert namespace declarations before the first `>` that closes the
        // opening tag of the root element.  The output starts with `<ElementName`
        // so the first `>` is the opening-tag terminator.
        if let Some(first_close) = out.find('>') {
            out.insert_str(first_close, &ns_decls);
        }
    }
    Ok(out)
}

fn canonicalize_into(
    input: &str,
    out: &mut String,
    declared_prefixes: &mut BTreeSet<String>,
) -> QidResult<()> {
    let mut idx = 0;
    while idx < input.len() {
        let rest = &input[idx..];
        if let Some(pos) = rest.find('<') {
            if pos > 0 {
                out.push_str(&rest[..pos]);
                idx += pos;
                continue;
            }
        } else {
            out.push_str(rest);
            break;
        }
        let _tag_start = idx;
        if rest.starts_with("<?") {
            // XML declaration. Drop processing instructions and
            // comments from the canonical octet stream.
            if let Some(end) = rest.find("?>") {
                idx += end + 2;
                continue;
            }
            break;
        }
        if rest.starts_with("<!--") {
            if let Some(end) = rest.find("-->") {
                idx += end + 3;
                continue;
            }
            break;
        }
        if rest.starts_with("<![CDATA[") {
            if let Some(end) = rest.find("]]>") {
                let body = &rest[9..end];
                out.push_str(body);
                idx += end + 3;
                continue;
            }
            break;
        }
        if rest.starts_with("</") {
            let close = rest.find('>').ok_or_else(|| QidError::BadRequest {
                message: "SAML canonicalization: unterminated close tag".to_string(),
            })?;
            let name = &rest[2..close];
            let name = name.trim();
            let local = local_name(name);
            out.push_str("</");
            out.push_str(local);
            out.push('>');
            idx += close + 1;
            declared_prefixes.remove(local);
            continue;
        }
        let close = rest.find('>').ok_or_else(|| QidError::BadRequest {
            message: "SAML canonicalization: unterminated element start tag".to_string(),
        })?;
        let raw_tag = &rest[1..close];
        let (name, attrs, self_closing) = parse_start_tag(raw_tag)?;
        let local = local_name(&name);
        let mut attr_pairs: Vec<(&str, &str)> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        attr_pairs.sort_by(|a, b| a.0.cmp(b.0));
        out.push('<');
        out.push_str(local);
        for (key, value) in attr_pairs {
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escape_attr(value));
            out.push('"');
        }
        if self_closing {
            out.push_str("/>");
            idx += close + 1;
            continue;
        }
        out.push('>');
        idx += close + 1;
        declared_prefixes.insert(local.to_string());
        if let Some(inner_start) = input[idx..].find('>') {
            let _ = inner_start;
        }
        // Walk inner content looking for the matching close tag, taking
        // nested same-named elements into account.
        let mut depth: usize = 1;
        let mut cursor = idx;
        while depth > 0 && cursor < input.len() {
            let rest_inner = &input[cursor..];
            let next_open = find_open_tag_for_local(rest_inner, local)
                .map(|(pos, _)| pos)
                .unwrap_or(usize::MAX);
            let next_close = find_close_tag_for_local(rest_inner, local)
                .map(|(pos, _)| pos)
                .unwrap_or(usize::MAX);
            if next_close == usize::MAX {
                return Err(QidError::BadRequest {
                    message: format!("SAML canonicalization: closing tag for {local} not found"),
                });
            }
            if next_open < next_close {
                depth += 1;
                let (_, open_end) =
                    find_open_tag_for_local(rest_inner, local).ok_or_else(|| {
                        QidError::BadRequest {
                            message: format!(
                                "SAML canonicalization: nested open tag for {local} not found"
                            ),
                        }
                    })?;
                cursor += open_end;
            } else {
                depth -= 1;
                let (close_pos, close_end) = find_close_tag_for_local(rest_inner, local)
                    .ok_or_else(|| QidError::BadRequest {
                        message: format!(
                            "SAML canonicalization: closing tag for {local} not found"
                        ),
                    })?;
                let inner_end = cursor + close_pos;
                let inner = &input[idx..inner_end];
                canonicalize_into(inner, out, declared_prefixes)?;
                out.push_str("</");
                out.push_str(local);
                out.push('>');
                cursor += close_end;
                idx = cursor;
            }
        }
    }
    Ok(())
}

/// Canonicalize a subtree tracking used namespace prefixes for exc-c14n.
/// Outputs element names with original namespace prefixes and records
/// the prefix portion of each element name in `used_prefixes`.
fn canonicalize_into_with_prefixes(
    input: &str,
    out: &mut String,
    _declared_prefixes: &mut BTreeSet<String>,
    used_prefixes: &mut BTreeSet<String>,
) -> QidResult<()> {
    let mut idx = 0;
    while idx < input.len() {
        let rest = &input[idx..];
        if let Some(pos) = rest.find('<') {
            if pos > 0 {
                out.push_str(&rest[..pos]);
                idx += pos;
                continue;
            }
        } else {
            out.push_str(rest);
            break;
        }
        if rest.starts_with("<?") {
            if let Some(end) = rest.find("?>") {
                idx += end + 2;
                continue;
            }
            break;
        }
        if rest.starts_with("<!--") {
            if let Some(end) = rest.find("-->") {
                idx += end + 3;
                continue;
            }
            break;
        }
        if rest.starts_with("<![CDATA[") {
            if let Some(end) = rest.find("]]>") {
                let body = &rest[9..end];
                out.push_str(body);
                idx += end + 3;
                continue;
            }
            break;
        }
        if rest.starts_with("</") {
            let close = rest.find('>').ok_or_else(|| QidError::BadRequest {
                message: "SAML canonicalization: unterminated close tag".to_string(),
            })?;
            let name = &rest[2..close];
            let name = name.trim();
            if let Some((prefix, _)) = name.split_once(':') {
                used_prefixes.insert(prefix.to_string());
            }
            out.push_str("</");
            out.push_str(name);
            out.push('>');
            idx += close + 1;
            continue;
        }
        let close = rest.find('>').ok_or_else(|| QidError::BadRequest {
            message: "SAML canonicalization: unterminated element start tag".to_string(),
        })?;
        let raw_tag = &rest[1..close];
        let (name, attrs, self_closing) = parse_start_tag(raw_tag)?;
        if let Some((prefix, _)) = name.split_once(':') {
            used_prefixes.insert(prefix.to_string());
        }
        let mut attr_pairs: Vec<(&str, &str)> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // Remove xmlns:* attributes; they are handled via ns_prefixes
        attr_pairs.retain(|(k, _)| !k.starts_with("xmlns"));
        attr_pairs.sort_by(|a, b| a.0.cmp(b.0));
        out.push('<');
        out.push_str(&name);
        for (key, value) in attr_pairs {
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escape_attr(value));
            out.push('"');
        }
        if self_closing {
            out.push_str("/>");
            idx += close + 1;
            continue;
        }
        out.push('>');
        idx += close + 1;
        let local = local_name(&name);
        // Walk inner content matching close tags by local name
        let mut depth: usize = 1;
        let mut cursor = idx;
        while depth > 0 && cursor < input.len() {
            let rest_inner = &input[cursor..];
            let next_open_pos = rest_inner.find('<').unwrap_or(usize::MAX);
            if next_open_pos == usize::MAX {
                break;
            }
            let abs_open = cursor + next_open_pos;
            if let Some(rest) = rest_inner.strip_prefix("</") {
                let close_end = rest
                    .find('>')
                    .map(|p| abs_open + 2 + p + 1)
                    .unwrap_or(usize::MAX);
                let tag_end = rest.find('>').unwrap_or(usize::MAX);
                let tag_name = rest[..tag_end].trim();
                if local_name(tag_name) == local {
                    depth -= 1;
                    if depth == 0 {
                        let inner = &input[idx..abs_open];
                        canonicalize_into_with_prefixes(
                            inner,
                            out,
                            _declared_prefixes,
                            used_prefixes,
                        )?;
                        out.push_str("</");
                        out.push_str(tag_name.trim());
                        out.push('>');
                        idx = close_end;
                        break;
                    }
                }
                if close_end != usize::MAX {
                    cursor = close_end;
                } else {
                    cursor = abs_open + 1;
                }
            } else if !rest_inner.starts_with("<?")
                && !rest_inner.starts_with("<!--")
                && !rest_inner.starts_with("<![CDATA[")
            {
                // Check if this is an open tag with the same local name
                if let Some(ce) = rest_inner.find('>') {
                    if ce == 0 {
                        cursor = abs_open + 1;
                        continue;
                    }
                    let raw = &rest_inner[1..ce];
                    let (oname, _self_c) = {
                        let trimmed = raw.trim();
                        let self_c = trimmed.ends_with('/');
                        let body = if self_c {
                            &trimmed[..trimmed.len() - 1]
                        } else {
                            trimmed
                        };
                        let name = body.split_whitespace().next().unwrap_or("");
                        (name.to_string(), self_c)
                    };
                    if local_name(&oname) == local && !oname.is_empty() {
                        depth += 1;
                    }
                    cursor = abs_open + ce + 1;
                } else {
                    cursor = abs_open + 1;
                }
            } else {
                cursor = abs_open + 1;
            }
        }
    }
    Ok(())
}

type StartTag = (String, Vec<(String, String)>, bool);

fn parse_start_tag(raw: &str) -> QidResult<StartTag> {
    let trimmed = raw.trim();
    let self_closing = trimmed.ends_with('/');
    let body = if self_closing {
        &trimmed[..trimmed.len() - 1]
    } else {
        trimmed
    };
    let mut iter = body.splitn(2, |c: char| c.is_whitespace());
    let name = iter
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "SAML canonicalization: empty element name".to_string(),
        })?
        .to_string();
    let mut attrs = Vec::new();
    if let Some(remainder) = iter.next() {
        for pair in split_attrs(remainder) {
            let (key, value) = pair?;
            attrs.push((key, value));
        }
    }
    Ok((name, attrs, self_closing))
}

fn split_attrs(input: &str) -> impl Iterator<Item = QidResult<(String, String)>> + '_ {
    let mut rest = input.trim_start();
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let eq = rest.find('=')?;
        let key = rest[..eq].trim().to_string();
        rest = rest[eq + 1..].trim_start();
        if !rest.starts_with('"') {
            return Some(Err(QidError::BadRequest {
                message: "SAML canonicalization: attribute value must be quoted".to_string(),
            }));
        }
        rest = &rest[1..];
        let end = rest.find('"')?;
        let value = rest[..end].to_string();
        rest = rest[end + 1..].trim_start();
        Some(Ok((key, value)))
    })
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            other => out.push(other),
        }
    }
    out
}

fn find_close_tag_for_local(haystack: &str, local: &str) -> Option<(usize, usize)> {
    let mut scan = 0;
    while let Some(open_pos) = haystack[scan..].find("</") {
        let abs = scan + open_pos;
        let after = abs + 2;
        let end = haystack[after..].find('>')?;
        let name = haystack[after..after + end].trim();
        if local_name(name) == local {
            return Some((abs, after + end + 1));
        }
        scan = after + end + 1;
    }
    None
}

fn find_open_tag_for_local(haystack: &str, local: &str) -> Option<(usize, usize)> {
    let mut scan = 0;
    while let Some(open_pos) = haystack[scan..].find('<') {
        let abs = scan + open_pos;
        if haystack[abs..].starts_with("</")
            || haystack[abs..].starts_with("<!")
            || haystack[abs..].starts_with("<?")
        {
            scan = abs + 1;
            continue;
        }
        let after = abs + 1;
        let end = haystack[after..].find('>')?;
        let raw = haystack[after..after + end].trim();
        let self_closing = raw.ends_with('/');
        let body = if self_closing {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        let name = body.split_whitespace().next().unwrap_or("");
        if !self_closing && local_name(name) == local {
            return Some((abs, after + end + 1));
        }
        scan = after + end + 1;
    }
    None
}

/// Serialization-mode label used by qid's limited SAML XMLDSig-shaped
/// signing profile. These modes select custom serialization, not full W3C C14N.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningCanonicalization {
    /// Custom serialization selected by the C14N 1.0 algorithm URI.
    C14N10,
    /// Custom serialization selected by the Exclusive C14N algorithm URI.
    Exclusive,
}

/// Build a `<ds:Signature>`-shaped document using qid's limited custom profile
/// and a PKCS#8 PEM private key. This is not a general W3C XMLDSig signer and
/// makes no standards-interoperability claim. The inbound verifier is separate
/// and does not accept this default C14N-10 signing mode.
pub fn sign_saml_element_with_key(
    target_xml: &str,
    element_id: &str,
    algorithm: SamlXmlSignatureAlgorithm,
    private_key_pem: &[u8],
) -> QidResult<String> {
    sign_saml_element_with_key_c14n(
        target_xml,
        element_id,
        algorithm,
        private_key_pem,
        SigningCanonicalization::C14N10,
    )
}

/// Build a `<ds:Signature>`-shaped document with a choice of custom
/// serialization mode. See [`sign_saml_element_with_key`] for the default.
pub fn sign_saml_element_with_key_c14n(
    target_xml: &str,
    element_id: &str,
    algorithm: SamlXmlSignatureAlgorithm,
    private_key_pem: &[u8],
    c14n: SigningCanonicalization,
) -> QidResult<String> {
    reject_insecure(target_xml)?;

    let (c14n_alg_uri, exc_alg_uri, inclusive_ns) = match c14n {
        SigningCanonicalization::Exclusive => {
            let ns_prefixes = extract_ns_prefixes(target_xml);
            let mut prefix_list = String::new();
            for (p, _) in &ns_prefixes {
                if !prefix_list.is_empty() {
                    prefix_list.push(' ');
                }
                prefix_list.push_str(p);
            }
            (
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                if prefix_list.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<ds:InclusiveNamespaces xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" PrefixList=\"{prefix_list}\"/>"
                    )
                },
            )
        }
        SigningCanonicalization::C14N10 => (
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            String::new(),
        ),
    };

    let target_canonical = match c14n {
        SigningCanonicalization::Exclusive => {
            let ns_prefixes = extract_ns_prefixes(target_xml);
            canonicalize_exclusive(target_xml, &ns_prefixes)?
        }
        SigningCanonicalization::C14N10 => canonicalize_saml_element(target_xml)?,
    };

    let mut hasher = Sha256::new();
    hasher.update(target_canonical.as_bytes());
    let digest = hasher.finalize();
    let digest_value = base64::engine::general_purpose::STANDARD.encode(digest);

    let signature_algorithm_uri = match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        SamlXmlSignatureAlgorithm::EcdsaSha256 => {
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        }
    };
    let reference_uri = format!("#{element_id}");

    let transform_c14n_part = if inclusive_ns.is_empty() {
        format!("<ds:Transform Algorithm=\"{exc_alg_uri}\"/>")
    } else {
        format!("<ds:Transform Algorithm=\"{exc_alg_uri}\">{inclusive_ns}</ds:Transform>")
    };

    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{c14n_alg_uri}\"/><ds:SignatureMethod Algorithm=\"{signature_algorithm_uri}\"/><ds:Reference URI=\"{reference_uri}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>{transform_c14n_part}</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );

    let signed_info_canonical = match c14n {
        SigningCanonicalization::Exclusive => {
            let ns_prefixes = extract_ns_prefixes(&signed_info);
            canonicalize_exclusive(&signed_info, &ns_prefixes)?
        }
        SigningCanonicalization::C14N10 => canonicalize_saml_element(&signed_info)?,
    };

    let signature_bytes =
        sign_canonicalized_with_pem(signed_info_canonical.as_bytes(), private_key_pem, algorithm)?;
    let signature_value = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

    Ok(format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{c14n_alg_uri}\"/><ds:SignatureMethod Algorithm=\"{signature_algorithm_uri}\"/><ds:Reference URI=\"{reference_uri}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>{transform_c14n_part}</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>{signature_value}</ds:SignatureValue></ds:Signature>"
    ))
}

/// Sign the supplied byte stream with a PKCS#8 PEM private key.
///
/// This cryptographic helper does not canonicalize XML or make its input a
/// standards-conforming XMLDSig SignedInfo octet stream.
pub fn sign_canonicalized_with_pem(
    canonical: &[u8],
    private_key_pem: &[u8],
    algorithm: SamlXmlSignatureAlgorithm,
) -> QidResult<Vec<u8>> {
    let pem = std::str::from_utf8(private_key_pem).map_err(|e| QidError::BadRequest {
        message: format!("SAML PEM is not valid UTF-8: {e}"),
    })?;
    match algorithm {
        SamlXmlSignatureAlgorithm::RsaSha256 => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::pkcs8::DecodePrivateKey;
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| QidError::Internal {
                message: format!("SAML RSA private key parse failed: {e}"),
            })?;
            let signing_key = SigningKey::<sha2::Sha256>::new(key);
            let mut rng = rand::thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, canonical);
            Ok(signature.to_bytes().to_vec())
        }
        SamlXmlSignatureAlgorithm::EcdsaSha256 => {
            use p256::ecdsa::SigningKey;
            use p256::ecdsa::signature::Signer as _;
            use p256::pkcs8::DecodePrivateKey;
            let key = match SigningKey::from_pkcs8_pem(pem) {
                Ok(key) => key,
                Err(err) => {
                    return Err(QidError::Internal {
                        message: format!("SAML ECDSA private key parse failed: {err}"),
                    });
                }
            };
            let signature: p256::ecdsa::Signature = key.sign(canonical);
            Ok(signature.to_bytes().to_vec())
        }
    }
}

/// Convert a DER-encoded X.509 certificate to a PEM-encoded
/// SubjectPublicKeyInfo suitable for handing to `rsa::RsaPublicKey`
/// or `p256::ecdsa::VerifyingKey`. The function intentionally keeps
/// the public-key extraction step transport-agnostic: the same
/// helper is used to drive both the SP-side signature verification
/// and the IdP-side signature generation paths.
pub fn cert_pem_to_public_key_pem(cert_der: &[u8]) -> QidResult<String> {
    use x509_parser::prelude::*;
    let (_, certificate): (_, x509_parser::certificate::X509Certificate<'_>) =
        x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
            QidError::BadRequest {
                message: format!("failed to parse X.509 certificate: {e}"),
            }
        })?;
    let spki_der = certificate.public_key().raw;
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki_der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        wrap_base64(&b64)
    ))
}

fn wrap_base64(value: &str) -> String {
    value
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Public-key extraction from a PEM-encoded X.509 certificate.
pub fn cert_pem_to_public_key_pem_from_pem(cert_pem: &str) -> QidResult<String> {
    let body: String = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("X.509 certificate PEM base64 decode failed: {e}"),
        })?;
    cert_pem_to_public_key_pem(&der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_preserves_structure_with_attribute_sorting() {
        let input = r#"<root b="2" a="1"><child/></root>"#;
        let canonical = canonicalize_saml_element(input).unwrap();
        assert!(canonical.contains("a=\"1\""));
        assert!(canonical.contains("b=\"2\""));
    }

    #[test]
    fn canonicalize_handles_namespaced_close_tags() {
        let input = r##"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="req-1"><saml:Issuer>x</saml:Issuer><samlp:NameIDPolicy/></samlp:AuthnRequest>"##;
        let canonical =
            canonicalize_saml_element(input).expect("namespaced canonicalize should succeed");
        assert!(canonical.contains("<AuthnRequest"));
        assert!(canonical.contains("<Issuer>x</Issuer>"));
        assert!(canonical.ends_with("</AuthnRequest>"));
    }

    #[test]
    fn canonicalize_known_vector_drops_comments_and_sorts_attributes() {
        let input = r#"<?xml version="1.0"?><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" b="2" a="1">Issuer <![CDATA[& Entity]]><!-- ignored --></saml:Issuer>"#;
        let canonical =
            canonicalize_saml_element(input).expect("known c14n vector should canonicalize");

        assert_eq!(
            canonical,
            r#"<Issuer a="1" b="2" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Issuer & Entity</Issuer>"#
        );
    }

    #[test]
    fn exclusive_c14n_known_vector_emits_used_namespace_only() {
        let input = r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:unused="urn:unused" b="2" a="1">https://idp.example.com</saml:Issuer>"#;
        let canonical = canonicalize_exclusive(
            input,
            &[
                (
                    "saml".to_string(),
                    "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
                ),
                ("unused".to_string(), "urn:unused".to_string()),
            ],
        )
        .expect("known exclusive c14n vector should canonicalize");

        assert_eq!(
            canonical,
            r#"<saml:Issuer a="1" b="2" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>"#
        );
    }

    #[test]
    fn sign_exc_c14n_produces_valid_output() {
        let input = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="exc-1" Version="2.0"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>"#;
        let key_pem = include_str!("test-ec-key.pem");
        let result = sign_saml_element_with_key_c14n(
            input,
            "exc-1",
            SamlXmlSignatureAlgorithm::EcdsaSha256,
            key_pem.as_bytes(),
            SigningCanonicalization::Exclusive,
        );
        assert!(
            result.is_ok(),
            "exc-c14n signing should succeed: {:?}",
            result.err()
        );
        let sig = result.unwrap();
        assert!(sig.contains("Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\""));
    }
}
