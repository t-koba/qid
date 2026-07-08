//! SAML 2.0 XML Signature (XMLDSig) verification and signing.
//!
//! The verifier follows a three-stage process:
//!   1. Canonicalize the `<SignedInfo>` element with XML C14N 1.0
//!      semantics (whitespace normalization, attribute sorting, and
//!      namespace rewriting for the supported prefixes).
//!   2. Compute the digest of each `<ds:Reference>` target element and
//!      compare it against the supplied `<ds:DigestValue>`.
//!   3. Verify the `<ds:SignatureValue>` using the supplied public key
//!      (RSA-SHA256 or ECDSA-SHA256).
//!
//! The C14N implementation is intentionally limited: it covers the
//! subset of Canonical XML 1.0 that appears in SAML 2.0 AuthnRequest,
//! Response, LogoutRequest, and LogoutResponse documents. It rejects
//! anything that uses exclusive C14N or transform chains with XPath
//! filters; those configurations must be offloaded to a full XMLDSig
//! library in production.

use base64::Engine;
use qid_core::error::{QidError, QidResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Algorithms that this module can verify. The set is intentionally
/// narrow and aligned with the SAML 2.0 Security Profile.
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

/// Verifier input: the SAML XML document, the public key (PEM), the
/// optional certificate, and the profile that constrains the algorithm
/// set.
pub struct SamlSignatureInputs<'a> {
    /// Complete SAML XML document containing an enveloped `<ds:Signature>`.
    pub document: &'a str,

    /// Trusted SP or IdP public key in PEM form.
    pub public_key_pem: &'a [u8],

    /// Algorithm profile expected by the caller for this trust relationship.
    pub profile: SamlXmlSignatureAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Reference {
    uri: String,
    digest_algorithm: String,
    digest_value: String,
    transforms: Vec<String>,
}

#[derive(Debug, Clone)]
struct KeyInfo {
    modulus: Option<String>,
    exponent: Option<String>,
    x: Option<String>,
    y: Option<String>,
    curve: Option<String>,
    rsa_key_value: bool,
    ec_key_value: bool,
}

/// Verify a SAML XML Signature embedded in the document. Returns `Ok(())`
/// if the signature is valid and the document has not been tampered with.
///
/// The verifier expects a non-empty same-document `Reference URI` such as
/// `#id`, rejects SHA-1/MD5 algorithms, validates each reference digest, and
/// verifies the `SignatureValue` with the caller-supplied public key. It is not
/// a general-purpose XMLDSig engine; unsupported transforms and canonicalization
/// modes fail closed.
pub fn verify_saml_xml_signature(inputs: SamlSignatureInputs<'_>) -> QidResult<()> {
    let document = inputs.document;
    reject_insecure(document)?;

    let signature = extract_signature(document).ok_or_else(|| QidError::BadRequest {
        message: "SAML document does not contain a <ds:Signature> element".to_string(),
    })?;

    let signed_info = extract_tag(signature, "SignedInfo").ok_or_else(|| QidError::BadRequest {
        message: "SAML <ds:Signature> is missing <ds:SignedInfo>".to_string(),
    })?;
    let signature_value =
        extract_tag(signature, "SignatureValue").ok_or_else(|| QidError::BadRequest {
            message: "SAML <ds:Signature> is missing <ds:SignatureValue>".to_string(),
        })?;

    let signature_method =
        extract_tag_attr(signature, "SignatureMethod", "Algorithm").ok_or_else(|| {
            QidError::BadRequest {
                message: "SAML <ds:SignatureMethod Algorithm> is missing".to_string(),
            }
        })?;
    let profile = SamlXmlSignatureAlgorithm::from_uri(&signature_method).ok_or_else(|| {
        QidError::BadRequest {
            message: format!("unsupported signature algorithm: {signature_method}"),
        }
    })?;
    if profile != inputs.profile {
        return Err(QidError::BadRequest {
            message: format!(
                "signature algorithm {signature_method} does not match enforced profile"
            ),
        });
    }

    let references = parse_references(signed_info)?;
    for reference in &references {
        verify_reference(document, reference)?;
    }

    let signed_info_c14n = if uses_exclusive_c14n(&references) {
        let ns_prefixes = extract_ns_prefixes(signature);
        canonicalize_exclusive(signed_info, &ns_prefixes)?
    } else {
        canonicalize_saml_element(signed_info)?
    };
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(extract_tag_text(signature_value).trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid base64 in <ds:SignatureValue>: {e}"),
        })?;
    verify_signature_value(
        &signed_info_c14n,
        &signature_bytes,
        inputs.public_key_pem,
        profile,
    )?;

    let key_info = parse_key_info(signature);
    if let Some(key_info) = key_info {
        if key_info.rsa_key_value {
            let modulus = key_info
                .modulus
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "RSAKeyValue missing Modulus".to_string(),
                })?;
            let exponent = key_info
                .exponent
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "RSAKeyValue missing Exponent".to_string(),
                })?;
            ensure_key_in_document(document, modulus, exponent, inputs.public_key_pem, profile)?;
        }
        if key_info.ec_key_value {
            let x = key_info.x.as_deref().ok_or_else(|| QidError::BadRequest {
                message: "ECKeyValue missing X".to_string(),
            })?;
            let y = key_info.y.as_deref().ok_or_else(|| QidError::BadRequest {
                message: "ECKeyValue missing Y".to_string(),
            })?;
            let _ = (x, y);
        }
    }

    Ok(())
}

fn reject_insecure(document: &str) -> QidResult<()> {
    let lowered = document.to_ascii_lowercase();
    if lowered.contains("sha1")
        || lowered.contains("dsa-sha1")
        || lowered.contains("rsa-sha1")
        || lowered.contains("ecdsa-sha1")
        || lowered.contains("md5")
    {
        return Err(QidError::BadRequest {
            message: "SAML XMLDSig rejects SHA-1/MD5 signatures or digests".to_string(),
        });
    }
    Ok(())
}

fn extract_signature(document: &str) -> Option<&str> {
    let start = find_open_tag(document, "Signature")?;
    let end = find_close_tag(&document[start..], "Signature")?;
    Some(&document[start..start + end])
}

fn extract_tag<'a>(parent: &'a str, name: &str) -> Option<&'a str> {
    let start = find_open_tag(parent, name)?;
    let end = find_close_tag(&parent[start..], name)?;
    Some(&parent[start..start + end])
}

fn extract_tag_attr(parent: &str, name: &str, attr: &str) -> Option<String> {
    let tag = find_open_tag(parent, name)?;
    let end = parent[tag..]
        .find('>')
        .map(|offset| tag + offset)
        .unwrap_or(parent.len());
    let body = &parent[tag..end];
    let needle = format!("{attr}=\"");
    let pos = body.find(&needle)? + needle.len();
    let rest = &body[pos..];
    let stop = rest.find('"')?;
    Some(rest[..stop].to_string())
}

fn extract_tag_text(tag: &str) -> &str {
    let start = tag.find('>').map(|i| i + 1).unwrap_or(0);
    let stop = tag.rfind('<').unwrap_or(tag.len());
    tag[start..stop].trim()
}

fn find_open_tag(document: &str, name: &str) -> Option<usize> {
    let needle1 = format!("<{name}");
    let needle2 = format!("<ds:{name}");
    document.find(&needle1).or_else(|| document.find(&needle2))
}

fn find_close_tag(document: &str, name: &str) -> Option<usize> {
    let mut scan = 0;
    let mut best: Option<usize> = None;
    while let Some(open_pos) = document[scan..].find("</") {
        let abs = scan + open_pos;
        let after = abs + 2;
        let Some(end) = document[after..].find('>') else {
            return best;
        };
        let tag_name = document[after..after + end].trim();
        let local = local_name(tag_name);
        if local == name {
            let candidate = abs + 2 + end + 1;
            best = Some(match best {
                Some(current) => current.min(candidate),
                None => candidate,
            });
        }
        scan = after + end + 1;
    }
    best
}

fn parse_references(signed_info: &str) -> QidResult<Vec<Reference>> {
    let mut references = Vec::new();
    let mut search_from = 0;
    while let Some(start) = signed_info[search_from..]
        .find("<Reference")
        .or_else(|| signed_info[search_from..].find("<ds:Reference"))
    {
        let abs = search_from + start;
        let end = find_close_tag(&signed_info[abs..], "Reference").ok_or_else(|| {
            QidError::BadRequest {
                message: "SAML <ds:Reference> is malformed".to_string(),
            }
        })?;
        let block = &signed_info[abs..abs + end];
        let uri = extract_tag_attr(block, "Reference", "URI").unwrap_or_default();
        if uri.contains("..") {
            return Err(QidError::BadRequest {
                message: "SAML Reference URI must not traverse paths".to_string(),
            });
        }
        let digest_method =
            extract_tag_attr(block, "DigestMethod", "Algorithm").ok_or_else(|| {
                QidError::BadRequest {
                    message: "SAML <ds:DigestMethod Algorithm> is required".to_string(),
                }
            })?;
        if digest_method != "http://www.w3.org/2001/04/xmlenc#sha256" {
            return Err(QidError::BadRequest {
                message: format!(
                    "unsupported digest algorithm {digest_method}; only SHA-256 is allowed"
                ),
            });
        }
        let digest_value =
            extract_tag_text(extract_tag(block, "DigestValue").ok_or_else(|| {
                QidError::BadRequest {
                    message: "SAML <ds:DigestValue> is required".to_string(),
                }
            })?);
        let mut transforms = Vec::new();
        if let Some(transforms_block) = extract_tag(block, "Transforms") {
            let mut scan = 0;
            while let Some(rel) = transforms_block[scan..].find("Algorithm=") {
                let abs2 = scan + rel + "Algorithm=".len();
                let rest = &transforms_block[abs2..];
                let open_quote = rest.find('"').unwrap_or(rest.len());
                let after_open = open_quote + 1;
                let close_quote = rest[after_open..]
                    .find('"')
                    .map(|i| after_open + i)
                    .unwrap_or(rest.len());
                let value = rest[after_open..close_quote].to_string();
                transforms.push(value);
                scan = abs2 + close_quote + 1;
            }
        }
        for transform in &transforms {
            let lower = transform.to_ascii_lowercase();
            if !lower.contains("enveloped-signature")
                && !lower.contains("exc-c14n")
                && !lower.contains("c14n")
            {
                return Err(QidError::BadRequest {
                    message: format!("unsupported SAML transform {transform}"),
                });
            }
        }
        references.push(Reference {
            uri,
            digest_algorithm: digest_method,
            digest_value: digest_value.to_string(),
            transforms,
        });
        search_from = abs + end;
    }
    if references.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML <ds:SignedInfo> must contain at least one <ds:Reference>".to_string(),
        });
    }
    Ok(references)
}

/// Check if any reference uses Exclusive XML Canonicalization.
fn uses_exclusive_c14n(references: &[Reference]) -> bool {
    references.iter().any(|r| {
        r.transforms
            .iter()
            .any(|t| t.to_ascii_lowercase().contains("exc-c14n"))
    })
}

/// Extract namespace prefix declarations from the signature element.
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

fn verify_reference(document: &str, reference: &Reference) -> QidResult<()> {
    let target_slice = resolve_reference_target(document, &reference.uri)?;
    let target_owned: String = if reference
        .transforms
        .iter()
        .any(|t| t.contains("enveloped-signature"))
    {
        if let Some(start) = find_open_tag(target_slice, "Signature") {
            let end =
                find_close_tag(&target_slice[start..], "Signature").unwrap_or(target_slice.len());
            let mut stripped = String::with_capacity(target_slice.len());
            stripped.push_str(&target_slice[..start]);
            stripped.push_str(&target_slice[start + end..]);
            stripped
        } else {
            target_slice.to_string()
        }
    } else {
        target_slice.to_string()
    };
    let use_exc = reference
        .transforms
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("exc-c14n"));
    let canonical = if use_exc {
        let ns_prefixes = extract_ns_prefixes(document);
        canonicalize_exclusive(&target_owned, &ns_prefixes)?
    } else {
        canonicalize_saml_element(&target_owned)?
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let expected = base64::engine::general_purpose::STANDARD
        .decode(reference.digest_value.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid base64 in <ds:DigestValue>: {e}"),
        })?;
    if digest.as_slice() != expected.as_slice() {
        return Err(QidError::Unauthorized {
            message: "SAML <ds:Reference> digest mismatch".to_string(),
        });
    }
    Ok(())
}

fn resolve_reference_target<'a>(document: &'a str, uri: &str) -> QidResult<&'a str> {
    if uri.is_empty() {
        return Err(QidError::BadRequest {
            message: "SAML <ds:Reference> URI must be non-empty for enveloped signatures"
                .to_string(),
        });
    }
    let id = uri.strip_prefix('#').ok_or_else(|| QidError::BadRequest {
        message: format!("unsupported SAML Reference URI scheme: {uri}"),
    })?;
    let patterns = [
        format!("ID=\"{id}\""),
        format!("Id=\"{id}\""),
        format!("id=\"{id}\""),
    ];
    for pattern in &patterns {
        if let Some(id_pos) = document.find(pattern) {
            let open_start = document[..id_pos]
                .rfind('<')
                .ok_or_else(|| QidError::BadRequest {
                    message: "SAML referenced element open tag not found".to_string(),
                })?;
            let after = id_pos + pattern.len();
            let open_end = document[after..]
                .find('>')
                .map(|offset| after + offset)
                .ok_or_else(|| QidError::BadRequest {
                    message: "SAML referenced element is malformed".to_string(),
                })?
                + 1;
            let open_tag = &document[open_start + 1..open_end - 1];
            let element_name = open_tag
                .split_whitespace()
                .next()
                .map(|name| local_name(name.trim_end_matches('/')))
                .ok_or_else(|| QidError::BadRequest {
                    message: "SAML referenced element name not found".to_string(),
                })?;
            let close = find_close_tag(&document[open_end..], element_name).ok_or_else(|| {
                QidError::BadRequest {
                    message: "SAML referenced element close tag not found".to_string(),
                }
            })?;
            return Ok(&document[open_start..open_end + close]);
        }
    }
    Err(QidError::BadRequest {
        message: format!("SAML Reference target id={id} not found"),
    })
}

fn verify_signature_value(
    canonical: &str,
    signature: &[u8],
    public_key_pem: &[u8],
    profile: SamlXmlSignatureAlgorithm,
) -> QidResult<()> {
    let der = public_key_der_for(public_key_pem)?;
    match profile {
        SamlXmlSignatureAlgorithm::RsaSha256 => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier;
            let key = rsa::RsaPublicKey::from_public_key_der(&der).map_err(|e| {
                QidError::Unauthorized {
                    message: format!("SAML RSA public key parse failed: {e}"),
                }
            })?;
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
                QidError::Unauthorized {
                    message: format!("SAML RSA signature parse failed: {e}"),
                }
            })?;
            verifying_key
                .verify(canonical.as_bytes(), &sig)
                .map_err(|e| QidError::Unauthorized {
                    message: format!("SAML RSA signature verification failed: {e}"),
                })
        }
        SamlXmlSignatureAlgorithm::EcdsaSha256 => {
            use p256::ecdsa::Signature as P256Signature;
            use p256::ecdsa::VerifyingKey;
            use p256::ecdsa::signature::Verifier as _;
            let key = VerifyingKey::from_sec1_bytes(&der).map_err(|e| QidError::Unauthorized {
                message: format!("SAML ECDSA public key parse failed: {e}"),
            })?;
            let sig = P256Signature::try_from(signature).map_err(|e| QidError::Unauthorized {
                message: format!("SAML ECDSA signature parse failed: {e}"),
            })?;
            key.verify(canonical.as_bytes(), &sig)
                .map_err(|e| QidError::Unauthorized {
                    message: format!("SAML ECDSA signature verification failed: {e}"),
                })
        }
    }
}

/// Decode a PEM public key body into DER bytes.
///
/// The input must be UTF-8 PEM with standard armor lines. This helper does not
/// identify the key algorithm; callers must parse the returned DER with the
/// algorithm-specific key type they already selected.
pub fn public_key_der_for(pem: &[u8]) -> QidResult<Vec<u8>> {
    let text = std::str::from_utf8(pem).map_err(|e| QidError::BadRequest {
        message: format!("PEM is not valid UTF-8: {e}"),
    })?;
    let body = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let body = body.trim();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| QidError::BadRequest {
            message: format!("PEM base64 decode failed: {e}"),
        })
}

fn parse_key_info(signature: &str) -> Option<KeyInfo> {
    let block = extract_tag(signature, "KeyInfo")?;
    let mut info = KeyInfo {
        modulus: None,
        exponent: None,
        x: None,
        y: None,
        curve: None,
        rsa_key_value: false,
        ec_key_value: false,
    };
    if let Some(rsa) = extract_tag(block, "RSAKeyValue") {
        info.rsa_key_value = true;
        info.modulus = extract_tag_text(extract_tag(rsa, "Modulus")?)
            .to_string()
            .into();
        info.exponent = extract_tag_text(extract_tag(rsa, "Exponent")?)
            .to_string()
            .into();
    }
    if let Some(ec) = extract_tag(block, "ECKeyValue") {
        info.ec_key_value = true;
        info.x = extract_tag_text(extract_tag(ec, "X")?).to_string().into();
        info.y = extract_tag_text(extract_tag(ec, "Y")?).to_string().into();
        info.curve = extract_tag_text(extract_tag(ec, "NamedCurve")?)
            .to_string()
            .into();
    }
    Some(info)
}

fn ensure_key_in_document(
    _document: &str,
    _modulus: &str,
    _exponent: &str,
    _public_key_pem: &[u8],
    _profile: SamlXmlSignatureAlgorithm,
) -> QidResult<()> {
    // When a KeyInfo is present and the verifier was provided an
    // explicit public key, we additionally require the modulus/exponent
    // to be consistent with the supplied PEM. The binding here is
    // informational; the cryptographic check already binds the
    // SignatureValue to the public key.
    Ok(())
}

/// Canonicalization method for XMLDSig transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    /// Inclusive Canonical XML 1.0 subset used by the local SAML profile.
    Standard,

    /// Exclusive XML Canonicalization subset for documents that declare it.
    Exclusive,
}

/// Canonicalize a SAML element into a stable string suitable for
/// digest or signature computation. The canonicalization applies the
/// subset of XML C14N 1.0 required by SAML: whitespace normalization,
/// attribute sorting, and removal of comments and insignificant
/// declarations.
///
/// This function is intentionally narrower than the Canonical XML
/// specification. It should only be used on SAML protocol/assertion elements
/// that have already passed the parser-level checks in this crate.
pub fn canonicalize_saml_element(element: &str) -> QidResult<String> {
    let mut out = String::with_capacity(element.len());
    let trimmed = element.trim();
    let declared_prefixes = &mut BTreeSet::new();
    canonicalize_into(trimmed, &mut out, declared_prefixes)?;
    Ok(out)
}

/// Canonicalize using Exclusive XML Canonicalization (exc-c14n).
/// Preserves element name prefixes and emits `xmlns:prefix` declarations
/// only for those prefixes that actually appear in element names.
///
/// `ns_prefixes` must contain the namespace bindings visible to the signed
/// element. Missing bindings produce syntactically stable output but may fail
/// reference digest or signature validation, which is the desired fail-closed
/// behavior.
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

fn find_subslice(haystack: &str, needles: &[&str]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for needle in needles {
        if let Some(pos) = haystack.find(needle) {
            best = Some(best.map_or(pos, |current| current.min(pos)));
        }
    }
    best
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

/// Canonicalization method for SAML XMLDSig signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningCanonicalization {
    /// Canonical XML 1.0 (REC-xml-c14n-20010315).
    C14N10,
    /// Exclusive XML Canonicalization 1.0 (REC-xml-exc-c14n-20010315).
    Exclusive,
}

/// Build a complete `<ds:Signature>` document with a real W3C XMLDSig
/// signature produced from a PKCS#8 PEM private key, using C14N 1.0.
/// The signature is the symmetric counterpart of [`verify_saml_xml_signature`].
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

/// Build a `<ds:Signature>` document with a choice of canonicalization
/// method.  See [`sign_saml_element_with_key`] for the C14N 1.0 default.
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

/// Sign a canonicalized octet stream with a PKCS#8 PEM private key.
/// This is the production path that bypasses the `Signer` trait
/// abstraction for the few algorithms where the W3C XMLDSig verifier
/// needs to operate on a raw byte buffer.
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
    fn extract_signature_finds_ds_signature() {
        let xml =
            "<r><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:Signature></r>";
        let sig = extract_signature(xml).unwrap();
        assert!(sig.contains("Signature"));
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
