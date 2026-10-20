//! SAML 2.0 Artifact Binding support.
//!
//! Implements artifact generation, in-memory storage, and the
//! ArtifactResolutionService SOAP endpoint.
//!
//! Resolution requires a signed SOAP 1.1 ArtifactResolve authenticated against
//! an SP's `signing_certificates` in the requested realm. Empty or unusable
//! configured certificates deny access; embedded KeyInfo never grants trust.
//! Only a single direct request with direct leaf Issuer/Artifact is supported;
//! one optional direct `samlp:Extensions` child is signed and ignored, while any
//! other unexpected direct child is rejected. An optional single SOAP Header may
//! precede the Body; unprocessed `mustUnderstand` blocks addressed to this
//! endpoint are rejected and ordinary headers are ignored. The request must
//! carry SAML `Version="2.0"`, a present syntactically valid `IssueInstant` (no
//! freshness policy), and an optional `Destination` that, when present, exactly
//! matches the configured external artifact endpoint URL. The
//! verified Issuer must exactly match the SP entity_id, and both that SP and the
//! realm must match the artifact's stored context before one-time removal.
//! Outer responses remain unsigned; this module does not change signing policy.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::verification::{ASSERTION_NS, DSIG_NS, PROTOCOL_NS, attribute, children_named, named};
use crate::xml::xml_escape_preserving_whitespace as xml_escape;
use crate::{
    SamlSignatureInputs, SamlXmlSignatureAlgorithm, SignedSamlElement,
    verify_saml_xml_signature_for,
};
use base64::Engine;
use qid_core::{
    config::SamlServiceProviderConfig,
    error::{QidError, QidResult},
};
use sha1::{Digest, Sha1};

static ARTIFACTS: LazyLock<Mutex<HashMap<String, StoredArtifact>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_ARTIFACT_SWEEP: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

pub const ARTIFACT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";

const ARTIFACT_TYPE_CODE: &[u8] = &[0x00, 0x04];
const ARTIFACT_ENDPOINT_INDEX: &[u8] = &[0x00, 0x00];

struct StoredArtifact {
    realm_id: String,
    sp_entity_id: String,
    response_xml: String,
    expires_at: u64,
}

pub(crate) struct SamlArtifact {
    pub artifact: String,
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn evict_expired_artifacts(store: &mut HashMap<String, StoredArtifact>, now: u64) {
    if LAST_ARTIFACT_SWEEP.swap(now, std::sync::atomic::Ordering::Relaxed) != now {
        store.retain(|_, entry| entry.expires_at >= now);
    }
}

/// Generate a SAML 2.0 artifact and store the associated response.
///
/// Type 0x0004 format: base64(TypeCode[2] || EndpointIndex[2] ||
/// SHA-1(IdP entity ID UTF-8)[20] || MessageHandle[20]), exactly 44 bytes.
pub(crate) fn store_artifact(
    response_xml: &str,
    ttl_seconds: u64,
    realm_id: &str,
    sp_entity_id: &str,
    idp_entity_id: &str,
) -> QidResult<SamlArtifact> {
    let random_handle = {
        let mut bytes = [0u8; 20];
        let now = now_seconds();
        let hash = sha2::Sha256::digest(format!("{now}{}", ulid::Ulid::new()).as_bytes());
        bytes.copy_from_slice(&hash[..20]);
        bytes
    };
    let mut raw = Vec::with_capacity(44);
    raw.extend_from_slice(ARTIFACT_TYPE_CODE);
    raw.extend_from_slice(ARTIFACT_ENDPOINT_INDEX);
    raw.extend_from_slice(&Sha1::digest(idp_entity_id.as_bytes()));
    raw.extend_from_slice(&random_handle);

    let artifact = base64::engine::general_purpose::STANDARD.encode(&raw);
    let handle_hex = hex::encode(random_handle);

    let mut store = ARTIFACTS.lock().map_err(|_| QidError::Internal {
        message: "SAML artifact store lock is poisoned".to_string(),
    })?;
    let now = now_seconds();
    evict_expired_artifacts(&mut store, now);
    let expires_at = now.saturating_add(ttl_seconds);
    store.insert(
        handle_hex,
        StoredArtifact {
            realm_id: realm_id.to_owned(),
            sp_entity_id: sp_entity_id.to_owned(),
            response_xml: response_xml.to_string(),
            expires_at,
        },
    );

    Ok(SamlArtifact { artifact })
}

/// Resolve a SAML 2.0 artifact and return the stored response.
/// `sp_entity_id` must come from the authenticated request's configured SP;
/// `idp_entity_id` is the configured issuer for this realm.
pub(crate) fn resolve_artifact(
    artifact: &str,
    realm_id: &str,
    sp_entity_id: &str,
    idp_entity_id: &str,
) -> QidResult<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(artifact)
        .map_err(|_| QidError::BadRequest {
            message: "SAML artifact is not valid base64".to_string(),
        })?;
    if raw.len() != 44 {
        return Err(QidError::BadRequest {
            message: "SAML artifact must be exactly 44 bytes".to_string(),
        });
    }
    if raw[..2] != *ARTIFACT_TYPE_CODE {
        return Err(QidError::BadRequest {
            message: "SAML artifact type code mismatch".to_string(),
        });
    }
    if raw[2..4] != *ARTIFACT_ENDPOINT_INDEX {
        return Err(QidError::BadRequest {
            message: "SAML artifact endpoint index mismatch".to_string(),
        });
    }
    if raw[4..24] != Sha1::digest(idp_entity_id.as_bytes())[..] {
        return Err(QidError::BadRequest {
            message: "SAML artifact source ID mismatch".to_string(),
        });
    }
    let handle_hex = hex::encode(&raw[24..]);
    let mut store = ARTIFACTS.lock().map_err(|_| QidError::Internal {
        message: "SAML artifact store lock is poisoned".to_string(),
    })?;
    let entry = store.get(&handle_hex).ok_or_else(|| QidError::NotFound {
        resource: "SAML artifact".to_string(),
    })?;
    // Check context under the same lock as removal. A caller authenticated as
    // another SP or in another realm must never consume the legitimate handle.
    if entry.realm_id != realm_id || entry.sp_entity_id != sp_entity_id {
        return Err(artifact_denied());
    }
    let entry = store.remove(&handle_hex).ok_or_else(artifact_denied)?;
    let now = now_seconds();
    evict_expired_artifacts(&mut store, now);
    if now > entry.expires_at {
        return Err(QidError::BadRequest {
            message: "SAML artifact has expired".to_string(),
        });
    }
    Ok(entry.response_xml)
}

/// Build a SOAP `<ArtifactResponse>` envelope containing the SAML response.
pub(crate) fn build_artifact_response(
    in_response_to: &str,
    issuer: &str,
    saml_response_xml: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{}" Version="2.0"
        IssueInstant="{}"
        InResponseTo="{}">
      <saml:Issuer>{}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      {}
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        ulid::Ulid::new(),
        iso_now_utc(),
        xml_escape(in_response_to),
        xml_escape(issuer),
        saml_response_xml,
    )
}

/// Values extracted only from the exact verified ArtifactResolve target.
pub(crate) struct ResolvedArtifactResolve {
    pub id: String,
    pub artifact: String,
}

/// Authenticate with keys configured for this realm only. KeyInfo and the
/// unsigned Issuer are not trust sources; an SP must own both key and Issuer.
/// The verifier requires the SOAP 1.1 Envelope with an optional single Header
/// before exactly one Body containing only this target, a direct signature and
/// a unique signed ID. `expected_destination` is the configured external
/// artifact endpoint URL (from route config, never Host).
pub(crate) fn authenticate_artifact_resolve<'a>(
    xml: &str,
    providers: &'a [SamlServiceProviderConfig],
    expected_destination: &str,
) -> QidResult<(ResolvedArtifactResolve, &'a SamlServiceProviderConfig)> {
    const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
    const SOAP_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
    for sp in providers {
        for certificate in &sp.signing_certificates {
            let Ok(key) = crate::cert_pem_to_public_key_pem_from_pem(certificate) else {
                continue;
            };
            for profile in [
                SamlXmlSignatureAlgorithm::RsaSha256,
                SamlXmlSignatureAlgorithm::EcdsaSha256,
            ] {
                let Ok(verified) = verify_saml_xml_signature_for(
                    SamlSignatureInputs {
                        document: xml,
                        public_key_pem: key.as_bytes(),
                        profile,
                    },
                    SignedSamlElement::ArtifactResolve,
                ) else {
                    continue;
                };
                let doc = verified.document();
                let target = verified.target();
                // Headers are not processed: reject SOAP `mustUnderstand`
                // blocks addressed to this endpoint, ignore everything else.
                // SOAP 1.1 `mustUnderstand` and `actor` are SOAP-envelope
                // namespace attributes; unqualified names carry no SOAP
                // semantics.
                if let Some(root) = doc.document_element() {
                    for header in children_named(doc, root, SOAP_NS, "Header") {
                        for block in doc
                            .children(header)
                            .iter()
                            .filter(|n| doc.element(**n).is_some())
                        {
                            let attrs = &doc.element(*block).map(|e| &e.attributes);
                            let Some(attrs) = attrs else { continue };
                            let soap_value = |local: &str| {
                                attrs
                                    .iter()
                                    .find(|a| {
                                        a.name.local_name.as_ref() == local
                                            && a.name.namespace_uri.as_deref() == Some(SOAP_NS)
                                    })
                                    .map(|a| a.value.as_ref())
                            };
                            let Some(raw) = soap_value("mustUnderstand") else {
                                continue;
                            };
                            // Explicitly support `0`/`1` and `false`/`true`;
                            // anything else fails closed.
                            match raw.trim() {
                                "0" | "false" => continue,
                                "1" | "true" => {}
                                _ => return Err(artifact_denied()),
                            }
                            match soap_value("actor").map(str::trim) {
                                None | Some("") | Some(SOAP_NEXT) => {
                                    return Err(artifact_denied());
                                }
                                Some(actor) if actor == expected_destination => {
                                    return Err(artifact_denied());
                                }
                                Some(_) => {}
                            }
                        }
                    }
                }
                // Reject unsupported children rather than interpreting nested or
                // duplicate Issuer/Artifact values outside the signed contract.
                // One optional direct samlp:Extensions child is signed and
                // ignored; anything else beyond Issuer/Artifact/Signature fails.
                if children_named(doc, target, PROTOCOL_NS, "Extensions").len() > 1 {
                    return Err(artifact_denied());
                }
                if doc.children(target).iter().any(|n| {
                    doc.element(*n).is_some()
                        && !named(doc, *n, ASSERTION_NS, "Issuer")
                        && !named(doc, *n, PROTOCOL_NS, "Artifact")
                        && !named(doc, *n, PROTOCOL_NS, "Extensions")
                        && !named(doc, *n, DSIG_NS, "Signature")
                }) {
                    return Err(artifact_denied());
                }
                // SAML request semantics: Version 2.0 and a present syntactic
                // IssueInstant are required; no freshness/max-age is enforced.
                if attribute(doc, target, "Version") != Some("2.0") {
                    return Err(artifact_denied());
                }
                match attribute(doc, target, "IssueInstant") {
                    Some(value) if valid_issue_instant(value) => {}
                    _ => return Err(artifact_denied()),
                }
                // Destination is optional; when present it must exactly match
                // the configured external endpoint URL.
                if let Some(destination) = attribute(doc, target, "Destination")
                    && destination != expected_destination
                {
                    return Err(artifact_denied());
                }
                let leaf = |ns, name| {
                    let nodes = children_named(doc, target, ns, name);
                    if nodes.len() != 1
                        || doc
                            .children(nodes[0])
                            .iter()
                            .any(|n| doc.element(*n).is_some())
                    {
                        return Err(artifact_denied());
                    }
                    let text = doc.text_content_deep(nodes[0]);
                    if text.trim().is_empty() {
                        return Err(artifact_denied());
                    }
                    Ok(text)
                };
                if leaf(ASSERTION_NS, "Issuer")? != sp.entity_id {
                    continue;
                }
                return Ok((
                    ResolvedArtifactResolve {
                        id: attribute(doc, target, "ID")
                            .ok_or_else(artifact_denied)?
                            .to_owned(),
                        artifact: leaf(PROTOCOL_NS, "Artifact")?.trim().to_owned(),
                    },
                    sp,
                ));
            }
        }
    }
    Err(artifact_denied())
}

/// Validate the supported RFC3339 profile of SAML `IssueInstant`; no freshness
/// or max-age policy is applied.
fn valid_issue_instant(value: &str) -> bool {
    let Ok(instant) =
        time::OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    // XML Schema dateTime limits timezone offsets to +/-14:00.
    instant.offset().whole_seconds().unsigned_abs() <= 14 * 60 * 60
}

fn artifact_denied() -> QidError {
    QidError::Unauthorized {
        message: "SAML ArtifactResolve request denied".into(),
    }
}

pub(crate) fn iso_now_utc() -> String {
    let Ok(dur) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return String::new();
    };
    let secs = dur.as_secs();
    let nanos = dur.subsec_nanos();
    let ds = (secs / 86400) as i64;
    let time_secs = secs % 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    let (y, mo, d) = civil_from_days(ds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        mo,
        d,
        h,
        m,
        s,
        nanos / 1_000_000
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;
