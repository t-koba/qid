//! SAML 2.0 Artifact Binding support.
//!
//! Implements artifact generation, in-memory storage, and the
//! ArtifactResolutionService SOAP endpoint.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use base64::Engine;
use qid_core::error::{QidError, QidResult};

static ARTIFACTS: LazyLock<Mutex<HashMap<String, StoredArtifact>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub const ARTIFACT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";

const ARTIFACT_TYPE_CODE: &[u8] = &[0x00, 0x04];
const ARTIFACT_ENDPOINT_INDEX: &[u8] = &[0x00, 0x00];

struct StoredArtifact {
    response_xml: String,
    expires_at: u64,
}

pub(crate) struct SamlArtifact {
    pub artifact: String,
    #[allow(dead_code)] // schema completeness: SAML artifact handle stored for future use
    pub handle: String,
}

/// Current timestamp in seconds for expiry checks.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a SAML 2.0 artifact and store the associated response.
///
/// Format: base64(TypeCode || EndpointIndex || RandomHandle)
/// where the handle is 20 random bytes (SHA-1 sized).
pub(crate) fn store_artifact(response_xml: &str, ttl_seconds: u64) -> SamlArtifact {
    use sha2::Digest;
    let random_handle = {
        let mut bytes = [0u8; 20];
        let now = now_seconds();
        let hash = sha2::Sha256::digest(format!("{now}{}", ulid::Ulid::new()).as_bytes());
        bytes.copy_from_slice(&hash[..20]);
        bytes
    };
    let mut raw = Vec::with_capacity(2 + 2 + 20);
    raw.extend_from_slice(ARTIFACT_TYPE_CODE);
    raw.extend_from_slice(ARTIFACT_ENDPOINT_INDEX);
    raw.extend_from_slice(&random_handle);

    let artifact = base64::engine::general_purpose::STANDARD.encode(&raw);
    let handle_hex = hex::encode(random_handle);

    let expires_at = now_seconds().saturating_add(ttl_seconds);
    let mut store = ARTIFACTS.lock().expect("artifact store lock");
    store.insert(
        handle_hex.clone(),
        StoredArtifact {
            response_xml: response_xml.to_string(),
            expires_at,
        },
    );

    SamlArtifact {
        artifact,
        handle: handle_hex,
    }
}

/// Resolve a SAML 2.0 artifact and return the stored response.
pub(crate) fn resolve_artifact(artifact: &str) -> QidResult<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(artifact)
        .map_err(|_| QidError::BadRequest {
            message: "SAML artifact is not valid base64".to_string(),
        })?;
    if raw.len() < 24 {
        return Err(QidError::BadRequest {
            message: "SAML artifact is too short".to_string(),
        });
    }
    if raw[..2] != *ARTIFACT_TYPE_CODE {
        return Err(QidError::BadRequest {
            message: "SAML artifact type code mismatch".to_string(),
        });
    }
    let handle_hex = hex::encode(&raw[4..]);
    let mut store = ARTIFACTS.lock().expect("artifact store lock");
    let entry = store
        .remove(&handle_hex)
        .ok_or_else(|| QidError::NotFound {
            resource: "SAML artifact".to_string(),
        })?;
    if now_seconds() > entry.expires_at {
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
        in_response_to,
        issuer,
        saml_response_xml,
    )
}

/// Build a SOAP `<ArtifactResolve>` parsing helper result.
pub(crate) struct ResolvedArtifactResolve {
    pub id: String,
    #[allow(dead_code)]
    pub issuer: String,
    pub artifact: String,
}

/// Parse a SAML `<ArtifactResolve>` from raw SOAP XML.
pub(crate) fn parse_artifact_resolve(soap_body: &str) -> QidResult<ResolvedArtifactResolve> {
    let (_, artifact_tag) = soap_body
        .split_once("<samlp:ArtifactResolve")
        .ok_or_else(|| QidError::BadRequest {
            message: "missing samlp:ArtifactResolve element".to_string(),
        })?;
    let id = artifact_tag
        .split_once("ID=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(id, _)| id.to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "missing ArtifactResolve ID".to_string(),
        })?;
    let issuer = artifact_tag
        .split_once("<saml:Issuer>")
        .and_then(|(_, rest)| rest.split_once("</saml:Issuer>"))
        .map(|(iss, _)| iss.to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "missing ArtifactResolve Issuer".to_string(),
        })?;
    let artifact = artifact_tag
        .split_once("<samlp:Artifact>")
        .and_then(|(_, rest)| rest.split_once("</samlp:Artifact>"))
        .map(|(art, _)| art.trim().to_string())
        .ok_or_else(|| QidError::BadRequest {
            message: "missing samlp:Artifact element".to_string(),
        })?;
    Ok(ResolvedArtifactResolve {
        id,
        issuer,
        artifact,
    })
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
mod tests {
    use super::*;

    #[test]
    fn artifact_roundtrip() {
        let stored = store_artifact("<saml:Response/>", 3600);
        let resolved = resolve_artifact(&stored.artifact).unwrap();
        assert_eq!(resolved, "<saml:Response/>");
    }

    #[test]
    fn artifact_expired() {
        let stored = store_artifact("<saml:Response/>", 0);
        {
            let mut store = ARTIFACTS.lock().unwrap_or_else(|e| e.into_inner());
            let handle_hex = {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(&stored.artifact)
                    .unwrap();
                hex::encode(&raw[4..])
            };
            if let Some(entry) = store.get_mut(&handle_hex) {
                entry.expires_at = 0;
            }
        }
        let result = resolve_artifact(&stored.artifact);
        assert!(result.is_err());
    }

    #[test]
    fn artifact_invalid_base64() {
        let result = resolve_artifact("!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn artifact_wrong_type_code() {
        let raw = base64::engine::general_purpose::STANDARD.encode([
            0xffu8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let result = resolve_artifact(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn parse_artifact_resolve_valid() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_abc123" Version="2.0" IssueInstant="2026-06-21T12:00:00Z">
      <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
      <samlp:Artifact>AAABAAARbR0jLVq5Qkq4pPqxR0jLVq5Qkq4=</samlp:Artifact>
    </samlp:ArtifactResolve>
  </soap:Body>
</soap:Envelope>"#;
        let parsed = parse_artifact_resolve(xml).unwrap();
        assert_eq!(parsed.id, "_abc123");
        assert_eq!(parsed.issuer, "https://sp.example.com/saml");
        assert_eq!(parsed.artifact, "AAABAAARbR0jLVq5Qkq4pPqxR0jLVq5Qkq4=");
    }

    #[test]
    fn parse_artifact_resolve_missing_id() {
        let xml = r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Issuer>issuer</saml:Issuer>
      <samlp:Artifact>AAABAAAR</samlp:Artifact>
    </samlp:ArtifactResolve>"#;
        let result = parse_artifact_resolve(xml);
        assert!(result.is_err());
    }

    #[test]
    fn build_artifact_response_contains_elements() {
        let xml = build_artifact_response("_req123", "https://idp.example.com", "<saml:Response/>");
        assert!(xml.contains("ArtifactResponse"));
        assert!(xml.contains("_req123"));
        assert!(xml.contains("https://idp.example.com"));
        assert!(xml.contains("<saml:Response/>"));
        assert!(xml.contains("soap:Envelope"));
    }

    #[test]
    fn iso_now_format() {
        let s = iso_now_utc();
        assert!(s.len() >= 24, "ISO string too short: {s}");
        assert!(s.ends_with('Z'), "should end with Z: {s}");
    }
}
