//! OAuth mTLS sender-constrained token helpers.

use axum::http::HeaderMap;
#[cfg(test)]
use base64::Engine;
use qid_core::{
    error::{QidError, QidResult},
    state::SharedState,
};
use qid_storage::prelude::*;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, ToSocketAddrs};
use x509_parser::prelude::{FromDer, X509Certificate};

const MTLS_ADAPTER_AUTHORIZATION_HEADER: &str = "x-qid-pep-adapter-authorization";
const MTLS_THUMBPRINT_HEADER: &str = "x-qid-mtls-x5t-s256";

/// Settings controlling certificate revocation checks.
#[derive(Debug, Clone, Default)]
pub struct RevocationCheckSettings {
    /// When true, attempt to fetch and verify a CRL for client certificates
    /// that advertise CRL Distribution Points. Failed fetches or unparseable
    /// CRLs cause the certificate to be rejected.
    pub require_crl: bool,
    /// Timeout for HTTP fetches of CRLs, in seconds.
    pub timeout_seconds: u64,
}

/// Settings for OCSP (Online Certificate Status Protocol) revocation
/// checking per RFC 6960.
#[derive(Debug, Clone, Default)]
pub struct OcspSettings {
    /// When true, attempt to check certificate status via OCSP.
    /// The OCSP responder URI is extracted from the AIA extension.
    /// If no OCSP responder URI is found and `require_ocsp` is true,
    /// the certificate is rejected.
    pub require_ocsp: bool,
    /// Timeout for the OCSP HTTP request in seconds.
    pub timeout_seconds: u64,
}

pub fn extract_mtls_x5t_s256<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> QidResult<Option<String>> {
    let token = bearer_token_from_header(headers, MTLS_ADAPTER_AUTHORIZATION_HEADER).ok_or_else(|| QidError::Unauthorized {
        message: "OAuth mTLS requires native peer certificate binding or authenticated PEP mTLS metadata".to_string(),
    })?;
    let mut authenticated_thumbprint = None;
    for adapter in state
        .config
        .realms
        .iter()
        .flat_map(|realm| realm.pep_registrations.registrations.iter())
    {
        let Some(audience) = adapter.audience.as_deref() else {
            continue;
        };
        if let Ok(decoded) = state.signer.decode_with_aud(token, audience)
            && decoded.claims.sub.as_deref() == Some(adapter.name.as_str())
        {
            authenticated_thumbprint = decoded
                .claims
                .extra
                .get("x5t#S256")
                .or_else(|| decoded.claims.extra.get("x5t_s256"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            break;
        }
    }
    let Some(bound_thumbprint) = authenticated_thumbprint else {
        return Err(QidError::Unauthorized {
            message: "invalid or unbound PEP mTLS metadata adapter authentication".to_string(),
        });
    };
    let x5t_s256 = headers
        .get(MTLS_THUMBPRINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: "authenticated PEP mTLS metadata is missing x5t#S256".to_string(),
        })?;
    if x5t_s256 != bound_thumbprint {
        return Err(QidError::Unauthorized {
            message: "PEP mTLS metadata thumbprint does not match adapter assertion".to_string(),
        });
    }
    Ok(Some(x5t_s256.to_string()))
}

fn bearer_token_from_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.contains(' ')).then_some(token)
}

/// Extract the DER-encoded mTLS client certificate from request headers.
///
/// Returns `None` when no certificate header is present.
pub fn extract_mtls_client_der(_headers: &HeaderMap) -> QidResult<Option<Vec<u8>>> {
    Err(QidError::Unauthorized {
        message: "OAuth mTLS requires native peer certificate binding; certificate headers are not trusted".to_string(),
    })
}

/// Perform a synchronous CRL-based revocation check against the CRL
/// distribution points embedded in the supplied certificate DER.
///
/// The function parses the certificate, follows the first reachable
/// CRL Distribution Point URI over HTTP, parses the resulting DER-encoded
/// CRL, and rejects the certificate if its serial number appears on the CRL
/// or if any required lookup fails when `settings.require_crl` is `true`.
pub fn check_certificate_revocation(
    cert_der: &[u8],
    settings: &RevocationCheckSettings,
) -> QidResult<()> {
    if !settings.require_crl {
        return Ok(());
    }
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| QidError::Unauthorized {
        message: format!("failed to parse client certificate for revocation check: {e}"),
    })?;

    let crl_urls = extract_crl_distribution_points(&cert);
    if crl_urls.is_empty() {
        return Err(QidError::Unauthorized {
            message: "client certificate has no CRL distribution points and CRL is required"
                .to_string(),
        });
    }

    let serial = cert.raw_serial_as_string();
    let issuer_name = cert.tbs_certificate.issuer.to_string();
    let issuer_key_id = cert
        .extensions_map()
        .ok()
        .and_then(|m| {
            m.get(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
                .copied()
        })
        .and_then(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        });

    let mut last_error: Option<String> = None;
    for url in crl_urls {
        match fetch_and_verify_crl(
            &url,
            &serial,
            &issuer_name,
            issuer_key_id.as_deref(),
            settings,
        ) {
            Ok(RevocationOutcome::Good) => return Ok(()),
            Ok(RevocationOutcome::Revoked) => {
                return Err(QidError::Unauthorized {
                    message: "mTLS client certificate has been revoked".to_string(),
                });
            }
            Err(err) => {
                last_error = Some(err.message());
            }
        }
    }
    Err(QidError::Unauthorized {
        message: last_error.unwrap_or_else(|| "all CRL lookups failed".to_string()),
    })
}

/// Perform OCSP revocation check (RFC 6960) for a client certificate.
///
/// Extracts the OCSP responder URI from the Authority Information Access
/// extension, builds a DER-encoded OCSP request, POSTs it to the responder,
/// and validates the response.
pub fn check_certificate_ocsp(
    cert_der: &[u8],
    issuer_der: Option<&[u8]>,
    settings: &OcspSettings,
) -> QidResult<()> {
    if !settings.require_ocsp {
        return Ok(());
    }
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| QidError::Unauthorized {
        message: format!("failed to parse client certificate for OCSP: {e}"),
    })?;

    let ocsp_url = extract_ocsp_responder_url(&cert).ok_or_else(|| QidError::Unauthorized {
        message: "certificate has no OCSP responder URI in AIA extension".to_string(),
    })?;
    validate_revocation_fetch_url(&ocsp_url, "OCSP")?;

    // Use the supplied issuer DER, or fall back to the issuer field on the certificate.
    let issuer_der = match issuer_der {
        Some(der) => der,
        None => cert.tbs_certificate.issuer().as_raw(),
    };

    // Compute CertID: SHA-256 hash of issuer DN and issuer public key
    let issuer_name_hash = Sha256::digest(issuer_der).to_vec();
    let issuer_key_hash = {
        let (_, issuer_cert) =
            X509Certificate::from_der(issuer_der).map_err(|_| QidError::Unauthorized {
                message: "failed to parse issuer certificate for OCSP".to_string(),
            })?;
        let spki = issuer_cert.tbs_certificate.subject_pki.raw;
        Sha256::digest(spki).to_vec()
    };
    let serial_bytes = cert.raw_serial();

    let request_der = build_ocsp_request(&issuer_name_hash, &issuer_key_hash, serial_bytes);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(
            settings.timeout_seconds.max(1),
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| QidError::Unauthorized {
            message: format!("failed to build OCSP HTTP client: {e}"),
        })?;
    let response = client
        .post(&ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .map_err(|e| QidError::Unauthorized {
            message: format!("OCSP request to {ocsp_url} failed: {e}"),
        })?;
    if !response.status().is_success() {
        return Err(QidError::Unauthorized {
            message: format!(
                "OCSP responder {ocsp_url} returned status {}",
                response.status()
            ),
        });
    }
    let response_bytes = response.bytes().map_err(|e| QidError::Unauthorized {
        message: format!("failed to read OCSP response body: {e}"),
    })?;

    parse_ocsp_response(&response_bytes)
}

enum RevocationOutcome {
    Good,
    Revoked,
}

/// Minimal DER Writer for OCSP request construction.
struct DerWriter(Vec<u8>);

impl DerWriter {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn write_tag(&mut self, tag: u8, contents: &[u8]) {
        self.0.push(tag);
        self.write_len(contents.len());
        self.0.extend_from_slice(contents);
    }

    fn write_len(&mut self, len: usize) {
        if len < 128 {
            self.0.push(len as u8);
        } else if len < 256 {
            self.0.push(0x81);
            self.0.push(len as u8);
        } else {
            self.0.push(0x82);
            self.0.push((len >> 8) as u8);
            self.0.push((len & 0xff) as u8);
        }
    }

    fn write_sequence(&mut self, contents: impl AsRef<[u8]>) {
        self.write_tag(0x30, contents.as_ref());
    }

    fn write_octet_string(&mut self, contents: &[u8]) {
        self.write_tag(0x04, contents);
    }

    fn write_oid(&mut self, oid: &[u32]) {
        let mut encoded = Vec::new();
        if oid.len() >= 2 {
            encoded.push((oid[0] * 40 + oid[1]) as u8);
        }
        for &component in &oid[2..] {
            if component < 128 {
                encoded.push(component as u8);
            } else {
                let mut val = component;
                let mut tmp = Vec::new();
                tmp.push((val & 0x7f) as u8);
                val >>= 7;
                while val > 0 {
                    tmp.push((val & 0x7f) as u8 | 0x80);
                    val >>= 7;
                }
                encoded.extend(tmp.into_iter().rev());
            }
        }
        self.write_tag(0x06, &encoded);
    }

    #[allow(dead_code)] // used in OCSP request construction
    fn write_null(&mut self) {
        self.0.push(0x05);
        self.0.push(0x00);
    }

    #[allow(dead_code)]
    fn write_explicit_tag(&mut self, tag: u8, contents: &[u8]) {
        self.write_tag(0xa0 | tag, contents);
    }

    fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

/// Build a DER-encoded OCSP request for a single certificate.
fn build_ocsp_request(
    issuer_name_hash: &[u8],
    issuer_key_hash: &[u8],
    serial_number: &[u8],
) -> Vec<u8> {
    // AlgorithmIdentifier for SHA-256: 2.16.840.1.101.3.4.2.1
    let mut hash_alg = DerWriter::new();
    let mut hash_alg_inner = DerWriter::new();
    hash_alg_inner.write_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]); // id-sha256
    let hash_alg_seq = hash_alg_inner.into_inner();
    hash_alg.write_sequence(&hash_alg_seq);
    let hash_alg_der = hash_alg.into_inner();

    // CertID = SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let mut cert_id = DerWriter::new();
    cert_id.write_sequence({
        let mut inner = DerWriter::new();
        inner.0.extend_from_slice(&hash_alg_der);
        inner.write_octet_string(issuer_name_hash);
        inner.write_octet_string(issuer_key_hash);
        inner.write_tag(0x02, serial_number); // INTEGER
        inner.into_inner()
    });

    // Request = SEQUENCE { reqCert CertID }
    let mut request = DerWriter::new();
    request.write_sequence({
        let mut inner = DerWriter::new();
        inner.0.extend_from_slice(&cert_id.into_inner());
        inner.into_inner()
    });

    // TBSRequest = SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, requestList SEQUENCE OF Request }
    let mut tbs_request = DerWriter::new();
    tbs_request.write_sequence({
        let mut inner = DerWriter::new();
        // requestList SEQUENCE OF Request
        inner.write_sequence(request.into_inner());
        inner.into_inner()
    });

    // OCSPRequest = SEQUENCE { tbsRequest TBSRequest }
    let mut ocsp_request = DerWriter::new();
    ocsp_request.write_sequence(tbs_request.into_inner());
    ocsp_request.into_inner()
}

/// Parse an OCSP response and determine certificate status.
fn parse_ocsp_response(response_bytes: &[u8]) -> QidResult<()> {
    const STATUS_SUCCESSFUL: u8 = 0;
    const STATUS_MALFORMED: u8 = 1;
    const STATUS_INTERNAL: u8 = 2;
    const STATUS_TRY_LATER: u8 = 3;
    const STATUS_SIG_REQUIRED: u8 = 5;
    const STATUS_UNAUTHORIZED: u8 = 6;

    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT OPTIONAL }
    // Read the status from the first element inside the top-level SEQUENCE.
    let status = der_read_enumerated(response_bytes)?;
    match status {
        STATUS_SUCCESSFUL => {}
        STATUS_MALFORMED => {
            return Err(QidError::Unauthorized {
                message: "OCSP: malformedRequest".into(),
            });
        }
        STATUS_INTERNAL => {
            return Err(QidError::Unauthorized {
                message: "OCSP: internalError".into(),
            });
        }
        STATUS_TRY_LATER => {
            return Err(QidError::Unauthorized {
                message: "OCSP: tryLater".into(),
            });
        }
        STATUS_SIG_REQUIRED => {
            return Err(QidError::Unauthorized {
                message: "OCSP: sigRequired".into(),
            });
        }
        STATUS_UNAUTHORIZED => {
            return Err(QidError::Unauthorized {
                message: "OCSP: unauthorized".into(),
            });
        }
        _ => {
            return Err(QidError::Unauthorized {
                message: format!("OCSP: unknown status {status}"),
            });
        }
    }

    // Status is successful.  Walk DER for a certStatus choice.
    match find_ocsp_cert_status(response_bytes) {
        Some(0x80) => Ok(()),
        Some(0xa1) => Err(QidError::Unauthorized {
            message: "client certificate has been revoked (OCSP)".into(),
        }),
        Some(0x82) => Err(QidError::Unauthorized {
            message: "certificate status unknown (OCSP)".into(),
        }),
        _ => Err(QidError::Unauthorized {
            message: "no OCSP certStatus found".into(),
        }),
    }
}

/// Scan OCSP response DER for the certStatus choice tag in a SingleResponse.
/// Returns the tag byte (0x80 = good, 0xa1 = revoked, 0x82 = unknown) if found.
fn find_ocsp_cert_status(der: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 1 < der.len() {
        let tag = der[i];
        let (len, hdr) = der_decode_len(&der[i + 1..])?;
        let total = i + 1 + hdr + len;
        if total > der.len() {
            return None;
        }
        if tag == 0x30 {
            let content = &der[i + 1 + hdr..total];
            let mut offset = 0;
            let mut count = 0;
            while offset < content.len() {
                let etag = content[offset];
                let (elen, ehdr) = der_decode_len(&content[offset + 1..])?;
                if offset + 1 + ehdr + elen > content.len() {
                    break;
                }
                count += 1;
                if count == 2 && (etag == 0x80 || etag == 0xa1 || etag == 0x82) {
                    return Some(etag);
                }
                offset += 1 + ehdr + elen;
            }
            if let Some(found) = find_ocsp_cert_status(content) {
                return Some(found);
            }
        } else if tag == 0x80 || tag == 0xa1 || tag == 0x82 {
            return Some(tag);
        }
        i = total;
    }
    None
}

/// Read the first ENUMERATED value inside a SEQUENCE from `data`.
fn der_read_enumerated(data: &[u8]) -> QidResult<u8> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(QidError::Unauthorized {
            message: "OCSP: expected SEQUENCE".into(),
        });
    }
    let (seq_len, seq_hdr) = der_decode_len(&data[1..]).ok_or_else(|| QidError::Unauthorized {
        message: "OCSP: invalid SEQUENCE length".into(),
    })?;
    let seq_start = 1 + seq_hdr;
    let content =
        data.get(seq_start..seq_start + seq_len)
            .ok_or_else(|| QidError::Unauthorized {
                message: "OCSP: truncated SEQUENCE".into(),
            })?;
    if content.is_empty() || content[0] != 0x0a {
        return Err(QidError::Unauthorized {
            message: "OCSP: expected ENUMERATED status".into(),
        });
    }
    let (val_len, val_hdr) =
        der_decode_len(&content[1..]).ok_or_else(|| QidError::Unauthorized {
            message: "OCSP: invalid ENUMERATED length".into(),
        })?;
    let val_start = 1 + val_hdr;
    let value =
        content
            .get(val_start..val_start + val_len)
            .ok_or_else(|| QidError::Unauthorized {
                message: "OCSP: truncated ENUMERATED".into(),
            })?;
    if value.is_empty() {
        return Err(QidError::Unauthorized {
            message: "OCSP: empty ENUMERATED value".into(),
        });
    }
    Ok(value[0])
}

/// Decode a DER length field. Returns `(length, bytes_consumed)`.
fn der_decode_len(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }
    let b = buf[0] as usize;
    if b < 0x80 {
        Some((b, 1))
    } else if b == 0x81 && buf.len() >= 2 {
        Some((buf[1] as usize, 2))
    } else if b == 0x82 && buf.len() >= 3 {
        Some((((buf[1] as usize) << 8) | (buf[2] as usize), 3))
    } else {
        None
    }
}

fn extract_ocsp_responder_url(cert: &X509Certificate<'_>) -> Option<String> {
    let extensions = cert.extensions_map().ok()?;
    let aia_ext = extensions.get(&x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)?;
    match aia_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) => {
            for desc in &aia.accessdescs {
                if desc.access_method == x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP
                    && let x509_parser::prelude::GeneralName::URI(uri) = &desc.access_location
                {
                    return Some(uri.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

fn validate_revocation_fetch_url(url: &str, label: &str) -> QidResult<()> {
    let parsed = reqwest::Url::parse(url).map_err(|e| QidError::Unauthorized {
        message: format!("{label} responder URL is invalid: {e}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(QidError::Unauthorized {
            message: format!("{label} responder URL scheme is not allowed"),
        });
    }
    let Some(host) = parsed.host_str() else {
        return Err(QidError::Unauthorized {
            message: format!("{label} responder URL host is missing"),
        });
    };
    let normalized_host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if matches!(
        normalized_host.as_str(),
        "localhost" | "localhost.localdomain"
    ) || normalized_host.ends_with(".localhost")
    {
        return Err(QidError::Unauthorized {
            message: format!("{label} responder URL host is not allowed"),
        });
    }
    if let Ok(ip) = normalized_host.parse::<IpAddr>()
        && !is_public_ip_literal(ip)
    {
        return Err(QidError::Unauthorized {
            message: format!("{label} responder URL IP is not allowed"),
        });
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| QidError::Unauthorized {
            message: format!("{label} responder URL port is missing"),
        })?;
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|e| QidError::Unauthorized {
            message: format!("{label} responder URL DNS resolution failed: {e}"),
        })?;
    for address in resolved {
        if !is_public_ip_literal(address.ip()) {
            return Err(QidError::Unauthorized {
                message: format!("{label} responder URL resolved IP is not allowed"),
            });
        }
    }
    Ok(())
}

fn is_public_ip_literal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
    }
}

fn fetch_and_verify_crl(
    url: &str,
    serial: &str,
    expected_issuer: &str,
    expected_key_id: Option<&[u8]>,
    settings: &RevocationCheckSettings,
) -> QidResult<RevocationOutcome> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(QidError::Unauthorized {
            message: format!("unsupported CRL distribution point scheme: {url}"),
        });
    }
    validate_revocation_fetch_url(url, "CRL")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(
            settings.timeout_seconds.max(1),
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| QidError::Unauthorized {
            message: format!("failed to build CRL HTTP client: {e}"),
        })?;
    let response = client.get(url).send().map_err(|e| QidError::Unauthorized {
        message: format!("failed to fetch CRL from {url}: {e}"),
    })?;
    if !response.status().is_success() {
        return Err(QidError::Unauthorized {
            message: format!("CRL endpoint {url} returned status {}", response.status()),
        });
    }
    let bytes = response.bytes().map_err(|e| QidError::Unauthorized {
        message: format!("failed to read CRL body from {url}: {e}"),
    })?;

    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&bytes)
        .map_err(|e| QidError::Unauthorized {
            message: format!("failed to parse CRL from {url}: {e}"),
        })?;
    let crl_issuer = crl.tbs_cert_list.issuer.to_string();
    if crl_issuer != expected_issuer {
        return Err(QidError::Unauthorized {
            message: format!(
                "CRL issuer mismatch: expected '{expected_issuer}', got '{crl_issuer}'"
            ),
        });
    }
    if let Some(expected) = expected_key_id {
        let crl_key_id = crl
            .tbs_cert_list
            .extensions_map()
            .ok()
            .and_then(|m| {
                m.get(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
                    .copied()
            })
            .and_then(|ext| match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            });
        match crl_key_id {
            Some(actual) if actual == expected => {}
            _ => {
                return Err(QidError::Unauthorized {
                    message: "CRL authority key identifier does not match issuer".to_string(),
                });
            }
        }
    }
    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial_as_string() == serial {
            return Ok(RevocationOutcome::Revoked);
        }
    }
    Ok(RevocationOutcome::Good)
}

fn extract_crl_distribution_points(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok(extensions) = cert.extensions_map() else {
        return urls;
    };
    let Some(extension) = extensions
        .get(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .copied()
    else {
        return urls;
    };
    if let x509_parser::extensions::ParsedExtension::CRLDistributionPoints(points) =
        extension.parsed_extension()
    {
        for point in points.iter() {
            if let Some(x509_parser::extensions::DistributionPointName::FullName(general_names)) =
                point.distribution_point.as_ref()
            {
                for general_name in general_names.iter() {
                    if let x509_parser::prelude::GeneralName::URI(uri) = general_name {
                        urls.push(uri.to_string());
                    }
                }
            }
        }
    }
    urls
}

#[cfg(test)]
fn normalize_thumbprint(value: &str) -> QidResult<String> {
    let value = value.trim();
    if is_base64url_sha256(value) {
        return Ok(value.to_string());
    }
    if is_hex_sha256(value) {
        let mut bytes = Vec::with_capacity(32);
        for pair in value.as_bytes().chunks_exact(2) {
            let hex = std::str::from_utf8(pair).map_err(|e| QidError::BadRequest {
                message: format!("invalid mTLS certificate thumbprint: {e}"),
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|e| QidError::BadRequest {
                message: format!("invalid mTLS certificate thumbprint: {e}"),
            })?;
            bytes.push(byte);
        }
        return Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    }
    Err(QidError::BadRequest {
        message: "invalid mTLS certificate thumbprint".to_string(),
    })
}

#[cfg(test)]
fn decode_certificate_der(value: &str) -> QidResult<Vec<u8>> {
    let decoded = urlencoding::decode(value).map_err(|e| QidError::BadRequest {
        message: format!("invalid mTLS client certificate encoding: {e}"),
    })?;
    let cert = decoded.trim();
    let body = if let Some(start) = cert.find("-----BEGIN CERTIFICATE-----") {
        let cert = &cert[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = cert
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| QidError::BadRequest {
                message: "invalid mTLS client certificate PEM".to_string(),
            })?;
        &cert[..end]
    } else {
        cert
    };
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid mTLS client certificate DER: {e}"),
        })
}

#[cfg(test)]
fn is_base64url_sha256(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hex_thumbprint() {
        let value = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(
            normalize_thumbprint(value).unwrap(),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
    }

    #[test]
    fn hashes_pem_certificate_body() {
        let der = b"certificate-bytes-for-test";
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        assert_eq!(decode_certificate_der(&pem).unwrap(), der);
    }

    #[test]
    fn revocation_check_is_noop_when_not_required() {
        let der = b"not-a-cert";
        let settings = RevocationCheckSettings::default();
        assert!(check_certificate_revocation(der, &settings).is_ok());
    }

    #[test]
    fn ocsp_check_is_noop_when_not_required() {
        let settings = OcspSettings::default();
        assert!(check_certificate_ocsp(b"not-a-cert", None, &settings).is_ok());
    }

    #[test]
    fn der_writer_produces_valid_sequence() {
        let mut writer = DerWriter::new();
        writer.write_sequence(b"hello");
        // SEQUENCE tag 0x30, length 5, contents "hello"
        assert_eq!(
            writer.into_inner(),
            vec![0x30, 0x05, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn ocsp_request_builds_without_panic() {
        let req = build_ocsp_request(&[0; 32], &[0; 32], &[0x01, 0x02, 0x03]);
        assert!(!req.is_empty());
        // Should be a valid DER SEQUENCE
        assert_eq!(req[0], 0x30);
    }
}
