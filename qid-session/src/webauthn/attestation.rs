//! Required packed enrollment trust. Ceremony verification remains owned by caden.
use super::*;
use base64::engine::general_purpose::STANDARD;
use qid_core::config::{AttestationLimits, AttestationModelStatus, attestation_model_id};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_EXT_EXTENDED_KEY_USAGE,
    OID_X509_ORGANIZATION_NAME,
};
use x509_parser::{der_parser::der::parse_der_octetstring, prelude::*};

fn rejected() -> QidError {
    QidError::Crypto {
        message: "WebAuthn required trusted packed attestation refused".into(),
    }
}

// Bound attacker-controlled strings before decoding, and hence before CBOR allocation.
pub(super) fn check_encoded_sizes(
    value: &serde_json::Value,
    limits: &AttestationLimits,
) -> QidResult<()> {
    for (name, max) in [
        ("attestationObject", limits.evidence_bytes),
        ("clientDataJSON", limits.client_data_bytes),
    ] {
        let encoded = value["response"][name].as_str().ok_or_else(rejected)?;
        // URL_SAFE_NO_PAD uses ceil(4*n/3) characters.
        if encoded.len() > max.saturating_mul(4).saturating_add(2) / 3 {
            return Err(rejected());
        }
    }
    Ok(())
}

// There is no standardized packed-attestation EKU in this profile. Consume the
// entire iterator (including malformed suffixes), never stop at a matching OID.
struct NoEku;
impl webpki::ExtendedKeyUsageValidator for NoEku {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        let mut present = false;
        for _purpose in iter {
            // Every item, including Err, rejects this absent-EKU profile.
            present = true;
        }
        if present {
            Err(webpki::Error::BadDer)
        } else {
            Ok(())
        }
    }
}

pub(super) fn verify(
    policy: &PackedAttestationPolicy,
    evidence: &RegistrationEvidence,
    client_data: &[u8],
    now: u64,
) -> QidResult<()> {
    let metadata = &policy.metadata;
    if now < metadata.not_before || now >= metadata.expires_at || evidence.format != "packed" {
        return Err(rejected());
    }
    let model = metadata
        .models
        .get(&attestation_model_id(&evidence.aaguid))
        .ok_or_else(rejected)?;
    if model.status != AttestationModelStatus::Allowed {
        return Err(rejected());
    }
    let stmt = &evidence.statement;
    if !matches!(stmt.get("alg"), Some(CborValue::Integer(n)) if i128::from(*n) == -7) {
        return Err(rejected());
    }
    let Some(CborValue::Bytes(signature)) = stmt.get("sig") else {
        return Err(rejected());
    };
    let Some(CborValue::Array(chain)) = stmt.get("x5c") else {
        return Err(rejected());
    };
    if chain.is_empty() || chain.len() > policy.limits.certificates {
        return Err(rejected());
    }
    let certs: Vec<CertificateDer<'_>> = chain
        .iter()
        .map(|v| {
            let CborValue::Bytes(der) = v else {
                return Err(rejected());
            };
            if der.len() > policy.limits.certificate_bytes {
                return Err(rejected());
            }
            Ok(CertificateDer::from(der.as_slice()))
        })
        .collect::<QidResult<_>>()?;
    for (i, der) in certs.iter().enumerate() {
        check_profile(der, if i == 0 { Some(&evidence.aaguid) } else { None })?;
    }
    let roots: Vec<CertificateDer<'_>> = model
        .roots
        .iter()
        .map(|s| {
            STANDARD
                .decode(s)
                .map(CertificateDer::from)
                .map_err(|_| rejected())
        })
        .collect::<QidResult<_>>()?;
    let anchors = roots
        .iter()
        .map(|der| webpki::anchor_from_trusted_cert(der).map_err(|_| rejected()))
        .collect::<QidResult<Vec<_>>>()?;
    let leaf = webpki::EndEntityCert::try_from(&certs[0]).map_err(|_| rejected())?;
    // Non-TLS usage: no DNS/server/client-purpose assumptions. Only P256/SHA256
    // certificate signatures are supported by this deliberately narrow profile.
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P256_SHA256],
        &anchors,
        &certs[1..],
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        NoEku,
        None,
        None,
    )
    .map_err(|_| rejected())?;
    let mut signed = evidence.auth_data.clone();
    signed.extend_from_slice(&sha2::Sha256::digest(client_data));
    // Use the parsed certificate's real SPKI, not caden's DER byte-pattern scan.
    leaf.verify_signature(webpki::ring::ECDSA_P256_SHA256, &signed, signature)
        .map_err(|_| rejected())
}

fn check_profile(der: &[u8], aaguid: Option<&[u8]>) -> QidResult<()> {
    let (remaining, cert) = parse_x509_certificate(der).map_err(|_| rejected())?;
    if !remaining.is_empty() || cert.extensions_map().is_err() {
        return Err(rejected());
    }
    // Reject even an empty EKU extension: the configured profile requires absence.
    if cert
        .extensions()
        .iter()
        .any(|e| e.oid == OID_X509_EXT_EXTENDED_KEY_USAGE)
    {
        return Err(rejected());
    }
    if let Some(ku) = cert.key_usage().map_err(|_| rejected())?
        && !(if aaguid.is_some() {
            ku.value.digital_signature()
        } else {
            ku.value.key_cert_sign()
        })
    {
        return Err(rejected());
    }
    let Some(aaguid) = aaguid else {
        return Ok(());
    };
    if cert.version() != X509Version::V3
        || cert
            .basic_constraints()
            .map_err(|_| rejected())?
            .is_none_or(|bc| bc.value.ca)
    {
        return Err(rejected());
    }
    let subject = cert.subject();
    for oid in [
        OID_X509_COUNTRY_NAME,
        OID_X509_ORGANIZATION_NAME,
        OID_X509_COMMON_NAME,
    ] {
        if !subject
            .iter_by_oid(&oid)
            .any(|a| a.as_str().is_ok_and(|s| !s.is_empty()))
        {
            return Err(rejected());
        }
    }
    if !subject.iter_country().any(|a| {
        a.as_str()
            .is_ok_and(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
    }) {
        return Err(rejected());
    }
    let ous: Vec<_> = subject.iter_organizational_unit().collect();
    if ous.len() != 1 || ous[0].as_str() != Ok("Authenticator Attestation") {
        return Err(rejected());
    }
    // FIDO id-fido-gen-ce-aaguid: raw OID bytes, not decoded diagnostics.
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == [0x2b, 6, 1, 4, 1, 0x82, 0xe5, 0x1c, 1, 1, 4])
        .ok_or_else(rejected)?;
    let (remaining, octets) = parse_der_octetstring(ext.value).map_err(|_| rejected())?;
    if ext.critical || !remaining.is_empty() || octets.as_slice().map_err(|_| rejected())? != aaguid
    {
        return Err(rejected());
    }
    Ok(())
}
