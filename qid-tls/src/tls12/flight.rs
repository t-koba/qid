//! Offline TLS 1.2 server first flight encoding: no key schedule, no I/O.
//!
//! Fixed profile: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B), P-256,
//! null compression and ecdsa_secp256r1_sha256 (0x0403). This module produces
//! bytes and a transcript hash only; it never installs a listener or changes
//! another TLS stack's configuration.

use super::status::{
    build_certificate_status_multi, select_status_request, wrap_handshake_message,
};
use super::wire::{ClientHello, Extension, HandshakeMessage, Reader, parse_client_hello};
use super::{
    CERTIFICATE_STATUS, MAX_U16, MAX_U24, OcspResponse, STATUS_REQUEST_V2_ACK, Tls12Error,
    u24_bytes,
};
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};

const SERVER_VERSION: [u8; 2] = [0x03, 0x03];
const CIPHER_SUITE: u16 = 0xC02B;
const NAMED_CURVE: u16 = 0x0017;
const HASH_SHA256: u8 = 0x04;
const SIGNATURE_ECDSA: u8 = 0x03;

const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CERTIFICATE: u8 = 11;
const SERVER_KEY_EXCHANGE: u8 = 12;
const SERVER_HELLO_DONE: u8 = 14;

/// Caller-supplied material for one TLS 1.2 server first flight.
///
/// `client_hello_message` is the complete ClientHello including its original
/// four-byte handshake header; those exact bytes enter the transcript.
pub struct ServerFirstFlightInput<'a> {
    pub client_hello_message: &'a [u8],
    pub server_random: [u8; 32],
    pub certificates: &'a [&'a [u8]],
    pub ocsp_responses: &'a [OcspResponse<'a>],
    pub ecdhe_secret: &'a SecretKey,
    pub signing_key: &'a SigningKey,
}

/// The encoded first flight and the SHA-256 transcript through ServerHelloDone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerFirstFlight {
    pub messages: Vec<HandshakeMessage>,
    pub transcript_sha256: [u8; 32],
    pub selected_ocsp_multi: bool,
}

/// Validate the ClientHello against the fixed profile and encode the server
/// first flight, including the RFC 6961 multi-status message when selected.
///
/// No key derivation or Finished verification is performed here.
pub fn build_server_first_flight(
    input: &ServerFirstFlightInput<'_>,
) -> Result<ServerFirstFlight, Tls12Error> {
    let client = parse_client_hello_message(input.client_hello_message)?;
    validate_client_profile(&client)?;
    let status = select_status_request(&client.extensions)?;

    let mut messages = Vec::with_capacity(5);
    messages.push(HandshakeMessage {
        msg_type: SERVER_HELLO,
        body: build_server_hello(
            &client.extensions,
            input.server_random,
            status.ocsp_multi_usable,
        )?,
    });
    messages.push(HandshakeMessage {
        msg_type: CERTIFICATE,
        body: build_certificate(input.certificates)?,
    });
    if status.ocsp_multi_usable {
        let body = build_certificate_status_multi(input.certificates.len(), input.ocsp_responses)?;
        messages.push(HandshakeMessage {
            msg_type: CERTIFICATE_STATUS,
            body,
        });
    }

    let params = server_ecdh_params(input.ecdhe_secret)?;
    let signature = sign_server_key_exchange(
        client.random,
        &input.server_random,
        &params,
        input.signing_key,
    )?;
    let mut ske_body = params;
    ske_body.extend_from_slice(&[HASH_SHA256, SIGNATURE_ECDSA]);
    ske_body.extend_from_slice(
        &u16::try_from(signature.len())
            .map_err(|_| Tls12Error::InvalidSignature)?
            .to_be_bytes(),
    );
    ske_body.extend_from_slice(&signature);
    messages.push(HandshakeMessage {
        msg_type: SERVER_KEY_EXCHANGE,
        body: ske_body,
    });
    messages.push(HandshakeMessage {
        msg_type: SERVER_HELLO_DONE,
        body: Vec::new(),
    });

    let mut transcript = Sha256::new();
    transcript.update(input.client_hello_message);
    for message in &messages {
        transcript.update(wrap_handshake_message(message.msg_type, &message.body)?);
    }
    Ok(ServerFirstFlight {
        messages,
        transcript_sha256: transcript.finalize().into(),
        selected_ocsp_multi: status.ocsp_multi_usable,
    })
}

/// Check the full message framing before hashing it into the transcript.
fn parse_client_hello_message(message: &[u8]) -> Result<ClientHello<'_>, Tls12Error> {
    if message.len() < 4 || message[0] != CLIENT_HELLO {
        return Err(Tls12Error::InvalidClientHelloMessage);
    }
    let body_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    if body_len != message.len() - 4 {
        return Err(Tls12Error::InvalidClientHelloMessage);
    }
    parse_client_hello(&message[4..])
}

fn validate_client_profile(client: &ClientHello<'_>) -> Result<(), Tls12Error> {
    if client.legacy_version != SERVER_VERSION {
        return Err(Tls12Error::UnsupportedVersion);
    }
    if !client.cipher_suites.contains(&CIPHER_SUITE) {
        return Err(Tls12Error::UnsupportedCipherSuite);
    }
    if !client.compression_methods.contains(&0) {
        return Err(Tls12Error::UnsupportedCompressionMethod);
    }
    for extension in &client.extensions {
        match extension.ext_type {
            EXT_SUPPORTED_GROUPS => validate_supported_groups(extension.data)?,
            EXT_EC_POINT_FORMATS => validate_point_formats(extension.data)?,
            EXT_SIGNATURE_ALGORITHMS => validate_signature_algorithms(extension.data)?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_supported_groups(data: &[u8]) -> Result<(), Tls12Error> {
    let mut reader = Reader::new(data);
    let len = reader.u16(Tls12Error::InvalidSupportedGroups)?;
    let groups = reader.take(len, Tls12Error::InvalidSupportedGroups)?;
    reader.finish(Tls12Error::InvalidSupportedGroups)?;
    if groups.is_empty() || groups.len() % 2 != 0 {
        return Err(Tls12Error::InvalidSupportedGroups);
    }
    let supported = groups
        .chunks_exact(2)
        .any(|pair| u16::from_be_bytes([pair[0], pair[1]]) == NAMED_CURVE);
    if supported {
        Ok(())
    } else {
        Err(Tls12Error::UnsupportedNamedCurve)
    }
}

fn validate_point_formats(data: &[u8]) -> Result<(), Tls12Error> {
    let mut reader = Reader::new(data);
    let formats = reader.vector_u8(1, u8::MAX as usize, Tls12Error::InvalidEcPointFormats)?;
    reader.finish(Tls12Error::InvalidEcPointFormats)?;
    if formats.contains(&0) {
        Ok(())
    } else {
        Err(Tls12Error::UnsupportedPointFormat)
    }
}

fn validate_signature_algorithms(data: &[u8]) -> Result<(), Tls12Error> {
    let mut reader = Reader::new(data);
    let schemes = reader.vector_u16(2, MAX_U16, Tls12Error::InvalidSignatureAlgorithms)?;
    reader.finish(Tls12Error::InvalidSignatureAlgorithms)?;
    if schemes.len() % 2 != 0 {
        return Err(Tls12Error::InvalidSignatureAlgorithms);
    }
    let supported = schemes
        .chunks_exact(2)
        .any(|pair| pair == [HASH_SHA256, SIGNATURE_ECDSA]);
    if supported {
        Ok(())
    } else {
        Err(Tls12Error::UnsupportedSignatureScheme)
    }
}

fn build_server_hello(
    client_extensions: &[Extension<'_>],
    server_random: [u8; 32],
    ocsp_multi: bool,
) -> Result<Vec<u8>, Tls12Error> {
    let mut extensions = Vec::new();
    if ocsp_multi {
        extensions.extend_from_slice(&STATUS_REQUEST_V2_ACK);
    }
    if client_extensions
        .iter()
        .any(|extension| extension.ext_type == EXT_EXTENDED_MASTER_SECRET)
    {
        push_extension(&mut extensions, EXT_EXTENDED_MASTER_SECRET, &[])?;
    }
    if let Some(renegotiation) = client_extensions
        .iter()
        .find(|extension| extension.ext_type == EXT_RENEGOTIATION_INFO)
    {
        push_extension(&mut extensions, EXT_RENEGOTIATION_INFO, renegotiation.data)?;
    }

    let mut body = Vec::with_capacity(2 + 32 + 1 + 2 + 1 + 2 + extensions.len());
    body.extend_from_slice(&SERVER_VERSION);
    body.extend_from_slice(&server_random);
    body.push(0); // empty legacy_session_id
    body.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
    body.push(0); // null compression
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .map_err(|_| Tls12Error::InvalidExtensions)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);
    Ok(body)
}

fn push_extension(block: &mut Vec<u8>, ext_type: u16, data: &[u8]) -> Result<(), Tls12Error> {
    let len = u16::try_from(data.len()).map_err(|_| Tls12Error::InvalidExtensions)?;
    block.extend_from_slice(&ext_type.to_be_bytes());
    block.extend_from_slice(&len.to_be_bytes());
    block.extend_from_slice(data);
    Ok(())
}

fn build_certificate(certificates: &[&[u8]]) -> Result<Vec<u8>, Tls12Error> {
    let mut list_len = 0usize;
    for der in certificates {
        if der.len() > MAX_U24 {
            return Err(Tls12Error::InvalidCertificateList);
        }
        list_len = list_len
            .checked_add(3)
            .and_then(|sum| sum.checked_add(der.len()))
            .ok_or(Tls12Error::InvalidCertificateList)?;
        if list_len > MAX_U24 {
            return Err(Tls12Error::InvalidCertificateList);
        }
    }
    let mut body = Vec::with_capacity(3 + list_len);
    body.extend_from_slice(&u24_bytes(list_len));
    for der in certificates {
        body.extend_from_slice(&u24_bytes(der.len()));
        body.extend_from_slice(der);
    }
    Ok(body)
}

/// RFC 4492 §5.4 `ServerKeyExchange` EC parameters: named_curve, P-256,
/// then the 65-byte uncompressed SEC1 point as a u8-length vector.
fn server_ecdh_params(secret: &SecretKey) -> Result<Vec<u8>, Tls12Error> {
    let point = secret.public_key().to_sec1_point(false);
    let point = point.as_bytes();
    if point.len() != 65 || point[0] != 4 {
        return Err(Tls12Error::InvalidEcdhePoint);
    }
    let mut params = Vec::with_capacity(4 + point.len());
    params.extend_from_slice(&[0x03, 0x00, NAMED_CURVE as u8, point.len() as u8]);
    params.extend_from_slice(point);
    Ok(params)
}

/// RFC 5246 §7.4.3: sign client_random || server_random || ECDHE params,
/// hashed once with SHA-256. `PrehashSigner` makes the hash choice explicit;
/// the p256 `Signer` trait would hash the message itself with its own digest.
fn sign_server_key_exchange(
    client_random: &[u8],
    server_random: &[u8; 32],
    params: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Tls12Error> {
    let mut preimage = Vec::with_capacity(32 + 32 + params.len());
    preimage.extend_from_slice(client_random);
    preimage.extend_from_slice(server_random);
    preimage.extend_from_slice(params);
    let digest = Sha256::digest(preimage);
    let signature: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|_| Tls12Error::InvalidSignature)?;
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::{STATUS_REQUEST, STATUS_REQUEST_V2};
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    const CLIENT_RANDOM: [u8; 32] = [0xA1; 32];
    const V2_MULTI_DATA: &[u8] = &[0x00, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    const V2_OCSP_DATA: &[u8] = &[0x00, 0x07, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];

    fn u24(len: usize) -> [u8; 3] {
        [(len >> 16) as u8, (len >> 8) as u8, len as u8]
    }

    fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(4 + data.len());
        encoded.extend_from_slice(&ext_type.to_be_bytes());
        encoded.extend_from_slice(&(data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(data);
        encoded
    }

    fn client_message(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&CLIENT_RANDOM);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut message = vec![1];
        message.extend_from_slice(&u24(body.len()));
        message.extend_from_slice(&body);
        message
    }

    fn keys() -> (SecretKey, SigningKey) {
        let ecdhe = SecretKey::from_slice(&[0x11; 32]).expect("valid ECDHE scalar");
        let signing = SigningKey::from_bytes(&[0x22; 32].into()).expect("valid signing scalar");
        (ecdhe, signing)
    }

    fn input<'a>(
        message: &'a [u8],
        ecdhe: &'a SecretKey,
        signing: &'a SigningKey,
        certificates: &'a [&'a [u8]],
        responses: &'a [OcspResponse<'a>],
    ) -> ServerFirstFlightInput<'a> {
        ServerFirstFlightInput {
            client_hello_message: message,
            server_random: [0xB2; 32],
            certificates,
            ocsp_responses: responses,
            ecdhe_secret: ecdhe,
            signing_key: signing,
        }
    }

    fn v2_request() -> Vec<u8> {
        extension(STATUS_REQUEST_V2, V2_MULTI_DATA)
    }

    fn full_profile_extensions() -> Vec<u8> {
        let mut extensions = v2_request();
        extensions.extend_from_slice(&extension(EXT_EXTENDED_MASTER_SECRET, &[]));
        extensions.extend_from_slice(&extension(EXT_RENEGOTIATION_INFO, &[0xDE, 0xAD]));
        extensions.extend_from_slice(&extension(EXT_SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x17]));
        extensions.extend_from_slice(&extension(EXT_EC_POINT_FORMATS, &[0x01, 0x00]));
        extensions.extend_from_slice(&extension(
            EXT_SIGNATURE_ALGORITHMS,
            &[0x00, 0x02, 0x04, 0x03],
        ));
        extensions
    }

    fn framed(message: &HandshakeMessage) -> Vec<u8> {
        let mut framed = vec![message.msg_type];
        framed.extend_from_slice(&u24(message.body.len()));
        framed.extend_from_slice(&message.body);
        framed
    }

    fn expected_params(ecdhe: &SecretKey) -> Vec<u8> {
        let point = ecdhe.public_key().to_sec1_point(false);
        let mut params = vec![0x03, 0x00, 0x17, 0x41];
        params.extend_from_slice(point.as_bytes());
        params
    }

    #[test]
    fn happy_path_encodes_ordered_messages_and_verifiable_signature() {
        let (ecdhe, signing) = keys();
        let message = client_message(&full_profile_extensions());
        let cert_a = [0x30, 0x82, 0x01, 0x02];
        let cert_b = [0x30, 0x03, 0x01, 0x02, 0x03];
        let cert_c = [0x30, 0x00];
        let staple_a = [0x01, 0x02, 0x03];
        let staple_b = [0x04, 0x05];
        let certificates: &[&[u8]] = &[&cert_a, &cert_b, &cert_c];
        let responses: &[OcspResponse<'_>] = &[
            OcspResponse::Der(&staple_a),
            OcspResponse::Der(&staple_b),
            OcspResponse::Missing,
        ];
        let flight =
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .expect("build first flight");

        assert!(flight.selected_ocsp_multi);
        let types: Vec<u8> = flight.messages.iter().map(|m| m.msg_type).collect();
        assert_eq!(types, [2, 11, 22, 12, 14]);

        let mut expected_extensions = STATUS_REQUEST_V2_ACK.to_vec();
        expected_extensions.extend_from_slice(&extension(EXT_EXTENDED_MASTER_SECRET, &[]));
        expected_extensions.extend_from_slice(&extension(EXT_RENEGOTIATION_INFO, &[0xDE, 0xAD]));
        let mut expected_hello = vec![0x03, 0x03];
        expected_hello.extend_from_slice(&[0xB2; 32]);
        expected_hello.extend_from_slice(&[0x00, 0xC0, 0x2B, 0x00]);
        expected_hello.extend_from_slice(&(expected_extensions.len() as u16).to_be_bytes());
        expected_hello.extend_from_slice(&expected_extensions);
        assert_eq!(flight.messages[0].body, expected_hello);

        let mut expected_certificates = vec![0x00, 0x00, 0x14];
        expected_certificates.extend_from_slice(&[0x00, 0x00, 0x04]);
        expected_certificates.extend_from_slice(&cert_a);
        expected_certificates.extend_from_slice(&[0x00, 0x00, 0x05]);
        expected_certificates.extend_from_slice(&cert_b);
        expected_certificates.extend_from_slice(&[0x00, 0x00, 0x02]);
        expected_certificates.extend_from_slice(&cert_c);
        assert_eq!(flight.messages[1].body, expected_certificates);

        // 3 + 2 = 5 bytes of response data, plus 3 bytes per slot = 14.
        let expected_status = [
            0x02, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x02, 0x04,
            0x05, 0x00, 0x00, 0x00,
        ];
        assert_eq!(flight.messages[2].body, expected_status);

        let params = expected_params(&ecdhe);
        assert_eq!(params[0..4], [0x03, 0x00, 0x17, 0x41]);
        let ske = &flight.messages[3].body;
        assert!(ske.starts_with(&params));
        assert_eq!(ske[params.len()..params.len() + 2], [0x04, 0x03]);
        let sig_len = u16::from_be_bytes([ske[params.len() + 2], ske[params.len() + 3]]) as usize;
        let signature = &ske[params.len() + 4..];
        assert_eq!(signature.len(), sig_len);
        assert!(ske.len() == params.len() + 4 + sig_len);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&CLIENT_RANDOM);
        preimage.extend_from_slice(&[0xB2; 32]);
        preimage.extend_from_slice(&params);
        let der = p256::ecdsa::DerSignature::from_bytes(signature).expect("DER signature");
        signing
            .verifying_key()
            .verify_prehash(&Sha256::digest(preimage), &der)
            .expect("signature over exact preimage");
        assert_eq!(flight.messages[4].body, Vec::<u8>::new());
    }

    #[test]
    fn no_usable_v2_request_omits_status_and_ack_but_keeps_echoes() {
        let (ecdhe, signing) = keys();
        let mut extensions = extension(STATUS_REQUEST_V2, V2_OCSP_DATA);
        extensions.extend_from_slice(&extension(STATUS_REQUEST, V2_MULTI_DATA));
        extensions.extend_from_slice(&extension(EXT_EXTENDED_MASTER_SECRET, &[]));
        extensions.extend_from_slice(&extension(EXT_RENEGOTIATION_INFO, &[0xDE, 0xAD]));
        let message = client_message(&extensions);
        let cert = [0x30, 0x00];
        let staple = [0x01];
        let certificates: &[&[u8]] = &[&cert];
        let responses: &[OcspResponse<'_>] = &[OcspResponse::Der(&staple)];
        let flight =
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .expect("build first flight");

        assert!(!flight.selected_ocsp_multi);
        let types: Vec<u8> = flight.messages.iter().map(|m| m.msg_type).collect();
        assert_eq!(types, [2, 11, 12, 14]);
        let mut expected_extensions = extension(EXT_EXTENDED_MASTER_SECRET, &[]);
        expected_extensions.extend_from_slice(&extension(EXT_RENEGOTIATION_INFO, &[0xDE, 0xAD]));
        assert!(flight.messages[0].body.ends_with(&expected_extensions));
        let ext_len = u16::from_be_bytes([
            flight.messages[0].body[flight.messages[0].body.len() - 2 - expected_extensions.len()],
            flight.messages[0].body[flight.messages[0].body.len() - 1 - expected_extensions.len()],
        ]) as usize;
        assert_eq!(ext_len, expected_extensions.len());
        assert!(
            !flight.messages[0]
                .body
                .windows(4)
                .any(|w| w == STATUS_REQUEST_V2_ACK)
        );
    }

    #[test]
    fn unsupported_and_malformed_client_profiles_are_rejected() {
        let (ecdhe, signing) = keys();
        let cert = [0x30, 0x00];
        let certificates: &[&[u8]] = &[&cert];
        let responses: &[OcspResponse<'_>] = &[];
        let check = |extensions: &[u8]| {
            let message = client_message(extensions);
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err()
        };

        let mut tls13_suite = Vec::new();
        tls13_suite.extend_from_slice(&extension(STATUS_REQUEST_V2, V2_MULTI_DATA));
        // Replace the fixed suite with 0x1301 by building a custom message.
        let mut message = client_message(&tls13_suite);
        let suite_offset = 4 + 2 + 32 + 1 + 2;
        message[suite_offset..suite_offset + 2].copy_from_slice(&0x1301u16.to_be_bytes());
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedCipherSuite)
        );

        message = client_message(&extension(EXT_SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1D]));
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedNamedCurve)
        );
        message = client_message(&extension(EXT_EC_POINT_FORMATS, &[0x01, 0x01]));
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedPointFormat)
        );
        message = client_message(&extension(
            EXT_SIGNATURE_ALGORITHMS,
            &[0x00, 0x02, 0x04, 0x01],
        ));
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedSignatureScheme)
        );
        message = client_message(&[]);
        message[0] = 2;
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::InvalidClientHelloMessage)
        );
        message = client_message(&[]);
        message[3] += 1;
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::InvalidClientHelloMessage)
        );
        assert_eq!(
            build_server_first_flight(&input(
                &message[..3],
                &ecdhe,
                &signing,
                certificates,
                responses
            ))
            .err(),
            Some(Tls12Error::InvalidClientHelloMessage)
        );
        message = client_message(&[]);
        message[4..6].copy_from_slice(&[0x03, 0x02]);
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedVersion)
        );

        let duplicate = [
            extension(EXT_EXTENDED_MASTER_SECRET, &[]),
            extension(EXT_EXTENDED_MASTER_SECRET, &[]),
        ]
        .concat();
        assert_eq!(check(&duplicate), Some(Tls12Error::DuplicateExtension));
        message = client_message(&[]);
        message[4 + 2 + 32 + 1 + 2 + 2 + 1] = 1;
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::UnsupportedCompressionMethod)
        );
        assert_eq!(
            check(&extension(EXT_SUPPORTED_GROUPS, &[0x00, 0x01, 0x17])),
            Some(Tls12Error::InvalidSupportedGroups)
        );
        assert_eq!(
            check(&extension(EXT_EC_POINT_FORMATS, &[0x03, 0x00, 0x01])),
            Some(Tls12Error::InvalidEcPointFormats)
        );
        assert_eq!(
            check(&extension(EXT_SIGNATURE_ALGORITHMS, &[0x00, 0x01, 0x04])),
            Some(Tls12Error::InvalidSignatureAlgorithms)
        );
    }

    #[test]
    fn transcript_hashes_the_exact_client_message_and_emitted_messages() {
        let (ecdhe, signing) = keys();
        let message = client_message(&full_profile_extensions());
        let cert = [0x30, 0x01, 0x00];
        let staple = [0xAA];
        let certificates: &[&[u8]] = &[&cert];
        let responses: &[OcspResponse<'_>] = &[OcspResponse::Der(&staple)];
        let mut first = input(&message, &ecdhe, &signing, certificates, responses);
        let flight = build_server_first_flight(&first).expect("build first flight");
        let repeated =
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .expect("build again");
        assert_eq!(flight.transcript_sha256, repeated.transcript_sha256);

        first.server_random[0] ^= 1;
        let changed = build_server_first_flight(&first).expect("build with changed random");
        assert_ne!(flight.transcript_sha256, changed.transcript_sha256);

        let mut joined = message.clone();
        for emitted in &flight.messages {
            joined.extend_from_slice(&framed(emitted));
        }
        assert_eq!(
            flight.transcript_sha256.as_slice(),
            Sha256::digest(joined).as_slice()
        );
    }

    #[test]
    fn response_count_is_checked_by_the_existing_status_encoder() {
        let (ecdhe, signing) = keys();
        let message = client_message(&v2_request());
        let cert_a = [0x30, 0x00];
        let staple_a = [0x01];
        let staple_b = [0x02];
        let certificates: &[&[u8]] = &[&cert_a];
        let responses: &[OcspResponse<'_>] =
            &[OcspResponse::Der(&staple_a), OcspResponse::Der(&staple_b)];
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, certificates, responses))
                .err(),
            Some(Tls12Error::TooManyResponses)
        );

        // An empty certificate list is encodable when no status is selected.
        let empty: &[&[u8]] = &[];
        let no_responses: &[OcspResponse<'_>] = &[];
        let flight = build_server_first_flight(&input(
            &client_message(&[]),
            &ecdhe,
            &signing,
            empty,
            no_responses,
        ))
        .expect("empty certificate list");
        assert_eq!(flight.messages[1].body, [0x00, 0x00, 0x00]);

        // With status selected, the existing encoder rejects empty responses.
        assert_eq!(
            build_server_first_flight(&input(&message, &ecdhe, &signing, empty, no_responses))
                .err(),
            Some(Tls12Error::InvalidCertificateStatus)
        );
    }
}
