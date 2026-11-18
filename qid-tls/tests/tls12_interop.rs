// clippy.toml's allow-expect-in-tests covers cfg(test) modules, not standalone
// integration-test targets; this entire target is test code.
#![allow(clippy::expect_used)]

//! Independent-implementation evidence for the core TLS 1.2 handshake only:
//! upstream rustls (aws-lc-rs) completes a full handshake against qid-tls's
//! in-memory server driver over byte pipes.
//!
//! This does NOT prove RFC 6961 interop: rustls does not offer
//! status_request_v2, so no CertificateStatus is negotiated or asserted here.

use p256::{SecretKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use qid_tls::tls12::{ServerHandshake, ServerHandshakeConfig, ServerHandshakeState};
use rustls_pki_types::ServerName;
use std::io::{self, Read, Write};
use std::sync::Arc;

/// In-memory, directional byte pipe: writes append, reads consume from a cursor.
#[derive(Debug, Default)]
struct BytePipe {
    bytes: Vec<u8>,
    read_at: usize,
}

impl Read for BytePipe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.bytes.len() - self.read_at);
        output[..count].copy_from_slice(&self.bytes[self.read_at..self.read_at + count]);
        self.read_at += count;
        Ok(count)
    }
}

impl Write for BytePipe {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn certificates() -> (rcgen::Certificate, rcgen::Certificate, rcgen::KeyPair) {
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate runtime test CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    let mut ca_name = rcgen::DistinguishedName::new();
    ca_name.push(rcgen::DnType::CommonName, "qid TLS 1.2 interop test CA");
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("generate runtime test CA");

    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate runtime server key");
    let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("build server parameters");
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("sign localhost server certificate");

    (ca, leaf, leaf_key)
}

fn rustls_client(ca: &rcgen::Certificate) -> rustls::ClientConnection {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca.der().clone())
        .expect("add runtime test CA to rustls root store");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("pin client to TLS 1.2")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from("localhost")
        .expect("build localhost server name")
        .to_owned();
    rustls::ClientConnection::new(Arc::new(config), name).expect("create rustls client connection")
}

/// Pump client bytes into the pure driver and driver bytes back into rustls
/// over in-memory pipes only. No socket, listener or rustls default is changed.
fn drive_handshake(client: &mut rustls::ClientConnection, server: &mut ServerHandshake<'_>) {
    let mut server_to_client = BytePipe::default();
    for round in 1..=32 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).expect("write client records");
        if !wire.is_empty() {
            let response = server.push(&wire).expect("driver accepts client records");
            server_to_client
                .write_all(&response)
                .expect("buffer server records");
        }
        client
            .read_tls(&mut server_to_client)
            .expect("client reads server records");
        client
            .process_new_packets()
            .expect("client processes server records");
        if !client.is_handshaking() {
            return;
        }
        assert!(
            round < 32,
            "TLS 1.2 handshake did not complete in 32 rounds"
        );
    }
    unreachable!("handshake loop always returns or panics");
}

#[test]
fn rustls_tls12_client_completes_handshake_against_in_memory_driver() {
    let (ca, leaf, leaf_key) = certificates();
    let mut client = rustls_client(&ca);

    let signing_key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der())
        .expect("parse leaf PKCS8 as P-256 signing key");
    let ecdhe_secret = SecretKey::from_slice(&[0x11; 32]).expect("fixed nonzero ECDHE scalar");
    let certificates: &[&[u8]] = &[leaf.der()];
    let mut server = ServerHandshake::new(ServerHandshakeConfig {
        certificates,
        ocsp_responses: &[],
        signing_key: &signing_key,
        ecdhe_secret: &ecdhe_secret,
        server_random: [0xB2; 32],
    });

    drive_handshake(&mut client, &mut server);

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2),
        "interop claim requires negotiated TLS 1.2"
    );
    assert_eq!(
        client
            .negotiated_cipher_suite()
            .expect("client negotiated a suite")
            .suite(),
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.suite(),
        "interop claim requires the 0xC02B cipher suite"
    );
    assert_eq!(server.state(), &ServerHandshakeState::Complete);
    assert!(
        server.key_block().is_some(),
        "completed handshake must expose derived keys"
    );
    // No RFC 6961 assertion: rustls does not offer status_request_v2.
    // Application data is not part of this driver: after Complete it ignores
    // further records, so this test stops at the handshake boundary.
}
