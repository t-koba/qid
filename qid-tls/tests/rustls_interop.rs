// clippy.toml's allow-expect-in-tests covers cfg(test) modules, not standalone
// integration-test targets; this entire target is test code.
#![allow(clippy::expect_used)]

//! Independent-implementation evidence: upstream rustls produces a TLS 1.3
//! protected record that qid-tls's read epoch can authenticate and decrypt.

use qid_tls::tls13::ReadEpoch;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

const CLIENT_HANDSHAKE_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";

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

/// Captures rustls key-log secrets in memory; nothing is written to disk.
#[derive(Debug, Default)]
struct RecordingKeyLog {
    secrets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl rustls::KeyLog for RecordingKeyLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.secrets
            .lock()
            .expect("key log mutex must not be poisoned")
            .insert(label.to_owned(), secret.to_vec());
    }
}

fn certificates() -> (rcgen::Certificate, rcgen::Certificate, rcgen::KeyPair) {
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate runtime test CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    let mut ca_name = rcgen::DistinguishedName::new();
    ca_name.push(rcgen::DnType::CommonName, "qid rustls interop test CA");
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

/// Pumps both directions until the handshake completes and returns the exact
/// client-to-server byte stream, including plaintext handshake and CCS records.
fn drive_handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Vec<u8> {
    let mut client_to_server = BytePipe::default();
    let mut server_to_client = BytePipe::default();
    let mut client_bytes = Vec::new();

    for _ in 0..32 {
        let mut wire = Vec::new();
        client
            .write_tls(&mut wire)
            .expect("write client handshake records");
        if !wire.is_empty() {
            client_bytes.extend_from_slice(&wire);
            client_to_server
                .write_all(&wire)
                .expect("buffer client handshake records");
            server
                .read_tls(&mut client_to_server)
                .expect("server reads client records");
            server
                .process_new_packets()
                .expect("server processes client handshake");
        }

        wire.clear();
        server
            .write_tls(&mut wire)
            .expect("write server handshake records");
        if !wire.is_empty() {
            server_to_client
                .write_all(&wire)
                .expect("buffer server handshake records");
            client
                .read_tls(&mut server_to_client)
                .expect("client reads server records");
            client
                .process_new_packets()
                .expect("client processes server handshake");
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return client_bytes;
        }
    }
    panic!("TLS 1.3 handshake did not complete in 32 pump rounds");
}

/// The first outer APPLICATION_DATA from an unauthenticated TLS 1.3 client is
/// its Finished handshake message, encrypted under the client handshake secret.
fn first_application_data(stream: &[u8]) -> Vec<u8> {
    let mut offset = 0;
    while offset + 5 <= stream.len() {
        let header = &stream[offset..offset + 5];
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = offset + 5 + length;
        assert!(
            end <= stream.len(),
            "TLS record at offset {offset} declares {length} bytes but only {} remain",
            stream.len() - offset - 5
        );
        if header[0] == 0x17 {
            return stream[offset..end].to_vec();
        }
        assert!(
            matches!(header[0], 0x16 | 0x14),
            "expected plaintext handshake or CCS record before the first APPLICATION_DATA, got 0x{:02x} at offset {offset}",
            header[0]
        );
        offset = end;
    }
    panic!("client-to-server stream contained no APPLICATION_DATA record");
}

#[test]
fn opens_upstream_rustls_client_finished_record() {
    let (ca, leaf, leaf_key) = certificates();

    // ReadEpoch implements only TLS_AES_128_GCM_SHA256, so pin both the version
    // and the suite rather than relying on rustls's default negotiation.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca.der().clone())
        .expect("add runtime test CA to rustls root store");
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("configure TLS 1.3 only")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key_log = Arc::new(RecordingKeyLog::default());
    client_config.key_log = key_log.clone();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("build rustls server config with runtime leaf certificate");

    let server_name = ServerName::try_from("localhost")
        .expect("build localhost server name")
        .to_owned();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), server_name)
        .expect("create rustls client connection");
    let mut server = rustls::ServerConnection::new(Arc::new(server_config))
        .expect("create rustls server connection");
    let client_bytes = drive_handshake(&mut client, &mut server);

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "rustls must negotiate TLS 1.3 for this interop claim"
    );

    let mut record = first_application_data(&client_bytes);
    let secrets = key_log
        .secrets
        .lock()
        .expect("key log mutex must not be poisoned");
    let logged = secrets
        .get(CLIENT_HANDSHAKE_SECRET)
        .unwrap_or_else(|| panic!("rustls did not log {CLIENT_HANDSHAKE_SECRET}"));
    assert_eq!(
        logged.len(),
        32,
        "AES-128-GCM handshake secret must be 32 bytes"
    );
    let mut traffic_secret = [0u8; 32];
    traffic_secret.copy_from_slice(logged);
    drop(secrets);

    let mut epoch = ReadEpoch::aes_128_gcm_sha256(&traffic_secret)
        .expect("derive read epoch from rustls handshake secret");
    let inner = epoch
        .open(&mut record)
        .expect("qid-tls must decrypt the upstream rustls Finished record");
    assert_eq!(
        inner.content_type, 0x16,
        "inner content must be a handshake record"
    );
    assert_eq!(inner.content.len(), 36, "Finished message must be 36 bytes");
    assert_eq!(
        inner.content[0], 0x14,
        "inner handshake type must be Finished"
    );
}
