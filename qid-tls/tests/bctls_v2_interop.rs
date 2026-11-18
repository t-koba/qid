// clippy.toml's allow-expect-in-tests covers cfg(test) modules, not standalone
// integration-test targets; this entire target is test code.
#![allow(clippy::expect_used)]
// Panic paths intentionally leave the child to the OS; success and ERR paths wait.
#![allow(clippy::zombie_processes)]

//! Independent-implementation evidence for RFC 6961 multi-response stapling:
//! Bouncy Castle's low-level TLS 1.2 client offers `status_request_v2`, and
//! qid-tls's in-memory server returns two distinct staples.
//!
//! This test is ignored by default because it needs Java and pinned BC jars.
//! CI sets `QID_BCTLS_JARS` and `QID_BCTLS_CLASSES` and runs it explicitly.
//! A local `cargo test` still compiles the target.

use p256::{SecretKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use qid_tls::tls12::{OcspResponse, ServerHandshake, ServerHandshakeConfig, ServerHandshakeState};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

// Valid DER OCSPResponse values with distinct responseStatus codes. BC parses
// them without validating status at handshake time.
const STAPLE_A: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x00];
const STAPLE_B: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x03];

fn certificates() -> (rcgen::Certificate, rcgen::Certificate, rcgen::KeyPair) {
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate runtime test CA key");
    let mut ca_params = rcgen::CertificateParams::default();
    let mut ca_name = rcgen::DistinguishedName::new();
    ca_name.push(rcgen::DnType::CommonName, "qid BC v2 interop test CA");
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

#[test]
#[ignore = "requires the pinned Bouncy Castle jars and Java in CI"]
fn bouncy_castle_v2_client_receives_two_distinct_staples() {
    let jars = std::env::var_os("QID_BCTLS_JARS")
        .expect("QID_BCTLS_JARS must be set when running the ignored Bouncy Castle interop test");
    let classes = std::env::var_os("QID_BCTLS_CLASSES")
        .expect("QID_BCTLS_CLASSES must point at compiled V2Client classes");
    let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
    let classpath = format!("{}:{}", jars.to_string_lossy(), classes.to_string_lossy());

    let (ca, leaf, leaf_key) = certificates();
    let signing_key = SigningKey::from_pkcs8_der(&leaf_key.serialize_der())
        .expect("parse leaf PKCS8 as P-256 signing key");
    let ecdhe_secret = SecretKey::from_slice(&[0x11; 32]).expect("fixed nonzero ECDHE scalar");
    let certificates: &[&[u8]] = &[leaf.der(), ca.der()];
    let responses: &[OcspResponse<'_>] =
        &[OcspResponse::Der(STAPLE_A), OcspResponse::Der(STAPLE_B)];
    let mut server = ServerHandshake::new(ServerHandshakeConfig {
        certificates,
        ocsp_responses: responses,
        signing_key: &signing_key,
        ecdhe_secret: &ecdhe_secret,
        server_random: [0xB2; 32],
    });

    let mut child = Command::new(java)
        .arg("-cp")
        .arg(&classpath)
        .arg("V2Client")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn Bouncy Castle client");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));

    let mut line = String::new();
    for round in 0..64 {
        line.clear();
        let read = stdout
            .read_line(&mut line)
            .expect("read Bouncy Castle client line");
        assert!(
            read > 0,
            "Bouncy Castle client closed stdout at round {round}"
        );
        let line = line.trim();
        if let Some(client_hex) = line.strip_prefix("C ") {
            let client_bytes = hex::decode(client_hex).expect("decode client hex record");
            let server_bytes = server
                .push(&client_bytes)
                .expect("server accepts client records");
            if !server_bytes.is_empty() {
                writeln!(stdin, "S {}", hex::encode(&server_bytes)).expect("write server record");
                stdin.flush().expect("flush server record");
            }
            continue;
        }
        if let Some(result) = line.strip_prefix("DONE ") {
            let mut fields = result.split_whitespace();
            let status_type: u8 = fields
                .next()
                .expect("status type")
                .parse()
                .expect("numeric status type");
            let count: usize = fields
                .next()
                .expect("response count")
                .parse()
                .expect("numeric response count");
            let first = fields.next().expect("first staple");
            let second = fields.next().expect("second staple");
            assert_eq!(fields.next(), None, "unexpected extra DONE fields");
            assert_eq!(status_type, 2, "RFC 6961 ocsp_multi status type");
            assert_eq!(count, 2, "BC must report two staples");
            assert_eq!(hex::decode(first).expect("first staple hex"), STAPLE_A);
            assert_eq!(hex::decode(second).expect("second staple hex"), STAPLE_B);
            assert_ne!(STAPLE_A, STAPLE_B);
            assert_eq!(server.state(), &ServerHandshakeState::Complete);
            assert!(server.selected_ocsp_multi());
            drop(stdin);
            let status = child.wait().expect("wait for Bouncy Castle client");
            assert!(
                status.success(),
                "Bouncy Castle client exited with {status}"
            );
            return;
        }
        if let Some(error) = line.strip_prefix("ERR ") {
            drop(stdin);
            let _ = child.wait();
            panic!("Bouncy Castle client failed: {error}");
        }
        panic!("unexpected Bouncy Castle client line: {line}");
    }
    drop(stdin);
    let _ = child.kill();
    panic!("Bouncy Castle handshake did not complete in 64 rounds");
}
