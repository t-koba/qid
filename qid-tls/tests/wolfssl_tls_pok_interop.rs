// clippy.toml's allow-expect-in-tests covers cfg(test) modules, not standalone
// integration-test targets; this entire target is test code.
#![allow(clippy::expect_used)]
// The child is reaped on the success path; a panic leaves it to the guard's Drop.
#![allow(clippy::zombie_processes)]

//! Independent-implementation evidence for RFC 9973 certificate-plus-external-PSK:
//! wolfSSL's TLS 1.3 server completes a mutual RawPublicKey handshake against
//! qid-tls's in-memory `TlsPokClient`. Its CI build adapts the peer's binder
//! label to RFC 9258's `"imp binder"` and passes the peer the imported PSK qid
//! derives from the raw EPSK and ImportedIdentity, so this checks binder and
//! transcript handling with a shared key against an independent TLS stack. PSK
//! import itself is covered by the RFC vector tests.
//!
//! This test is ignored by default because CI builds the wolfSSL peer first.
//! A local `cargo test` still compiles the target.

use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{SecretKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use qid_tls::tls13::client::ClientHandshakeParams;
use qid_tls::tls13::external_psk::{ImportedIdentity, import_external_psk};
use qid_tls::tls13::record_client::{RecordStage, TlsPokClient};
use qid_tls::tls13::tls_pok::{CONTEXT, epskid};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const CIPHER_SUITE: u16 = 0x1301;
const SESSION_ID: &[u8] = b"qid-wolfssl-interop";
const EPSK: &[u8] = &[0xA6; 32];
const ECDHE_SECRET: [u8; 32] = [0x33; 32];
const CLIENT_RANDOM: [u8; 32] = [0x5A; 32];
const TLS_RECORD_HEADER_LEN: usize = 5;
const EARLY_DATA_EXTENSION: u16 = 0x002A;
const MAX_ROUNDS: usize = 64;

/// Removes only the generated DER inputs; the child is reaped separately.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn certificates() -> (
    rcgen::Certificate,
    rcgen::KeyPair,
    rcgen::Certificate,
    rcgen::KeyPair,
) {
    let make = |name: &str| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate P-256 test key");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("build test certificate parameters");
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, name);
        params.distinguished_name = distinguished_name;
        let cert = params
            .self_signed(&key)
            .expect("self-sign test certificate");
        (cert, key)
    };
    let (server_cert, server_key) = make("qid wolfSSL TLS-POK test server");
    let (client_cert, client_key) = make("qid wolfSSL TLS-POK test client");
    (server_cert, server_key, client_cert, client_key)
}

/// Verify that the client does not offer early data: RFC 9973 forbids it with
/// certificate-plus-external-PSK. The extension list is parsed from the fixed
/// ClientHello layout so arbitrary key bytes cannot produce a false positive.
fn assert_no_early_data_extension(hello_record: &[u8]) {
    assert_eq!(hello_record[0], 0x16, "ClientHello is a handshake record");
    let message = &hello_record[TLS_RECORD_HEADER_LEN..];
    assert_eq!(message[0], 0x01, "ClientHello handshake type");
    let body_len =
        usize::from(message[1]) << 16 | usize::from(message[2]) << 8 | usize::from(message[3]);
    assert_eq!(body_len + 4, message.len(), "ClientHello handshake length");

    let mut offset = 4 + 2 + 32;
    let session_len = usize::from(message[offset]);
    offset += 1 + session_len;
    let suites_len = usize::from(u16::from_be_bytes([message[offset], message[offset + 1]]));
    offset += 2 + suites_len;
    let compression_len = usize::from(message[offset]);
    offset += 1 + compression_len;
    let extensions_len = usize::from(u16::from_be_bytes([message[offset], message[offset + 1]]));
    offset += 2;
    let extensions = &message[offset..offset + extensions_len];
    assert_eq!(extensions.len(), extensions_len, "ClientHello extensions");

    let mut at = 0;
    while at + 4 <= extensions.len() {
        let kind = u16::from_be_bytes([extensions[at], extensions[at + 1]]);
        let length = usize::from(u16::from_be_bytes([extensions[at + 2], extensions[at + 3]]));
        assert_ne!(kind, EARLY_DATA_EXTENSION, "early_data must not be offered");
        at += 4 + length;
        assert!(at <= extensions.len(), "ClientHello extension length");
    }
    assert_eq!(at, extensions.len(), "ClientHello extensions are exact");
}

fn send_record(stdin: &mut ChildStdin, record: &[u8]) {
    writeln!(stdin, "F {}", hex::encode(record)).expect("send record to wolfSSL helper");
    stdin.flush().expect("flush record to wolfSSL helper");
}

#[test]
#[ignore = "requires the wolfSSL helper built by ci/wolfssl-tls-pok/build.sh"]
fn wolfssl_server_completes_tls_pok_handshake() {
    let helper = std::env::var_os("QID_WOLFSSL_SERVER_BIN")
        .expect("QID_WOLFSSL_SERVER_BIN must point at the built wolfSSL helper");
    if let Some(window) = std::env::var("QID_WOLFSSL_SOURCE_WINDOW")
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
    {
        eprintln!("wolfSSL parser source window:\n{window}");
    }

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_nanos();
    let temp =
        TempDir(std::env::temp_dir().join(format!("qid-tls-pok-{}-{unique}", std::process::id())));
    fs::create_dir(&temp.0).expect("create temporary test directory");

    let (server_cert, server_key, client_cert, client_key) = certificates();
    let cert_path = temp.0.join("server.der");
    let key_path = temp.0.join("server.key.der");
    fs::write(&cert_path, server_cert.der()).expect("write server certificate DER");
    fs::write(&key_path, server_key.serialize_der()).expect("write server key DER");

    let server_spki = server_key.public_key_der();
    let client_spki = client_key.public_key_der();
    let client_epskid = epskid(&client_spki).expect("derive client EPSK identity");
    let identity = ImportedIdentity::new(client_epskid.to_vec(), CONTEXT.to_vec())
        .expect("build RFC 9258 imported identity");
    let imported_psk = import_external_psk(EPSK, &identity).expect("import fixed EPSK");

    let client_secret = SecretKey::from_pkcs8_der(&client_key.serialize_der())
        .expect("parse client P-256 signing key");
    let signing_key = SigningKey::from(client_secret);
    let ecdhe_secret = SecretKey::from_slice(&ECDHE_SECRET).expect("fixed nonzero ECDHE scalar");
    let key_share = ecdhe_secret
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();

    let mut client = TlsPokClient::new(
        ClientHandshakeParams {
            random: CLIENT_RANDOM,
            legacy_session_id: SESSION_ID,
            cipher_suite: CIPHER_SUITE,
            ecdhe_secret: &ECDHE_SECRET,
            key_share: &key_share,
            client_spki: &client_spki,
            imported_identity: &identity,
            imported_psk: &imported_psk,
        },
        &server_spki,
    )
    .expect("create TLS-POK client");
    let hello = client.client_hello_record().expect("frame ClientHello");
    assert_no_early_data_extension(&hello);
    // Public wire bytes: on an interop failure these let the CI log be
    // compared byte-for-byte with the peer's binder transcript input.
    eprintln!("qid TLS-POK ClientHello record: {}", hex::encode(&hello));

    let mut guard = ChildGuard(Some(
        Command::new(helper)
            .arg(&cert_path)
            .arg(&key_path)
            // The peer uses the supplied bytes directly as its TLS 1.3 PSK,
            // so it receives the RFC 9258 imported PSK derived above. This
            // checks qid's binder and transcript against an independent stack.
            .arg(hex::encode(&imported_psk))
            .arg(hex::encode(&client_spki))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn wolfSSL helper"),
    ));
    let child = guard.0.as_mut().expect("child is running");
    let mut stdin = child.stdin.take().expect("helper stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("helper stdout"));
    send_record(&mut stdin, &hello);

    let mut buffered = Vec::<u8>::new();
    let mut line = String::new();
    let mut result = None;
    for _ in 0..MAX_ROUNDS {
        line.clear();
        let read = stdout.read_line(&mut line).expect("read helper line");
        assert!(read > 0, "wolfSSL helper closed stdout before OK");
        let line = line.trim();
        if let Some(payload) = line.strip_prefix("S ") {
            let bytes = hex::decode(payload).expect("decode helper S line");
            buffered.extend_from_slice(&bytes);
            while buffered.len() >= TLS_RECORD_HEADER_LEN {
                let length = usize::from(u16::from_be_bytes([
                    buffered[TLS_RECORD_HEADER_LEN - 2],
                    buffered[TLS_RECORD_HEADER_LEN - 1],
                ]));
                let end = TLS_RECORD_HEADER_LEN + length;
                if buffered.len() < end {
                    break;
                }
                let mut record: Vec<u8> = buffered.drain(..end).collect();
                if client.stage() == RecordStage::Complete {
                    // The minimal driver intentionally stops at handshake
                    // completion. wolfSSL may send post-handshake session
                    // tickets in the same drain; they are outside its scope.
                    continue;
                }
                client.receive_record(&mut record).unwrap_or_else(|error| {
                    panic!(
                        "client accepts wolfSSL server record {}: {error}",
                        hex::encode(&record)
                    )
                });
                if client.stage() == RecordStage::AwaitClientSignature {
                    let content = client
                        .pending_client_signature_content()
                        .expect("frame client raw public key certificate");
                    let signature: p256::ecdsa::Signature = signing_key.sign(&content);
                    let flight = client
                        .complete_client_flight(signature.to_der().as_bytes())
                        .expect("complete client flight");
                    for record in flight {
                        send_record(&mut stdin, &record);
                    }
                }
            }
            continue;
        }
        if let Some(outcome) = line.strip_prefix("OK ") {
            result = Some(
                outcome
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
            break;
        }
        if let Some(error) = line.strip_prefix("ERR ") {
            panic!("wolfSSL helper failed: {error}");
        }
        panic!("unexpected wolfSSL helper line");
    }

    drop(stdin);
    let mut child = guard.0.take().expect("child is running");
    let status = child.wait().expect("reap wolfSSL helper");
    assert!(status.success(), "wolfSSL helper exited with {status}");

    let fields = result.expect("wolfSSL helper reported OK");
    assert_eq!(fields.len(), 3, "OK cipher and certificate types");
    assert!(
        matches!(
            fields[0].as_str(),
            "TLS_AES_128_GCM_SHA256" | "TLS13-AES128-GCM-SHA256"
        ),
        "negotiated cipher is TLS 1.3 AES-128-GCM"
    );
    assert_eq!(fields[1], "2", "client certificate type is RawPublicKey");
    assert_eq!(fields[2], "2", "server certificate type is RawPublicKey");
    assert_eq!(client.stage(), RecordStage::Complete);
    assert_ne!(
        client_cert.der(),
        server_cert.der(),
        "independent test certificates"
    );
}
