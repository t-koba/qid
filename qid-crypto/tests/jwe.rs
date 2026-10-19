#![allow(clippy::expect_used, clippy::unwrap_used)]

use qid_crypto::jwe::{decrypt_jwe, encrypt_jwe};
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey};
use std::sync::OnceLock;

fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
    let public_key = private_key.to_public_key();
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to encode private key")
        .to_string()
        .into_bytes();
    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to encode public key")
        .to_string()
        .into_bytes();
    (private_pem, public_pem)
}

// Reuse the valid 2048-bit fixture; RSA key generation dominates these JWE tests.
fn shared_rsa_keypair() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYPAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYPAIR.get_or_init(generate_rsa_keypair)
}

#[test]
fn jwe_roundtrip() {
    let (private_pem, public_pem) = shared_rsa_keypair();
    let plaintext = b"hello jwe world";
    let jwe = encrypt_jwe(plaintext, public_pem, "RSA-OAEP-256", "A256GCM").unwrap();
    let decrypted = decrypt_jwe(&jwe, private_pem).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn jwe_wrong_key_rejected() {
    let (_, public_pem) = shared_rsa_keypair();
    let (wrong_private_pem, _) = generate_rsa_keypair();
    let plaintext = b"secret data";
    let jwe = encrypt_jwe(plaintext, public_pem, "RSA-OAEP-256", "A256GCM").unwrap();
    let result = decrypt_jwe(&jwe, &wrong_private_pem);
    assert!(result.is_err());
}
