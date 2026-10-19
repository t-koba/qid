#![allow(clippy::expect_used, clippy::unwrap_used)]

use qid_crypto::jwe::{decrypt_jwe, encrypt_jwe};

// Static test-only 2048-bit keys avoid randomized RSA key generation in every run.
// The second private key is intentionally unrelated to the public key below.
const PRIVATE_KEY_PEM: &[u8] = include_bytes!("fixtures/jwe_rsa_private.pem");
const PUBLIC_KEY_PEM: &[u8] = include_bytes!("fixtures/jwe_rsa_public.pem");
const WRONG_PRIVATE_KEY_PEM: &[u8] = include_bytes!("fixtures/jwe_rsa_wrong_private.pem");

#[test]
fn jwe_roundtrip() {
    let plaintext = b"hello jwe world";
    let jwe = encrypt_jwe(plaintext, PUBLIC_KEY_PEM, "RSA-OAEP-256", "A256GCM").unwrap();
    let decrypted = decrypt_jwe(&jwe, PRIVATE_KEY_PEM).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn jwe_wrong_key_rejected() {
    let plaintext = b"secret data";
    let jwe = encrypt_jwe(plaintext, PUBLIC_KEY_PEM, "RSA-OAEP-256", "A256GCM").unwrap();
    let result = decrypt_jwe(&jwe, WRONG_PRIVATE_KEY_PEM);
    assert!(result.is_err());
}
