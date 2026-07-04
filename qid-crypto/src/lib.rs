//! Cryptographic primitives for qid.
#![forbid(unsafe_code)]

pub mod aead;
pub mod cose;
pub mod ech;
pub mod hotp;
#[cfg(feature = "hpke-rfc9180")]
pub mod hpke;
pub mod jwe;
pub mod jwk;
pub mod jwt;
pub mod kdf;
pub mod keyring;
pub mod password;
pub mod pkcs11;
pub mod pki;
pub mod pqc;
pub mod totp;
pub mod tpm;
pub mod x25519;

#[cfg(feature = "acme")]
pub mod acme;

pub use aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
pub use jwk::{Jwk, JwkSet};
pub use jwt::{LocalSigner, RemoteJwtSigner, TokenPair, remote_sign_jwt};
pub use kdf::hkdf_sha256;
pub use keyring::{HttpRemoteSignerTransport, Keyring};
pub use password::{
    ARGON2ID_ALGORITHM, BCRYPT_ALGORITHM, BreachedPasswordSet, DenyPepperResolver,
    ImportedPasswordRecord, LDAP_BIND_ALGORITHM, PBKDF2_SHA256_ALGORITHM,
    PasswordImportMigrationPlan, PasswordPepperResolver, PasswordVerification, SCRYPT_ALGORITHM,
    encode_pbkdf2_sha256_hash, hash_password, hash_password_with_pepper,
    plan_password_import_migration, verify_password, verify_password_credential,
};
pub use qid_core::jwt::{JwtClaims, Signer, TokenData};
pub use totp::TotpVerifier;
