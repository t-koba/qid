//! PKCS#11 (Cryptoki) integration via trait.
//! Actual PKCS#11 interop requires linking against a PKCS#11 library
//! (e.g., `pkcs11` crate for OpenSC/SoftHSM). This module provides the
//! trait and a software-based development implementation.

use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pkcs11Slot {
    pub slot_id: u64,
    pub label: String,
    pub manufacturer_id: String,
    pub token_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pkcs11Key {
    pub key_handle: u64,
    pub key_type: String,
    pub key_label: Option<String>,
    pub id: Vec<u8>,
}

pub trait Pkcs11Backend: Send + Sync {
    fn initialize(&self, library_path: &str) -> QidResult<()>;
    fn find_slots(&self) -> QidResult<Vec<Pkcs11Slot>>;
    fn open_session(&self, slot_id: u64, pin: &str) -> QidResult<()>;
    fn generate_key(&self, key_type: &str) -> QidResult<Pkcs11Key>;
    fn sign(&self, key: &Pkcs11Key, data: &[u8]) -> QidResult<Vec<u8>>;
    fn close_session(&self) -> QidResult<()>;
    fn finalize(&self) -> QidResult<()>;
}

pub struct SoftwarePkcs11;

impl SoftwarePkcs11 {
    pub fn new() -> Self {
        Self
    }
    pub fn boxed() -> Box<dyn Pkcs11Backend> {
        Box::new(Self::new())
    }
}

impl Default for SoftwarePkcs11 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pkcs11Backend for SoftwarePkcs11 {
    fn initialize(&self, _library_path: &str) -> QidResult<()> {
        Ok(())
    }
    fn find_slots(&self) -> QidResult<Vec<Pkcs11Slot>> {
        Ok(vec![Pkcs11Slot {
            slot_id: 0,
            label: "SoftHSM".to_string(),
            manufacturer_id: "qid".to_string(),
            token_model: "Software".to_string(),
        }])
    }
    fn open_session(&self, _slot_id: u64, _pin: &str) -> QidResult<()> {
        Ok(())
    }
    fn generate_key(&self, key_type: &str) -> QidResult<Pkcs11Key> {
        Ok(Pkcs11Key {
            key_handle: 1,
            key_type: key_type.to_string(),
            key_label: Some("sw-key".to_string()),
            id: vec![0x01],
        })
    }
    fn sign(&self, _key: &Pkcs11Key, data: &[u8]) -> QidResult<Vec<u8>> {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        let sk = SigningKey::random(&mut rand::thread_rng());
        let signature: p256::ecdsa::Signature = sk.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
    fn close_session(&self) -> QidResult<()> {
        Ok(())
    }
    fn finalize(&self) -> QidResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_pkcs11_generates_key() {
        let pkcs11 = SoftwarePkcs11::new();
        pkcs11
            .initialize("/usr/lib/softhsm/libsofthsm2.so")
            .unwrap();
        let slots = pkcs11.find_slots().unwrap();
        assert!(!slots.is_empty());
        pkcs11.open_session(slots[0].slot_id, "1234").unwrap();
        let key = pkcs11.generate_key("EC").unwrap();
        assert_eq!(key.key_type, "EC");
        pkcs11.close_session().unwrap();
        pkcs11.finalize().unwrap();
    }

    #[test]
    fn software_pkcs11_signs_data() {
        let pkcs11 = SoftwarePkcs11::new();
        let key = pkcs11.generate_key("EC").unwrap();
        let signature = pkcs11.sign(&key, b"test data").unwrap();
        assert!(!signature.is_empty());
    }
}
