//! Post-Quantum Cryptography (FIPS 203/204/205).
//! Defines algorithm identifiers and key types for ML-KEM, ML-DSA, and SLH-DSA.
//! Actual implementations require dedicated crates (e.g. `ml-kem`, `ml-dsa`, `libcrux`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParameterSet {
    pub fn nist_security_level(&self) -> u32 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    SlhDsaSha2128s,
    SlhDsaSha2128f,
    SlhDsaSha2256s,
    SlhDsaSha2256f,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcPublicKey {
    pub algorithm: PqcAlgorithm,
    pub key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcSecretKey {
    pub algorithm: PqcAlgorithm,
    pub key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PqcAlgorithm {
    MlKem(MlKemParameterSet),
    MlDsa(MlDsaParameterSet),
    SlhDsa(SlhDsaParameterSet),
}

impl PqcAlgorithm {
    pub fn jose_alg(&self) -> Option<&'static str> {
        match self {
            Self::MlKem(_) => None,
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => Some("ML-DSA-44"),
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => Some("ML-DSA-65"),
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => Some("ML-DSA-87"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaSha2128s) => Some("SLH-DSA-SHA2-128s"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaSha2128f) => Some("SLH-DSA-SHA2-128f"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaSha2256s) => Some("SLH-DSA-SHA2-256s"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaSha2256f) => Some("SLH-DSA-SHA2-256f"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaShake128s) => Some("SLH-DSA-SHAKE-128s"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaShake128f) => Some("SLH-DSA-SHAKE-128f"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaShake256s) => Some("SLH-DSA-SHAKE-256s"),
            Self::SlhDsa(SlhDsaParameterSet::SlhDsaShake256f) => Some("SLH-DSA-SHAKE-256f"),
        }
    }
}

/// Real ML-KEM encapsulation (requires `pqc` feature).
#[cfg(feature = "pqc")]
pub mod pqc_impl {
    use qid_core::error::{QidError, QidResult};

    pub fn ml_kem_encapsulate(pk: &[u8]) -> QidResult<(Vec<u8>, Vec<u8>)> {
        let pk_arr: [u8; 1184] = pk.try_into().map_err(|_| QidError::BadRequest {
            message: "ML-KEM-768 public key must be 1184 bytes".to_string(),
        })?;
        let encapsulation_key =
            ml_kem::EncapsulationKey768::new(&pk_arr.into()).map_err(|_| QidError::Crypto {
                message: "ML-KEM-768 public key validation failed".to_string(),
            })?;
        let (ciphertext, shared_secret) = ml_kem::kem::Encapsulate::encapsulate(&encapsulation_key);
        Ok((
            ciphertext.as_slice().to_vec(),
            shared_secret.as_slice().to_vec(),
        ))
    }

    pub fn ml_kem_decapsulate(sk: &[u8], ct: &[u8]) -> QidResult<Vec<u8>> {
        let sk_arr: [u8; 2400] = sk.try_into().map_err(|_| QidError::BadRequest {
            message: "ML-KEM-768 secret key must be 2400 bytes".to_string(),
        })?;
        let ct_arr: [u8; 1088] = ct.try_into().map_err(|_| QidError::BadRequest {
            message: "ML-KEM-768 ciphertext must be 1088 bytes".to_string(),
        })?;
        #[allow(deprecated)]
        let sk_expanded: ml_kem::ml_kem_768::ExpandedDecapsulationKey = sk_arr.into();
        #[allow(deprecated)]
        let decapsulation_key =
            <ml_kem::DecapsulationKey768 as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(
                &sk_expanded,
            )
            .map_err(|_| QidError::Crypto {
                message: "ML-KEM-768 secret key validation failed".to_string(),
            })?;
        let shared_secret =
            ml_kem::kem::Decapsulate::decapsulate(&decapsulation_key, &ct_arr.into());
        Ok(shared_secret.as_slice().to_vec())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ml_kem_768_round_trip() {
            let (sk, pk) = <ml_kem::MlKem768 as ml_kem::kem::Kem>::generate_keypair();
            let pk = ml_kem::kem::KeyExport::to_bytes(&pk);
            #[allow(deprecated)]
            let sk =
                <ml_kem::DecapsulationKey768 as ml_kem::ExpandedKeyEncoding>::to_expanded_bytes(
                    &sk,
                );

            let (ct, ss1) = ml_kem_encapsulate(pk.as_slice()).unwrap();
            let ss2 = ml_kem_decapsulate(sk.as_slice(), &ct).unwrap();
            assert_eq!(ss1, ss2);
        }
    }
}

pub fn is_pqc_jose_alg(alg: &str) -> bool {
    matches!(
        alg,
        "ML-DSA-44"
            | "ML-DSA-65"
            | "ML-DSA-87"
            | "SLH-DSA-SHA2-128s"
            | "SLH-DSA-SHA2-128f"
            | "SLH-DSA-SHA2-256s"
            | "SLH-DSA-SHA2-256f"
            | "SLH-DSA-SHAKE-128s"
            | "SLH-DSA-SHAKE-128f"
            | "SLH-DSA-SHAKE-256s"
            | "SLH-DSA-SHAKE-256f"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_parameter_sizes() {
        assert_eq!(MlKemParameterSet::MlKem768.ciphertext_size(), 1088);
        assert_eq!(MlKemParameterSet::MlKem512.nist_security_level(), 1);
    }

    #[test]
    fn ml_dsa_jose_alg() {
        let alg = PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65);
        assert_eq!(alg.jose_alg(), Some("ML-DSA-65"));
    }

    #[test]
    fn is_pqc_jose_alg_matches() {
        assert!(is_pqc_jose_alg("ML-DSA-44"));
        assert!(!is_pqc_jose_alg("ES256"));
    }

    #[test]
    fn pqc_key_round_trip() {
        let key = PqcPublicKey {
            algorithm: PqcAlgorithm::MlKem(MlKemParameterSet::MlKem768),
            key_bytes: vec![0u8; 1184],
        };
        let json = serde_json::to_string(&key).unwrap();
        let parsed: PqcPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.algorithm,
            PqcAlgorithm::MlKem(MlKemParameterSet::MlKem768)
        );
    }

    #[test]
    fn slh_dsa_variants() {
        let variants = [
            SlhDsaParameterSet::SlhDsaSha2128s,
            SlhDsaParameterSet::SlhDsaShake256f,
        ];
        for v in &variants {
            let alg = PqcAlgorithm::SlhDsa(*v);
            assert!(alg.jose_alg().is_some());
        }
    }
}
