//! HPKE (RFC 9180) implementation using the `hpke` crate.
#![cfg(feature = "hpke-rfc9180")]

use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem as KemTrait, X25519HkdfSha256};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use qid_core::error::QidResult;

type Kem = X25519HkdfSha256;
type Aead = AesGcm128;

pub fn hpke_seal(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> QidResult<(Vec<u8>, Vec<u8>)> {
    let pk_r = <Kem as KemTrait>::PublicKey::from_bytes(pk_r).map_err(|_| {
        qid_core::error::QidError::BadRequest {
            message: "HPKE public key must be 32 bytes (X25519)".to_string(),
        }
    })?;
    let mut csprng = rand::thread_rng();
    let (encapped_key, mut sender) =
        hpke::setup_sender::<Aead, HkdfSha256, Kem, _>(&OpModeS::Base, &pk_r, info, &mut csprng)
            .map_err(|e| qid_core::error::QidError::Crypto {
                message: format!("HPKE setup sender failed: {e}"),
            })?;
    let ct = sender
        .seal(pt, aad)
        .map_err(|e| qid_core::error::QidError::Crypto {
            message: format!("HPKE seal failed: {e}"),
        })?;
    Ok((encapped_key.to_bytes().to_vec(), ct))
}

pub fn hpke_open(
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> QidResult<Vec<u8>> {
    let sk_r = <Kem as KemTrait>::PrivateKey::from_bytes(sk_r).map_err(|_| {
        qid_core::error::QidError::BadRequest {
            message: "HPKE private key must be 32 bytes (X25519)".to_string(),
        }
    })?;
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(enc).map_err(|_| {
        qid_core::error::QidError::BadRequest {
            message: "HPKE encapped key must be 32 bytes".to_string(),
        }
    })?;
    let mut recipient =
        hpke::setup_receiver::<Aead, HkdfSha256, Kem>(&OpModeR::Base, &sk_r, &encapped_key, info)
            .map_err(|e| qid_core::error::QidError::Crypto {
            message: format!("HPKE setup receiver failed: {e}"),
        })?;
    recipient
        .open(ct, aad)
        .map_err(|e| qid_core::error::QidError::Crypto {
            message: format!("HPKE open failed: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Kem as KemTrait, Serializable};

    #[test]
    fn hpke_round_trip() {
        let mut csprng = rand::thread_rng();
        let (sk_r, pk_r) = Kem::gen_keypair(&mut csprng);
        let info = b"hpke test";
        let aad = b"aad";
        let pt = b"hello hpke";
        let (enc, ct) = hpke_seal(&pk_r.to_bytes(), info, aad, pt).unwrap();
        let result = hpke_open(&enc, &sk_r.to_bytes(), info, aad, &ct).unwrap();
        assert_eq!(result, pt);
    }

    #[test]
    fn hpke_wrong_key_rejected() {
        let mut csprng = rand::thread_rng();
        let (sk_r, pk_r) = Kem::gen_keypair(&mut csprng);
        let (_, wrong_pk) = Kem::gen_keypair(&mut csprng);
        let pt = b"test";
        let (enc, ct) = hpke_seal(&pk_r.to_bytes(), b"info", b"aad", pt).unwrap();
        let result = hpke_open(&enc, &sk_r.to_bytes(), b"info", b"aad", &ct);
        assert!(result.is_ok()); // same key should work
        let result2 = hpke_open(&enc, &wrong_pk.to_bytes(), b"info", b"aad", &ct);
        assert!(result2.is_err()); // wrong key should fail
    }
}
