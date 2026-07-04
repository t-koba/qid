//! X25519 ECDH key exchange (RFC 7748).

use qid_core::error::{QidError, QidResult};
use x25519_dalek::{PublicKey, StaticSecret};

/// Generate an X25519 key pair. Returns (private_key, public_key).
pub fn x25519_gen_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let sk = StaticSecret::random_from_rng(&mut rng);
    let pk = PublicKey::from(&sk);
    (sk.to_bytes(), pk.to_bytes())
}

/// Compute ECDH shared secret.
pub fn x25519_ecdh(private_key: &[u8; 32], public_key: &[u8; 32]) -> QidResult<[u8; 32]> {
    let pk = PublicKey::from(*public_key);
    let sk = StaticSecret::from(*private_key);
    let shared = sk.diffie_hellman(&pk);
    Ok(shared.to_bytes())
}

/// Validate an X25519 public key (clamping check).
pub fn x25519_validate_public_key(key: &[u8; 32]) -> QidResult<()> {
    if key.iter().all(|&b| b == 0) {
        return Err(QidError::BadRequest {
            message: "X25519 public key is the identity element".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypair_generation() {
        let (sk, pk) = x25519_gen_keypair();
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);
    }

    #[test]
    fn x25519_ecdh_round_trip() {
        let (sk_a, pk_a) = x25519_gen_keypair();
        let (sk_b, pk_b) = x25519_gen_keypair();
        let shared_a = x25519_ecdh(&sk_a, &pk_b).unwrap();
        let shared_b = x25519_ecdh(&sk_b, &pk_a).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn x25519_validate_rejects_zero() {
        assert!(x25519_validate_public_key(&[0u8; 32]).is_err());
    }
}
