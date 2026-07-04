//! COSE (CBOR Object Signing and Encryption) — RFC 8152.
//!
//! Minimal implementation supporting:
//! - COSE_Sign1 with ES256 (ECDSA P-256)
//! - CWT (CBOR Web Token, RFC 8392)

use ciborium::Value;
use data_encoding::HEXLOWER;
use p256::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use qid_core::error::{QidError, QidResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A parsed COSE_Sign1 structure.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub protected: BTreeMap<i64, Value>,
    pub unprotected: BTreeMap<i64, Value>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// JSON <-> CBOR conversion helpers for CWT claims
// ---------------------------------------------------------------------------

fn cbor_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            if let Ok(v) = i64::try_from(n) {
                serde_json::Value::Number(v.into())
            } else {
                serde_json::Value::Number(
                    serde_json::Number::from_f64(n as f64).unwrap_or(serde_json::Number::from(0)),
                )
            }
        }
        Value::Bytes(b) => serde_json::Value::String(HEXLOWER.encode(b)),
        Value::Text(t) => serde_json::Value::String(t.clone()),
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Null => serde_json::Value::Null,
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(cbor_to_json).collect()),
        Value::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Text(s) => s.clone(),
                        Value::Integer(i) => {
                            let n: i128 = (*i).into();
                            n.to_string()
                        }
                        other => format!("{other:?}"),
                    };
                    (key, cbor_to_json(v))
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

fn json_to_cbor(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Integer(0.into())
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_cbor).collect()),
        serde_json::Value::Object(obj) => {
            let map: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
                .collect();
            Value::Map(map)
        }
    }
}

// ---------------------------------------------------------------------------
// Sig_structure helper
// ---------------------------------------------------------------------------

/// Build the Sig_structure for COSE_Sign1 (RFC 8152 Section 4.4).
///
/// `protected_bstr` is the raw CBOR bytes of the protected header map
/// (i.e., the *content* of the first `bstr` field in COSE_Sign1).
fn build_sig_structure(protected_bstr: &[u8], payload: &[u8]) -> Vec<u8> {
    // sign_protected and external_aad are empty bstr values.
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bstr.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&sig_structure, &mut buf).expect("CBOR encode of Sig_structure failed");
    buf
}

// ---------------------------------------------------------------------------
// Enc_structure helper  (RFC 8152 Section 5.3)
// ---------------------------------------------------------------------------

fn build_enc_structure(protected_bstr: &[u8]) -> Vec<u8> {
    let enc_structure = Value::Array(vec![
        Value::Text("Encrypt0".to_string()),
        Value::Bytes(protected_bstr.to_vec()),
        Value::Bytes(Vec::new()),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&enc_structure, &mut buf).expect("CBOR encode of Enc_structure failed");
    buf
}

// ---------------------------------------------------------------------------
// MAC_structure helper  (RFC 8152 Section 6.3)
// ---------------------------------------------------------------------------

fn build_mac_structure(protected_bstr: &[u8], payload: &[u8]) -> Vec<u8> {
    let mac_structure = Value::Array(vec![
        Value::Text("MAC0".to_string()),
        Value::Bytes(protected_bstr.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&mac_structure, &mut buf).expect("CBOR encode of MAC_structure failed");
    buf
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a COSE_Sign1 signature over `payload`.
///
/// * `key` – raw 32-byte P-256 private key.
/// * `alg` – must be `"ES256"`.
///
/// Returns the CBOR-encoded COSE_Sign1 as a hex string.
pub fn cose_sign1_sign(payload: &[u8], key: &[u8], alg: &str) -> QidResult<String> {
    if alg != "ES256" {
        return Err(QidError::Crypto {
            message: format!("unsupported COSE algorithm: {alg}"),
        });
    }

    let signing_key = SigningKey::from_slice(key).map_err(|e| QidError::Crypto {
        message: format!("invalid signing key: {e}"),
    })?;

    // Protected header map: { 1 (alg): -7 (ES256) }
    let protected_map = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer((-7i64).into()),
    )]);
    let mut protected_buf = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of protected headers failed: {e}"),
    })?;

    let sig_structure = build_sig_structure(&protected_buf, payload);
    let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();

    // COSE_Sign1 = [protected, unprotected, payload, signature]
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_buf),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig_bytes),
    ]);

    let mut cose_buf = Vec::new();
    ciborium::into_writer(&cose_sign1, &mut cose_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of COSE_Sign1 failed: {e}"),
    })?;

    Ok(HEXLOWER.encode(&cose_buf))
}

/// Verify a COSE_Sign1 and return its payload.
///
/// * `public_key` – SEC1-encoded P-256 public key (compressed 33-byte or
///   uncompressed 65-byte).
pub fn cose_sign1_verify(cose_data: &[u8], public_key: &[u8]) -> QidResult<Vec<u8>> {
    let cose: Value = ciborium::from_reader(cose_data).map_err(|e| QidError::Crypto {
        message: format!("failed to parse COSE data: {e}"),
    })?;

    let arr = match cose {
        Value::Array(ref a) if a.len() == 4 => a,
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Sign1 must be a 4-element array".to_string(),
            });
        }
    };

    let protected_bstr = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Sign1 protected must be bstr".to_string(),
            });
        }
    };
    let payload = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Sign1 payload must be bstr".to_string(),
            });
        }
    };
    let sig_bytes = match &arr[3] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Sign1 signature must be bstr".to_string(),
            });
        }
    };

    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|e| QidError::Crypto {
            message: format!("invalid public key: {e}"),
        })?;

    let sig_structure = build_sig_structure(&protected_bstr, &payload);

    let signature =
        p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|e| QidError::Crypto {
            message: format!("invalid signature bytes: {e}"),
        })?;

    verifying_key
        .verify(&sig_structure, &signature)
        .map_err(|_| QidError::Unauthorized {
            message: "COSE_Sign1 signature verification failed".to_string(),
        })?;

    Ok(payload)
}

/// Encode JSON claims as a CWT (COSE_Sign1 over CBOR-encoded claims, RFC 8392).
///
/// Returns the hex-encoded CBOR.
pub fn cwt_encode(claims: &serde_json::Value, signing_key: &[u8]) -> QidResult<String> {
    let cbor_claims = json_to_cbor(claims);
    let mut payload = Vec::new();
    ciborium::into_writer(&cbor_claims, &mut payload).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of claims failed: {e}"),
    })?;
    cose_sign1_sign(&payload, signing_key, "ES256")
}

/// Decode and verify a CWT, returning the claims as JSON.
pub fn cwt_decode(cwt_data: &[u8], public_key: &[u8]) -> QidResult<serde_json::Value> {
    let payload = cose_sign1_verify(cwt_data, public_key)?;
    let claims: Value = ciborium::from_reader(&payload[..]).map_err(|e| QidError::Crypto {
        message: format!("failed to parse CWT claims CBOR: {e}"),
    })?;
    Ok(cbor_to_json(&claims))
}

// ---------------------------------------------------------------------------
// COSE_Encrypt0  —  RFC 8152 Section 5.3
// ---------------------------------------------------------------------------

/// A parsed COSE_Encrypt0 structure (single-recipient encrypted message).
#[derive(Debug, Clone)]
pub struct CoseEncrypt0 {
    pub protected: BTreeMap<i64, Value>,
    pub unprotected: BTreeMap<i64, Value>,
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` using AES-GCM and return CBOR-encoded COSE_Encrypt0
/// (tag 16) as a hex string.
///
/// * `key` – 16 bytes for A128GCM, 32 bytes for A256GCM.
/// * `alg` – `"A128GCM"` or `"A256GCM"`.
pub fn cose_encrypt0_encrypt(plaintext: &[u8], key: &[u8], alg: &str) -> QidResult<String> {
    let (alg_id, key_size) = match alg {
        "A128GCM" => (1i64, 16usize),
        "A256GCM" => (3, 32),
        _ => {
            return Err(QidError::Crypto {
                message: format!("unsupported COSE algorithm: {alg}"),
            });
        }
    };

    if key.len() != key_size {
        return Err(QidError::Crypto {
            message: format!("key must be {key_size} bytes for {alg}"),
        });
    }

    let protected_map = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer(alg_id.into()),
    )]);
    let mut protected_buf = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of protected headers failed: {e}"),
    })?;

    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let aad = build_enc_structure(&protected_buf);

    let ciphertext = match alg {
        "A128GCM" => {
            use aes_gcm::aead::{Aead, Payload};
            use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
            let k = Key::<Aes128Gcm>::from_slice(key);
            let cipher = Aes128Gcm::new(k);
            let nonce = Nonce::from_slice(&iv);
            cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| QidError::Crypto {
                    message: "AES-128-GCM encryption failed".to_string(),
                })?
        }
        "A256GCM" => {
            use aes_gcm::aead::{Aead, Payload};
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            let k = Key::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(k);
            let nonce = Nonce::from_slice(&iv);
            cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| QidError::Crypto {
                    message: "AES-256-GCM encryption failed".to_string(),
                })?
        }
        _ => unreachable!(),
    };

    let cose_encrypt0 = Value::Tag(
        16,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_buf),
            Value::Map(vec![(Value::Integer(5.into()), Value::Bytes(iv.to_vec()))]),
            Value::Bytes(ciphertext),
        ])),
    );

    let mut cose_buf = Vec::new();
    ciborium::into_writer(&cose_encrypt0, &mut cose_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of COSE_Encrypt0 failed: {e}"),
    })?;

    Ok(HEXLOWER.encode(&cose_buf))
}

/// Decrypt a COSE_Encrypt0 (tag 16) and return the plaintext.
///
/// The algorithm is read from the protected header; `key` must match
/// the expected length (16 bytes for A128GCM, 32 for A256GCM).
pub fn cose_encrypt0_decrypt(cose_data: &[u8], key: &[u8]) -> QidResult<Vec<u8>> {
    let cose: Value = ciborium::from_reader(cose_data).map_err(|e| QidError::Crypto {
        message: format!("failed to parse COSE data: {e}"),
    })?;

    let arr = match cose {
        Value::Tag(16, ref inner) => match inner.as_ref() {
            Value::Array(a) if a.len() == 3 => a,
            _ => {
                return Err(QidError::Crypto {
                    message: "COSE_Encrypt0 must be a 3-element array".to_string(),
                });
            }
        },
        Value::Array(ref a) if a.len() == 3 => a,
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Encrypt0 must be tag-16 or a 3-element array".to_string(),
            });
        }
    };

    let protected_bstr = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Encrypt0 protected must be bstr".to_string(),
            });
        }
    };

    let unprotected = match &arr[1] {
        Value::Map(m) => m.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Encrypt0 unprotected must be map".to_string(),
            });
        }
    };

    let ciphertext = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Encrypt0 ciphertext must be bstr".to_string(),
            });
        }
    };

    let iv = unprotected
        .iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 5.into()))
        .and_then(|(_, v)| match v {
            Value::Bytes(b) if b.len() == 12 => Some(b.clone()),
            _ => None,
        })
        .ok_or_else(|| QidError::Crypto {
            message: "COSE_Encrypt0 missing or invalid IV".to_string(),
        })?;

    let protected_map: Value =
        ciborium::from_reader(&protected_bstr[..]).map_err(|e| QidError::Crypto {
            message: format!("failed to decode protected headers: {e}"),
        })?;

    let alg_id = match protected_map {
        Value::Map(ref m) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 1.into()))
            .and_then(|(_, v)| match v {
                Value::Integer(i) => Some(*i),
                _ => None,
            })
            .ok_or_else(|| QidError::Crypto {
                message: "protected headers missing algorithm".to_string(),
            })?,
        _ => {
            return Err(QidError::Crypto {
                message: "protected headers must be a map".to_string(),
            });
        }
    };
    let n: i128 = alg_id.into();
    let alg_id = n as i64;

    let aad = build_enc_structure(&protected_bstr);

    match alg_id {
        1 => {
            if key.len() != 16 {
                return Err(QidError::Crypto {
                    message: "key must be 16 bytes for A128GCM".to_string(),
                });
            }
            use aes_gcm::aead::{Aead, Payload};
            use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
            let k = Key::<Aes128Gcm>::from_slice(key);
            let cipher = Aes128Gcm::new(k);
            let nonce = Nonce::from_slice(&iv);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| QidError::Crypto {
                    message: "AES-128-GCM decryption failed".to_string(),
                })
        }
        3 => {
            if key.len() != 32 {
                return Err(QidError::Crypto {
                    message: "key must be 32 bytes for A256GCM".to_string(),
                });
            }
            use aes_gcm::aead::{Aead, Payload};
            use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
            let k = Key::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(k);
            let nonce = Nonce::from_slice(&iv);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| QidError::Crypto {
                    message: "AES-256-GCM decryption failed".to_string(),
                })
        }
        _ => Err(QidError::Crypto {
            message: format!("unsupported COSE algorithm ID: {alg_id}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// COSE_Mac0  —  RFC 8152 Section 6.3
// ---------------------------------------------------------------------------

/// A parsed COSE_Mac0 structure (single-sender MACed message).
#[derive(Debug, Clone)]
pub struct CoseMac0 {
    pub protected: BTreeMap<i64, Value>,
    pub unprotected: BTreeMap<i64, Value>,
    pub payload: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Compute a MAC over `payload` using HMAC and return CBOR-encoded
/// COSE_Mac0 (tag 17) as a hex string.
///
/// * `alg` — `"HMAC-SHA256"`.
pub fn cose_mac0_compute(payload: &[u8], key: &[u8], alg: &str) -> QidResult<String> {
    let alg_id = match alg {
        "HMAC-SHA256" => 5i64,
        _ => {
            return Err(QidError::Crypto {
                message: format!("unsupported COSE algorithm: {alg}"),
            });
        }
    };

    let protected_map = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer(alg_id.into()),
    )]);
    let mut protected_buf = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of protected headers failed: {e}"),
    })?;

    let mac_structure = build_mac_structure(&protected_buf, payload);

    let tag = match alg {
        "HMAC-SHA256" => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| QidError::Crypto {
                message: format!("invalid HMAC key: {e}"),
            })?;
            mac.update(&mac_structure);
            mac.finalize().into_bytes().to_vec()
        }
        _ => unreachable!(),
    };

    let cose_mac0 = Value::Tag(
        17,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_buf),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(tag),
        ])),
    );

    let mut cose_buf = Vec::new();
    ciborium::into_writer(&cose_mac0, &mut cose_buf).map_err(|e| QidError::Crypto {
        message: format!("CBOR encode of COSE_Mac0 failed: {e}"),
    })?;

    Ok(HEXLOWER.encode(&cose_buf))
}

/// Verify a COSE_Mac0 (tag 17) and return its payload.
///
/// The algorithm is read from the protected header.
pub fn cose_mac0_verify(cose_data: &[u8], key: &[u8]) -> QidResult<Vec<u8>> {
    let cose: Value = ciborium::from_reader(cose_data).map_err(|e| QidError::Crypto {
        message: format!("failed to parse COSE data: {e}"),
    })?;

    let arr = match cose {
        Value::Tag(17, ref inner) => match inner.as_ref() {
            Value::Array(a) if a.len() == 4 => a,
            _ => {
                return Err(QidError::Crypto {
                    message: "COSE_Mac0 must be a 4-element array".to_string(),
                });
            }
        },
        Value::Array(ref a) if a.len() == 4 => a,
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Mac0 must be tag-17 or a 4-element array".to_string(),
            });
        }
    };

    let protected_bstr = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Mac0 protected must be bstr".to_string(),
            });
        }
    };

    let payload = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Mac0 payload must be bstr".to_string(),
            });
        }
    };

    let tag = match &arr[3] {
        Value::Bytes(b) => b.clone(),
        _ => {
            return Err(QidError::Crypto {
                message: "COSE_Mac0 tag must be bstr".to_string(),
            });
        }
    };

    let protected_map: Value =
        ciborium::from_reader(&protected_bstr[..]).map_err(|e| QidError::Crypto {
            message: format!("failed to decode protected headers: {e}"),
        })?;

    let alg_id = match protected_map {
        Value::Map(ref m) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 1.into()))
            .and_then(|(_, v)| match v {
                Value::Integer(i) => Some(*i),
                _ => None,
            })
            .ok_or_else(|| QidError::Crypto {
                message: "protected headers missing algorithm".to_string(),
            })?,
        _ => {
            return Err(QidError::Crypto {
                message: "protected headers must be a map".to_string(),
            });
        }
    };
    let n: i128 = alg_id.into();
    let alg_id = n as i64;

    let mac_structure = build_mac_structure(&protected_bstr, &payload);

    match alg_id {
        5 => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| QidError::Crypto {
                message: format!("invalid HMAC key: {e}"),
            })?;
            mac.update(&mac_structure);
            mac.verify_slice(&tag).map_err(|_| QidError::Unauthorized {
                message: "COSE_Mac0 MAC verification failed".to_string(),
            })?;
            Ok(payload)
        }
        _ => Err(QidError::Crypto {
            message: format!("unsupported COSE algorithm ID: {alg_id}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// COSE_recipient  —  RFC 8152 Section 6.1
// ---------------------------------------------------------------------------

/// A COSE_recipient structure for key wrapping.
#[derive(Debug, Clone)]
pub struct CoseRecipient {
    pub protected: BTreeMap<i64, Value>,
    pub unprotected: BTreeMap<i64, Value>,
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// COSE Countersignatures  —  RFC 9338
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CoseCountersignature {
    pub protected: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn cose_add_countersignature(cose_data: &[u8], key: &[u8]) -> QidResult<Vec<u8>> {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    let pem = std::str::from_utf8(key).map_err(|_| QidError::BadRequest {
        message: "key must be PEM string".to_string(),
    })?;
    let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|e| QidError::Crypto {
        message: format!("countersign key parse failed: {e}"),
    })?;
    let signature: p256::ecdsa::Signature = signing_key.sign(cose_data);
    let sig_bytes = signature.to_bytes().to_vec();
    let mut result = cose_data.to_vec();
    let cs = Value::Tag(19, Box::new(Value::Bytes(sig_bytes)));
    let mut cs_buf = Vec::new();
    ciborium::ser::into_writer(&cs, &mut cs_buf).map_err(|e| QidError::Crypto {
        message: format!("countersignature CBOR encode failed: {e}"),
    })?;
    result.extend_from_slice(&cs_buf);
    Ok(result)
}

// ---------------------------------------------------------------------------
// CWT cnf  —  RFC 8747
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CwtCnf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub fn cwt_add_cnf(cwt_data: &mut serde_json::Value, cnf: &CwtCnf) {
    if let Some(obj) = cwt_data.as_object_mut() {
        obj.insert(
            "cnf".to_string(),
            serde_json::to_value(cnf).unwrap_or_default(),
        );
    }
}

pub fn cwt_extract_cnf(cwt_data: &serde_json::Value) -> Option<CwtCnf> {
    cwt_data
        .get("cnf")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_p256_keypair() -> ([u8; 32], Vec<u8>) {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let secret: [u8; 32] = signing_key.to_bytes().into();
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
        (secret, public_bytes)
    }

    #[test]
    fn cose_sign1_roundtrip() {
        let (private_key, public_key) = generate_p256_keypair();
        let payload = b"hello cose";
        let cose_hex = cose_sign1_sign(payload, &private_key, "ES256").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_sign1_verify(&cose_bytes, &public_key).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn cose_sign1_wrong_key_rejected() {
        let (private_key, _) = generate_p256_keypair();
        let (_, wrong_public_key) = generate_p256_keypair();
        let payload = b"test data";
        let cose_hex = cose_sign1_sign(payload, &private_key, "ES256").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_sign1_verify(&cose_bytes, &wrong_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn cwt_roundtrip() {
        let (private_key, public_key) = generate_p256_keypair();
        let claims = serde_json::json!({
            "iss": "example.com",
            "sub": "user123",
            "aud": "app1"
        });
        let cwt_hex = cwt_encode(&claims, &private_key).unwrap();
        let cwt_bytes = HEXLOWER
            .decode(cwt_hex.as_bytes())
            .expect("hex decode failed");
        let decoded = cwt_decode(&cwt_bytes, &public_key).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn cose_encrypt0_a128gcm_roundtrip() {
        let key = [0x11u8; 16];
        let plaintext = b"hello encrypt0";
        let cose_hex = cose_encrypt0_encrypt(plaintext, &key, "A128GCM").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_encrypt0_decrypt(&cose_bytes, &key).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn cose_encrypt0_a256gcm_roundtrip() {
        let key = [0x22u8; 32];
        let plaintext = b"aes-256-gcm test";
        let cose_hex = cose_encrypt0_encrypt(plaintext, &key, "A256GCM").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_encrypt0_decrypt(&cose_bytes, &key).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn cose_encrypt0_wrong_key_rejected() {
        let key = [0x33u8; 16];
        let wrong_key = [0x44u8; 16];
        let cose_hex = cose_encrypt0_encrypt(b"secret data", &key, "A128GCM").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_encrypt0_decrypt(&cose_bytes, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn cose_mac0_hmac_sha256_roundtrip() {
        let key = [0x55u8; 32];
        let payload = b"mac me";
        let cose_hex = cose_mac0_compute(payload, &key, "HMAC-SHA256").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_mac0_verify(&cose_bytes, &key).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn cose_mac0_wrong_key_rejected() {
        let key = [0x66u8; 32];
        let wrong_key = [0x77u8; 32];
        let cose_hex = cose_mac0_compute(b"authenticate me", &key, "HMAC-SHA256").unwrap();
        let cose_bytes = HEXLOWER
            .decode(cose_hex.as_bytes())
            .expect("hex decode failed");
        let result = cose_mac0_verify(&cose_bytes, &wrong_key);
        assert!(result.is_err());
    }
}
