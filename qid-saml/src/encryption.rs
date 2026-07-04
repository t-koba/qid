use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use base64::Engine;
use qid_core::error::{QidError, QidResult};
use rand::Rng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    SamlIssuedResponse, SamlServiceProviderMetadata, close_tag_len, find_close_tag,
    inspect_saml_response_profile, reject_insecure_saml_xml, tag_positions, text_values,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlEncryptionPolicy {
    pub encrypt_assertion: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlEncryptionPlan {
    pub assertion_id: String,
    pub recipient_entity_id: String,
    pub encryption_certificate: String,
}

pub fn plan_saml_encryption(
    issued: &SamlIssuedResponse,
    sp: &SamlServiceProviderMetadata,
    policy: &SamlEncryptionPolicy,
) -> QidResult<Option<SamlEncryptionPlan>> {
    if !policy.encrypt_assertion {
        return Ok(None);
    }
    let encryption_certificate =
        sp.encryption_certificates
            .first()
            .cloned()
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML encrypted assertion requires SP encryption certificate".to_string(),
            })?;
    Ok(Some(SamlEncryptionPlan {
        assertion_id: issued.assertion_id.clone(),
        recipient_entity_id: sp.entity_id.clone(),
        encryption_certificate,
    }))
}

/// Encrypts a SAML assertion XML string using the SP's RSA public key.
/// The `sp_encryption_cert_base64` is the base64-encoded DER X.509 certificate
/// as found in SAML SP metadata `<ds:X509Certificate>` element.
/// Returns the `<saml:EncryptedAssertion>...</saml:EncryptedAssertion>` XML element
/// conforming to XML Encryption (xmlenc) syntax.
///
/// Encryption scheme:
/// - Content encryption: AES-256-GCM (random 256-bit key, 96-bit nonce)
/// - Key transport: RSA-OAEP with SHA-256
pub fn encrypt_assertion_xml(
    assertion_xml: &str,
    sp_encryption_cert_base64: &str,
) -> QidResult<String> {
    use rsa::pkcs8::DecodePublicKey;
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(sp_encryption_cert_base64)
        .map_err(|e| QidError::BadRequest {
            message: format!("failed to base64-decode SP encryption certificate: {e}"),
        })?;
    let cert = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|e| QidError::BadRequest {
            message: format!("failed to parse SP encryption certificate: {e}"),
        })?
        .1;
    let spki_der = cert.tbs_certificate.subject_pki.raw.to_vec();
    let pub_key =
        RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| QidError::BadRequest {
            message: format!(
                "SP encryption certificate does not contain a valid RSA public key: {e}"
            ),
        })?;
    let mut gen_rng = rand::thread_rng();
    let cek: [u8; 32] = gen_rng.r#gen();
    let nonce_bytes: [u8; 12] = gen_rng.r#gen();
    let key = Key::<Aes256Gcm>::from_slice(&cek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, assertion_xml.as_bytes())
        .map_err(|e| QidError::Crypto {
            message: format!("AES-GCM encryption failed: {e}"),
        })?;
    let mut rng = rand::thread_rng();
    let encrypted_cek = pub_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)
        .map_err(|e| QidError::Crypto {
            message: format!("RSA-OAEP key encryption failed: {e}"),
        })?;
    let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
    let encrypted_cek_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted_cek);
    let xml = format!(
        r#"<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-gcm"/>
    <xenc:IV>{nonce_b64}</xenc:IV>
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        </xenc:EncryptionMethod>
        <xenc:CipherData>
          <xenc:CipherValue>{encrypted_cek_b64}</xenc:CipherValue>
        </xenc:CipherData>
      </xenc:EncryptedKey>
    </ds:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>{ciphertext_b64}</xenc:CipherValue>
    </xenc:CipherData>
  </xenc:EncryptedData>
</saml:EncryptedAssertion>"#
    );
    Ok(xml)
}

/// Encrypts the `<saml:Assertion>` element in a SAML Response XML,
/// replacing it with `<saml:EncryptedAssertion>`.
pub fn encrypt_saml_response(
    issued: &SamlIssuedResponse,
    sp_encryption_cert_base64: &str,
) -> QidResult<SamlIssuedResponse> {
    let assertion_starts: Vec<_> = tag_positions(&issued.xml, "Assertion").collect();
    if assertion_starts.len() != 1 {
        return Err(QidError::BadRequest {
            message: "SAML response must contain exactly one Assertion for encryption".to_string(),
        });
    }
    let assertion_start = assertion_starts[0];
    let open_end = assertion_start
        + issued.xml[assertion_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML Assertion start tag is malformed".to_string(),
            })?
        + 1;
    let close_start = find_close_tag(&issued.xml[open_end..], "Assertion").ok_or_else(|| {
        QidError::BadRequest {
            message: "SAML Assertion close tag is missing".to_string(),
        }
    })?;
    let close_start_inner = open_end + close_start;
    let close_end = close_start_inner
        + close_tag_len(&issued.xml[close_start_inner..]).ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion close tag is malformed".to_string(),
        })?;

    let assertion_xml = &issued.xml[assertion_start..close_end];
    let encrypted_assertion_xml = encrypt_assertion_xml(assertion_xml, sp_encryption_cert_base64)?;

    let xml = format!(
        "{}{}{}",
        &issued.xml[..assertion_start],
        encrypted_assertion_xml,
        &issued.xml[close_end..]
    );
    inspect_saml_response_profile(&xml)?;
    Ok(SamlIssuedResponse {
        response_id: issued.response_id.clone(),
        assertion_id: issued.assertion_id.clone(),
        xml,
    })
}

/// Decrypt an `<xenc:EncryptedData>` element back to the original assertion XML.
///
/// Parses the XML Encryption structure, decrypts the CEK via RSA-OAEP with SHA-256,
/// then decrypts the ciphertext with AES-256-GCM.
pub fn decrypt_assertion_xml(
    encrypted_assertion_xml: &str,
    private_key_pem: &[u8],
) -> QidResult<String> {
    // Locate EncryptedData
    let ed_start = tag_positions(encrypted_assertion_xml, "EncryptedData")
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "missing EncryptedData element".to_string(),
        })?;
    let ed_open_end = ed_start
        + encrypted_assertion_xml[ed_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "malformed EncryptedData start tag".to_string(),
            })?
        + 1;
    let ed_close_start = find_close_tag(&encrypted_assertion_xml[ed_open_end..], "EncryptedData")
        .ok_or_else(|| QidError::BadRequest {
        message: "missing EncryptedData close tag".to_string(),
    })?;
    let ed_body = &encrypted_assertion_xml[ed_open_end..ed_open_end + ed_close_start];

    // Extract IV (base64)
    let iv_b64 = text_values(ed_body, "IV")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "missing IV in EncryptedData".to_string(),
        })?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(iv_b64.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid IV base64: {e}"),
        })?;
    if nonce_bytes.len() != 12 {
        return Err(QidError::BadRequest {
            message: "IV must be 12 bytes for AES-256-GCM".to_string(),
        });
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Extract CipherData/CipherValue (base64).
    // The outer CipherData/CipherValue appears after KeyInfo/EncryptedKey,
    // so use the last CipherValue in ed_body.
    let ciphertext_b64 = text_values(ed_body, "CipherValue")
        .into_iter()
        .last()
        .ok_or_else(|| QidError::BadRequest {
            message: "missing CipherValue in EncryptedData".to_string(),
        })?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid CipherValue base64: {e}"),
        })?;

    // Extract EncryptedKey
    let ek_body =
        {
            let ek_start = tag_positions(ed_body, "EncryptedKey")
                .next()
                .ok_or_else(|| QidError::BadRequest {
                    message: "missing EncryptedKey in EncryptedData".to_string(),
                })?;
            let ek_open_end = ek_start
                + ed_body[ek_start..]
                    .find('>')
                    .ok_or_else(|| QidError::BadRequest {
                        message: "malformed EncryptedKey start tag".to_string(),
                    })?
                + 1;
            let ek_close_start = find_close_tag(&ed_body[ek_open_end..], "EncryptedKey")
                .ok_or_else(|| QidError::BadRequest {
                    message: "missing EncryptedKey close tag".to_string(),
                })?;
            &ed_body[ek_open_end..ek_open_end + ek_close_start]
        };

    let encrypted_cek_b64 = text_values(ek_body, "CipherValue")
        .into_iter()
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "missing CipherValue in EncryptedKey".to_string(),
        })?;
    let encrypted_cek = base64::engine::general_purpose::STANDARD
        .decode(encrypted_cek_b64.trim())
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid encrypted CEK base64: {e}"),
        })?;

    // Decrypt the CEK using the private key (RSA-OAEP with SHA-256)
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(private_key_pem).map_err(|_| {
            QidError::BadRequest {
                message: "private key is not valid UTF-8".to_string(),
            }
        })?)
        .map_err(|e| QidError::Crypto {
            message: format!("failed to parse private key: {e}"),
        })?;

    let cek = private_key
        .decrypt(Oaep::new::<Sha256>(), &encrypted_cek)
        .map_err(|e| QidError::Crypto {
            message: format!("RSA-OAEP key decryption failed: {e}",),
        })?;
    if cek.len() != 32 {
        return Err(QidError::BadRequest {
            message: "decrypted CEK must be 32 bytes for AES-256-GCM".to_string(),
        });
    }
    let key = Key::<Aes256Gcm>::from_slice(&cek);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| QidError::Crypto {
            message: format!("AES-256-GCM decryption failed: {e}"),
        })?;
    String::from_utf8(plaintext).map_err(|e| QidError::BadRequest {
        message: format!("decrypted assertion is not valid UTF-8: {e}"),
    })
}

/// Find the `<saml:EncryptedAssertion>` in a SAML Response XML and decrypt it,
/// replacing it with the original `<saml:Assertion>`.
pub fn decrypt_saml_response(saml_response_xml: &str, private_key_pem: &[u8]) -> QidResult<String> {
    let ea_start = tag_positions(saml_response_xml, "EncryptedAssertion")
        .next()
        .ok_or_else(|| QidError::BadRequest {
            message: "no EncryptedAssertion found in SAML Response".to_string(),
        })?;
    let ea_open_end = ea_start
        + saml_response_xml[ea_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "malformed EncryptedAssertion start tag".to_string(),
            })?
        + 1;
    let ea_close_start = find_close_tag(&saml_response_xml[ea_open_end..], "EncryptedAssertion")
        .ok_or_else(|| QidError::BadRequest {
            message: "missing EncryptedAssertion close tag".to_string(),
        })?;
    let ea_close_end = ea_close_start
        + close_tag_len(&saml_response_xml[ea_open_end + ea_close_start..]).ok_or_else(|| {
            QidError::BadRequest {
                message: "malformed EncryptedAssertion close tag".to_string(),
            }
        })?;
    let encrypted_xml = &saml_response_xml[ea_start..ea_open_end + ea_close_end];

    let decrypted_xml = decrypt_assertion_xml(encrypted_xml, private_key_pem)?;

    Ok(format!(
        "{}{}{}",
        &saml_response_xml[..ea_start],
        decrypted_xml,
        &saml_response_xml[ea_open_end + ea_close_end..]
    ))
}

pub fn apply_encrypted_assertion(
    issued: &SamlIssuedResponse,
    encrypted_assertion_xml: &str,
) -> QidResult<SamlIssuedResponse> {
    reject_insecure_saml_xml(encrypted_assertion_xml)?;
    let assertion_starts: Vec<_> = tag_positions(&issued.xml, "Assertion").collect();
    if assertion_starts.len() != 1 {
        return Err(QidError::BadRequest {
            message: "SAML encrypted assertion replacement requires exactly one Assertion"
                .to_string(),
        });
    }
    let assertion_start = assertion_starts[0];
    let open_end = assertion_start
        + issued.xml[assertion_start..]
            .find('>')
            .ok_or_else(|| QidError::BadRequest {
                message: "SAML Assertion start tag is malformed".to_string(),
            })?
        + 1;
    let close_start = find_close_tag(&issued.xml[open_end..], "Assertion").ok_or_else(|| {
        QidError::BadRequest {
            message: "SAML Assertion close tag is missing".to_string(),
        }
    })?;
    let close_start = open_end + close_start;
    let close_end = close_start
        + close_tag_len(&issued.xml[close_start..]).ok_or_else(|| QidError::BadRequest {
            message: "SAML Assertion close tag is malformed".to_string(),
        })?;
    let wrapped = if tag_positions(encrypted_assertion_xml, "EncryptedAssertion")
        .next()
        .is_some()
    {
        encrypted_assertion_xml.to_string()
    } else {
        format!("<saml:EncryptedAssertion>{encrypted_assertion_xml}</saml:EncryptedAssertion>")
    };
    let xml = format!(
        "{}{}{}",
        &issued.xml[..assertion_start],
        wrapped,
        &issued.xml[close_end..]
    );
    inspect_saml_response_profile(&xml)?;
    Ok(SamlIssuedResponse {
        response_id: issued.response_id.clone(),
        assertion_id: issued.assertion_id.clone(),
        xml,
    })
}
