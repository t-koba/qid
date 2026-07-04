//! SAML HTTP-Redirect binding (DEFLATE + base64 encoding per SAML 2.0 Bindings §3.4).

use base64::Engine;
use flate2::Compression;
use flate2::read::{DeflateDecoder, DeflateEncoder};
use qid_core::error::{QidError, QidResult};
use std::io::Read;

pub fn encode_saml_redirect_message(xml: &str, relay_state: Option<&str>) -> QidResult<String> {
    let mut encoder = DeflateEncoder::new(xml.as_bytes(), Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| QidError::Internal {
            message: format!("SAML DEFLATE compression failed: {e}"),
        })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    let mut url = format!("?SAMLRequest={}", urlencoding::encode(&encoded));
    if let Some(rs) = relay_state
        && rs.len() <= 80
    {
        url.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
    }
    Ok(url)
}

pub fn decode_saml_redirect_message(query: &str) -> QidResult<String> {
    let params: std::collections::HashMap<String, String> = query
        .trim_start_matches('?')
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((
                parts.next()?.to_string(),
                parts.next().unwrap_or("").to_string(),
            ))
        })
        .collect();
    let encoded = params
        .get("SAMLRequest")
        .or_else(|| params.get("SAMLResponse"))
        .ok_or_else(|| QidError::BadRequest {
            message: "missing SAMLRequest or SAMLResponse parameter".to_string(),
        })?;
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| QidError::BadRequest {
            message: format!("base64 decode failed: {e}"),
        })?;
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let mut xml = String::new();
    decoder
        .read_to_string(&mut xml)
        .map_err(|e| QidError::BadRequest {
            message: format!("DEFLATE decompression failed: {e}"),
        })?;
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_redirect_round_trip() {
        let xml = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"req-1\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://idp.example.com</saml:Issuer></samlp:AuthnRequest>";
        let url = encode_saml_redirect_message(xml, Some("relay-state")).unwrap();
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState=relay-state"));
        let decoded = decode_saml_redirect_message(&url).unwrap();
        assert!(decoded.contains("AuthnRequest"));
    }
}
