//! Web Push (RFC 8030/8291/8292).

use crate::error::{QidError, QidResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebPushSubscription {
    pub endpoint: String,
    pub keys: WebPushKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebPushKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebPushNotification {
    pub title: String,
    pub body: Option<String>,
    pub icon: Option<String>,
    pub badge: Option<String>,
    pub tag: Option<String>,
    pub data: Option<serde_json::Value>,
    pub actions: Vec<WebPushAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebPushAction {
    pub action: String,
    pub title: String,
}

impl WebPushNotification {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            body: None,
            icon: None,
            badge: None,
            tag: None,
            data: None,
            actions: Vec::new(),
        }
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

pub fn vapid_sign(subscription: &WebPushSubscription, private_key_pem: &[u8]) -> QidResult<String> {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;

    let pem = std::str::from_utf8(private_key_pem).map_err(|_| QidError::BadRequest {
        message: "VAPID key PEM is not valid UTF-8".to_string(),
    })?;
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| QidError::Crypto {
        message: format!("VAPID key parse failed: {e}"),
    })?;
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
    let now = crate::util::now_seconds();
    let claims = serde_json::json!({
        "aud": subscription.endpoint,
        "exp": now + 86400,
        "sub": "mailto:admin@example.com",
    });
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header).map_err(|e| QidError::Internal {
            message: format!("failed to encode VAPID header: {e}"),
        })?,
    );
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&claims).map_err(|e| QidError::Internal {
            message: format!("failed to encode VAPID claims: {e}"),
        })?,
    );
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_push_notification_serializes() {
        let n = WebPushNotification::new("Test Title").with_body("Test Body");
        let json = n.to_json();
        assert_eq!(json["title"], "Test Title");
    }
}
