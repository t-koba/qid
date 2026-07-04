//! HTTP Idempotency-Key (draft-ietf-httpapi-idempotency-key).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdempotencyKey {
    pub key: String,
    pub response_status: u16,
    pub response_body: Option<serde_json::Value>,
    pub created_at: u64,
}

impl IdempotencyKey {
    pub fn new(key: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            key,
            response_status: 0,
            response_body: None,
            created_at: now,
        }
    }

    pub fn is_expired(&self, ttl_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now - self.created_at > ttl_seconds
    }
}

pub fn validate_idempotency_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() || key.len() > 255 {
        return Err("Idempotency-Key must be 1-255 characters");
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~')
    {
        return Err("Idempotency-Key contains invalid characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key() {
        assert!(validate_idempotency_key("my-key-123").is_ok());
    }

    #[test]
    fn empty_key_invalid() {
        assert!(validate_idempotency_key("").is_err());
    }

    #[test]
    fn idempotency_key_expiry() {
        let key = IdempotencyKey::new("test-key".to_string());
        assert!(!key.is_expired(86400));
    }
}
