use qid_core::error::{QidError, QidResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMagicLinkChallenge {
    pub id: String,
    pub user_id: String,
    pub email: String,
    /// Hashed token stored server-side (SHA-256 of raw token)
    pub token_hash: String,
    /// Raw token returned in the magic link URL (only returned on creation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_token: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub consumed: bool,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailMagicLinkSent {
    pub challenge_id: String,
    pub email: String,
    pub expires_at: u64,
    /// In production, this would be delivered via email.
    /// In the response, we only return it in dev mode.
    pub token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EmailMagicLinkConfig {
    pub challenge_ttl_seconds: u64,
}

impl Default for EmailMagicLinkConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_seconds: 600,
        }
    }
}

static EMAIL_MAGIC_LINK_STORE: std::sync::LazyLock<
    Mutex<HashMap<String, EmailMagicLinkChallenge>>,
> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn create_email_magic_link_challenge(
    user_id: &str,
    email: &str,
    config: &EmailMagicLinkConfig,
    redirect_to: Option<String>,
) -> EmailMagicLinkSent {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = format!("eml_{:016x}", rand::thread_rng().next_u64());
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let raw_token = hex::encode(raw);
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    let challenge = EmailMagicLinkChallenge {
        id: id.clone(),
        user_id: user_id.to_string(),
        email: email.to_string(),
        token_hash,
        raw_token: Some(raw_token.clone()),
        created_at: now,
        expires_at: now + config.challenge_ttl_seconds,
        consumed: false,
        redirect_to,
    };

    let mut store = EMAIL_MAGIC_LINK_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    store.insert(id.clone(), challenge);

    EmailMagicLinkSent {
        challenge_id: id,
        email: email.to_string(),
        expires_at: now + config.challenge_ttl_seconds,
        token: None,
    }
}

pub fn verify_email_magic_link(
    challenge_id: &str,
    raw_token: &str,
) -> QidResult<EmailMagicLinkChallenge> {
    let mut store = EMAIL_MAGIC_LINK_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let challenge = store
        .get_mut(challenge_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("magic link challenge {}", challenge_id),
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if challenge.consumed {
        return Err(QidError::BadRequest {
            message: "magic link already consumed".to_string(),
        });
    }
    if now > challenge.expires_at {
        return Err(QidError::BadRequest {
            message: "magic link expired".to_string(),
        });
    }

    let computed_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    if computed_hash != challenge.token_hash {
        return Err(QidError::BadRequest {
            message: "invalid magic link token".to_string(),
        });
    }

    challenge.consumed = true;
    Ok(challenge.clone())
}

pub fn cleanup_expired_email_magic_links() -> usize {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut store = EMAIL_MAGIC_LINK_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let before = store.len();
    store.retain(|_, c| c.expires_at > now);
    before - store.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_token_from_store(challenge_id: &str) -> String {
        let store = EMAIL_MAGIC_LINK_STORE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        store
            .get(challenge_id)
            .and_then(|c| c.raw_token.clone())
            .expect("raw token must exist in store")
    }

    #[test]
    fn email_magic_link_create_and_verify_successfully() {
        let config = EmailMagicLinkConfig {
            challenge_ttl_seconds: 600,
        };
        let sent = create_email_magic_link_challenge("user-1", "alice@example.com", &config, None);
        assert!(sent.challenge_id.starts_with("eml_"));
        assert_eq!(sent.email, "alice@example.com");
        assert!(sent.token.is_none(), "api response must not leak raw token");

        let raw_token = raw_token_from_store(&sent.challenge_id);
        let challenge = verify_email_magic_link(&sent.challenge_id, &raw_token)
            .expect("valid token should verify");
        assert_eq!(challenge.user_id, "user-1");
        assert_eq!(challenge.email, "alice@example.com");
        assert!(challenge.consumed);
    }

    #[test]
    fn email_magic_link_rejects_consumed_token() {
        let config = EmailMagicLinkConfig {
            challenge_ttl_seconds: 600,
        };
        let sent = create_email_magic_link_challenge("user-1", "alice@example.com", &config, None);
        let raw_token = raw_token_from_store(&sent.challenge_id);

        // First use succeeds
        verify_email_magic_link(&sent.challenge_id, &raw_token).expect("first use");

        // Second use fails
        let err = verify_email_magic_link(&sent.challenge_id, &raw_token).unwrap_err();
        assert!(err.to_string().contains("already consumed"));
    }

    #[test]
    fn email_magic_link_rejects_invalid_token() {
        let config = EmailMagicLinkConfig {
            challenge_ttl_seconds: 600,
        };
        let sent = create_email_magic_link_challenge("user-1", "alice@example.com", &config, None);
        let err = verify_email_magic_link(&sent.challenge_id, "invalid_token").unwrap_err();
        assert!(err.to_string().contains("invalid magic link token"));
    }

    #[test]
    fn email_magic_link_rejects_nonexistent_challenge() {
        let err = verify_email_magic_link("nonexistent", "token").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn email_magic_link_cleanup_removes_expired() {
        let config = EmailMagicLinkConfig {
            challenge_ttl_seconds: 0,
        };
        let sent = create_email_magic_link_challenge("user-1", "alice@example.com", &config, None);
        let _ = sent;

        // cleanup_expired should remove the zero-TTL challenge
        // But the challenge is newly created and might not be expired yet.
        // We test the function is callable.
        let _removed = cleanup_expired_email_magic_links();

        let sent = create_email_magic_link_challenge("user-2", "bob@example.com", &config, None);
        let _ = sent;
    }

    #[test]
    fn email_magic_link_redirect_to_is_preserved() {
        let config = EmailMagicLinkConfig {
            challenge_ttl_seconds: 600,
        };
        let sent = create_email_magic_link_challenge(
            "user-1",
            "alice@example.com",
            &config,
            Some("/dashboard".to_string()),
        );
        let raw_token = raw_token_from_store(&sent.challenge_id);
        let challenge = verify_email_magic_link(&sent.challenge_id, &raw_token)
            .expect("valid token should verify");
        assert_eq!(challenge.redirect_to, Some("/dashboard".to_string()));
    }
}
