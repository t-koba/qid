//! Session management and authentication for qid.
#![forbid(unsafe_code)]
//!
//! Phase 0: browser session, password login, refresh token rotation.

pub mod api;
pub mod auth;
pub mod browser;
mod email_magic_link;
pub mod hibp;
mod password_limit;
pub mod refresh;
pub mod totp_api;
pub mod webauthn;

pub use api::{auth_routes, auth_routes_with_password_attempt_limiter};
pub use auth::Authenticator;
pub use browser::{
    BrowserSession, decode_cached_session, session_cache_key, session_cache_put, session_is_active,
};
pub use hibp::HibpClient;
pub use password_limit::PasswordAttemptLimiter;
pub use webauthn::WebAuthnService;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_session_construction() {
        let session = BrowserSession {
            id: "sid_test".to_string(),
            user_id: "user_test".to_string(),
            realm_id: "realm_test".to_string(),
        };
        assert_eq!(session.id, "sid_test");
        assert_eq!(session.user_id, "user_test");
        assert_eq!(session.realm_id, "realm_test");
    }

    #[test]
    fn test_webauthn_builder_valid_params() {
        WebAuthnService::new("login.example.com", "qid-test", "https://login.example.com")
            .expect("webauthn service");
    }

    #[test]
    fn test_webauthn_uid_from_hash() {
        use sha2::Digest;
        let user_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let uid = uuid::Uuid::from_slice(&sha2::Sha256::digest(user_id.as_bytes())[..16]).unwrap();
        let uid_str = uid.to_string();
        // same input must produce same uid
        let uid2 = uuid::Uuid::from_slice(&sha2::Sha256::digest(user_id.as_bytes())[..16]).unwrap();
        assert_eq!(uid, uid2);
        assert_eq!(uid_str.len(), 36);
    }
}
