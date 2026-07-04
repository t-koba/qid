//! Push MFA: number matching, geo/device display, fatigue detection.

use qid_core::error::{QidError, QidResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A registered push notification device for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDevice {
    pub id: String,
    pub user_id: String,
    pub device_name: String,
    pub platform: String,
    pub push_token: String,
    pub created_at: u64,
    pub enabled: bool,
}

/// A push authentication challenge sent to the user's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushChallenge {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    /// 6-digit number the user must enter on their phone to approve.
    pub number_match_code: String,
    /// Human-readable location (city, country) of the login attempt.
    pub geo_display: Option<String>,
    /// Device name attempting the login.
    pub requesting_device: Option<String>,
    /// IP address of the login attempt.
    pub requesting_ip: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: PushChallengeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushChallengeStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Configuration for push MFA behaviour.
#[derive(Debug, Clone)]
pub struct PushMfaConfig {
    /// Challenge TTL in seconds (default: 120).
    pub challenge_ttl_seconds: u64,
    /// Cooldown between resending push notifications (seconds).
    pub resend_cooldown_seconds: u64,
    /// Max pending challenges per user before fatigue detection kicks in.
    pub fatigue_max_pending: usize,
    /// Seconds window for fatigue detection.
    pub fatigue_window_seconds: u64,
}

impl Default for PushMfaConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_seconds: 120,
            resend_cooldown_seconds: 30,
            fatigue_max_pending: 5,
            fatigue_window_seconds: 300,
        }
    }
}

/// Tracks recent push attempts to detect fatigue attacks.
#[derive(Debug)]
pub struct PushFatigueState {
    /// user_id -> Vec\<challenge created_at timestamps\>
    recent_attempts: Mutex<HashMap<String, Vec<u64>>>,
}

impl PushFatigueState {
    pub fn new() -> Self {
        Self {
            recent_attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if this push should be rate-limited due to fatigue.
    pub fn check_and_record(&self, user_id: &str, config: &PushMfaConfig) -> QidResult<bool> {
        let now = now_seconds();
        let window_start = now.saturating_sub(config.fatigue_window_seconds);
        let mut map = self
            .recent_attempts
            .lock()
            .map_err(|_| QidError::Internal {
                message: "push fatigue state lock poisoned".to_string(),
            })?;
        let attempts = map.entry(user_id.to_string()).or_default();
        // Remove expired entries
        attempts.retain(|t| *t >= window_start);
        let is_fatigued = attempts.len() >= config.fatigue_max_pending;
        if !is_fatigued {
            attempts.push(now);
        }
        Ok(is_fatigued)
    }

    /// Clear recent attempts (e.g., after successful auth).
    pub fn clear(&self, user_id: &str) -> QidResult<()> {
        let mut map = self
            .recent_attempts
            .lock()
            .map_err(|_| QidError::Internal {
                message: "push fatigue state lock poisoned".to_string(),
            })?;
        map.remove(user_id);
        Ok(())
    }
}

impl Default for PushFatigueState {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a 6-digit number matching code.
pub fn generate_number_match_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let code: u32 = rng.next_u32() % 1_000_000;
    format!("{:06}", code)
}

/// Create a new push authentication challenge.
#[allow(clippy::too_many_arguments)]
pub fn create_push_challenge(
    challenge_id: String,
    user_id: String,
    device: &PushDevice,
    number_match_code: String,
    geo_display: Option<String>,
    requesting_device: Option<String>,
    requesting_ip: Option<String>,
    config: &PushMfaConfig,
) -> PushChallenge {
    let now = now_seconds();
    PushChallenge {
        id: challenge_id,
        user_id,
        device_id: device.id.clone(),
        number_match_code,
        geo_display,
        requesting_device,
        requesting_ip,
        created_at: now,
        expires_at: now + config.challenge_ttl_seconds,
        status: PushChallengeStatus::Pending,
    }
}

/// Verify a user's response to a push challenge.
pub fn verify_push_response(challenge: &PushChallenge, user_number_code: &str) -> bool {
    if challenge.status != PushChallengeStatus::Pending {
        return false;
    }
    let now = now_seconds();
    if now > challenge.expires_at {
        return false;
    }
    qid_core::util::constant_time_eq(
        challenge.number_match_code.as_bytes(),
        user_number_code.as_bytes(),
    )
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_match_code_is_6_digits() {
        for _ in 0..100 {
            let code = generate_number_match_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_create_challenge_and_verify() {
        let device = PushDevice {
            id: "dev-1".to_string(),
            user_id: "usr-1".to_string(),
            device_name: "Alice's iPhone".to_string(),
            platform: "ios".to_string(),
            push_token: "fcm-token-xxx".to_string(),
            created_at: 100,
            enabled: true,
        };
        let config = PushMfaConfig::default();
        let code = generate_number_match_code();
        let challenge = create_push_challenge(
            "chal-1".to_string(),
            "usr-1".to_string(),
            &device,
            code.clone(),
            Some("Tokyo, Japan".to_string()),
            Some("Chrome on macOS".to_string()),
            Some("203.0.113.1".to_string()),
            &config,
        );
        assert_eq!(challenge.status, PushChallengeStatus::Pending);
        assert!(verify_push_response(&challenge, &code));
        assert!(challenge.expires_at >= challenge.created_at + config.challenge_ttl_seconds - 1);
    }

    #[test]
    fn test_verify_wrong_code_fails() {
        let device = PushDevice {
            id: "dev-1".to_string(),
            user_id: "usr-1".to_string(),
            device_name: "device".to_string(),
            platform: "android".to_string(),
            push_token: "tok".to_string(),
            created_at: 100,
            enabled: true,
        };
        let config = PushMfaConfig::default();
        let code = generate_number_match_code();
        let challenge = create_push_challenge(
            "chal-2".to_string(),
            "usr-1".to_string(),
            &device,
            code,
            None,
            None,
            None,
            &config,
        );
        assert!(!verify_push_response(&challenge, "000000"));
    }

    #[test]
    fn test_verify_expired_challenge_fails() {
        let device = PushDevice {
            id: "dev-1".to_string(),
            user_id: "usr-1".to_string(),
            device_name: "device".to_string(),
            platform: "ios".to_string(),
            push_token: "tok".to_string(),
            created_at: 100,
            enabled: true,
        };
        let config = PushMfaConfig::default();
        let code = generate_number_match_code();
        let mut challenge = create_push_challenge(
            "chal-3".to_string(),
            "usr-1".to_string(),
            &device,
            code.clone(),
            None,
            None,
            None,
            &config,
        );
        challenge.expires_at = 0;
        assert!(!verify_push_response(&challenge, &code));
    }

    #[test]
    fn test_fatigue_detection_blocks_excessive() {
        let state = PushFatigueState::new();
        let config = PushMfaConfig {
            fatigue_max_pending: 3,
            fatigue_window_seconds: 300,
            ..PushMfaConfig::default()
        };
        assert!(!state.check_and_record("usr-1", &config).unwrap());
        assert!(!state.check_and_record("usr-1", &config).unwrap());
        assert!(!state.check_and_record("usr-1", &config).unwrap());
        // Fourth one should be fatigued
        assert!(state.check_and_record("usr-1", &config).unwrap());
        // Different user should not be affected
        assert!(!state.check_and_record("usr-2", &config).unwrap());
        // Clearing resets
        state.clear("usr-1").unwrap();
        assert!(!state.check_and_record("usr-1", &config).unwrap());
    }
}
