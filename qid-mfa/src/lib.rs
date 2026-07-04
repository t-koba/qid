//! Multi-factor authentication primitives for qid.
#![forbid(unsafe_code)]

pub mod email_magic;
pub mod push;

use qid_core::{
    error::{QidError, QidResult},
    models::TotpCredential,
};
use qid_crypto::totp::TotpVerifier;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactorKind {
    WebAuthn,
    Totp,
    Push,
    EmailMagicLink,
    RecoveryCode,
    ClientCertificate,
}

impl MfaFactorKind {
    pub fn amr(self) -> &'static str {
        match self {
            Self::WebAuthn => "urn:qid:amr:webauthn",
            Self::Totp => "urn:qid:amr:totp",
            Self::Push => "urn:qid:amr:push",
            Self::EmailMagicLink => "urn:qid:amr:email_magic_link",
            Self::RecoveryCode => "urn:qid:amr:recovery_code",
            Self::ClientCertificate => "urn:qid:amr:client_certificate",
        }
    }

    pub fn phishing_resistant(self) -> bool {
        matches!(self, Self::WebAuthn | Self::ClientCertificate)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaPolicy {
    pub allowed: BTreeSet<MfaFactorKind>,
    pub require_phishing_resistant_for_admin: bool,
    pub allow_recovery_code_for_step_up: bool,
    /// Cooldown between push notification resends (seconds). Default: 30.
    pub push_resend_cooldown_seconds: u64,
    /// Max pending push challenges per user before fatigue blocking. Default: 5.
    pub push_fatigue_max_pending: usize,
    /// Window for push fatigue detection (seconds). Default: 300.
    pub push_fatigue_window_seconds: u64,
}

impl Default for MfaPolicy {
    fn default() -> Self {
        Self {
            allowed: BTreeSet::from([
                MfaFactorKind::WebAuthn,
                MfaFactorKind::Totp,
                MfaFactorKind::Push,
                MfaFactorKind::RecoveryCode,
            ]),
            require_phishing_resistant_for_admin: true,
            allow_recovery_code_for_step_up: true,
            push_resend_cooldown_seconds: 30,
            push_fatigue_max_pending: 5,
            push_fatigue_window_seconds: 300,
        }
    }
}

impl MfaPolicy {
    pub fn validate(&self) -> QidResult<()> {
        if self.allowed.is_empty() {
            return Err(QidError::Config {
                message: "MFA policy must allow at least one factor".to_string(),
            });
        }
        if self.require_phishing_resistant_for_admin
            && !self
                .allowed
                .iter()
                .any(|factor| factor.phishing_resistant())
        {
            return Err(QidError::Config {
                message: "admin MFA policy requires at least one phishing-resistant factor"
                    .to_string(),
            });
        }
        if self.push_resend_cooldown_seconds < 5 {
            return Err(QidError::Config {
                message: "push MFA resend cooldown must be at least 5 seconds".to_string(),
            });
        }
        if self.push_fatigue_max_pending < 1 {
            return Err(QidError::Config {
                message: "push MFA fatigue max pending must be at least 1".to_string(),
            });
        }
        if self.push_fatigue_window_seconds < 30 {
            return Err(QidError::Config {
                message: "push MFA fatigue window must be at least 30 seconds".to_string(),
            });
        }
        Ok(())
    }

    pub fn allowed_amr(&self) -> Vec<&'static str> {
        self.allowed.iter().map(|factor| factor.amr()).collect()
    }

    pub fn step_up_satisfies_policy(&self, amr: &[String], admin: bool) -> bool {
        let used: BTreeSet<&str> = amr.iter().map(String::as_str).collect();
        let allowed = self
            .allowed
            .iter()
            .filter(|factor| {
                self.allow_recovery_code_for_step_up || **factor != MfaFactorKind::RecoveryCode
            })
            .any(|factor| used.contains(factor.amr()));
        if !allowed {
            return false;
        }
        if admin && self.require_phishing_resistant_for_admin {
            return self
                .allowed
                .iter()
                .filter(|factor| factor.phishing_resistant())
                .any(|factor| used.contains(factor.amr()));
        }
        true
    }

    pub fn push_config(&self) -> push::PushMfaConfig {
        push::PushMfaConfig {
            challenge_ttl_seconds: 120,
            resend_cooldown_seconds: self.push_resend_cooldown_seconds,
            fatigue_max_pending: self.push_fatigue_max_pending,
            fatigue_window_seconds: self.push_fatigue_window_seconds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollmentPlan {
    pub credential: TotpCredential,
    pub otpauth_url: String,
}

pub fn create_totp_enrollment(
    id: impl Into<String>,
    user_id: impl Into<String>,
    account_name: &str,
    issuer: &str,
    digits: u32,
    period: u64,
    created_at: u64,
) -> QidResult<TotpEnrollmentPlan> {
    if account_name.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "TOTP account name must not be empty".to_string(),
        });
    }
    if issuer.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "TOTP issuer must not be empty".to_string(),
        });
    }
    if !(6..=8).contains(&digits) {
        return Err(QidError::BadRequest {
            message: "TOTP digits must be between 6 and 8".to_string(),
        });
    }
    if period < 15 {
        return Err(QidError::BadRequest {
            message: "TOTP period must be at least 15 seconds".to_string(),
        });
    }

    let verifier = TotpVerifier::new(digits, period);
    let secret = TotpVerifier::generate_secret();
    let credential = TotpCredential {
        id: id.into(),
        user_id: user_id.into(),
        secret: secret.clone(),
        algorithm: "SHA1".to_string(),
        digits,
        period,
        enabled: false,
        last_used_step: None,
        created_at,
    };
    Ok(TotpEnrollmentPlan {
        otpauth_url: build_otpauth_url(issuer, account_name, &secret, &verifier),
        credential,
    })
}

pub fn verify_totp_at(credential: &TotpCredential, code: &str, timestamp: u64) -> bool {
    verify_totp_at_with_step(credential, code, timestamp)
        .unwrap_or(None)
        .is_some()
}

/// Verify a TOTP code AND atomically compute the next `last_used_step`
/// value that the caller MUST persist. Returning both the boolean result
/// and the new `last_used_step` from a single function keeps replay
/// prevention in one place instead of duplicating the boundary check
/// across every code path.
pub fn verify_totp_at_with_step(
    credential: &TotpCredential,
    code: &str,
    timestamp: u64,
) -> QidResult<Option<u64>> {
    if !credential.enabled || credential.algorithm != "SHA1" {
        return Ok(None);
    }
    let verifier = TotpVerifier::new(credential.digits, credential.period);
    let candidates = [
        timestamp,
        timestamp.saturating_sub(credential.period),
        timestamp.saturating_add(credential.period),
    ];
    for ts in candidates {
        let step = ts / credential.period;
        if let Some(last_step) = credential.last_used_step
            && step <= last_step
        {
            continue;
        }
        if qid_core::util::constant_time_eq(
            code.as_bytes(),
            verifier.generate_code(&credential.secret, ts)?.as_bytes(),
        ) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryCode {
    pub display_code: String,
    pub code_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryCodeBatch {
    pub codes: Vec<RecoveryCode>,
}

impl RecoveryCodeBatch {
    pub fn generate(count: usize) -> QidResult<Self> {
        if !(1..=24).contains(&count) {
            return Err(QidError::BadRequest {
                message: "recovery code count must be between 1 and 24".to_string(),
            });
        }
        let mut seen = BTreeSet::new();
        let mut codes = Vec::with_capacity(count);
        while codes.len() < count {
            let display_code = generate_recovery_code();
            if seen.insert(display_code.clone()) {
                codes.push(RecoveryCode {
                    code_hash: hash_recovery_code(&display_code),
                    display_code,
                });
            }
        }
        Ok(Self { codes })
    }

    pub fn verify(&self, candidate: &str) -> Option<usize> {
        let hash = hash_recovery_code(candidate);
        self.codes.iter().position(|code| {
            qid_core::util::constant_time_eq(code.code_hash.as_bytes(), hash.as_bytes())
        })
    }

    pub fn consume(&mut self, candidate: &str) -> bool {
        let Some(index) = self.verify(candidate) else {
            return false;
        };
        self.codes.remove(index);
        true
    }
}

pub fn hash_recovery_code(code: &str) -> String {
    let normalized = normalize_recovery_code(code);
    let digest = Sha256::digest(normalized.as_bytes());
    hex_encode(&digest)
}

fn build_otpauth_url(
    issuer: &str,
    account_name: &str,
    secret: &str,
    verifier: &TotpVerifier,
) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent_encode(issuer),
        percent_encode(account_name),
        secret,
        percent_encode(issuer),
        verifier.digits,
        verifier.period
    )
}

fn generate_recovery_code() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut bytes = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(14);
    for (idx, byte) in bytes.iter().enumerate() {
        if idx == 5 {
            out.push('-');
        }
        out.push(ALPHABET[*byte as usize % ALPHABET.len()] as char);
    }
    out
}

fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => {
                let hex = b"0123456789ABCDEF";
                vec![
                    '%',
                    hex[(byte >> 4) as usize] as char,
                    hex[(byte & 0x0f) as usize] as char,
                ]
            }
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_policy_requires_phishing_resistant_admin_factor() {
        let policy = MfaPolicy {
            allowed: BTreeSet::from([MfaFactorKind::Totp, MfaFactorKind::RecoveryCode]),
            require_phishing_resistant_for_admin: true,
            allow_recovery_code_for_step_up: true,
            push_resend_cooldown_seconds: 30,
            push_fatigue_max_pending: 5,
            push_fatigue_window_seconds: 300,
        };
        assert!(policy.validate().is_err());

        let policy = MfaPolicy::default();
        assert!(policy.validate().is_ok());
        assert!(policy.step_up_satisfies_policy(&["urn:qid:amr:webauthn".to_string()], true));
        assert!(!policy.step_up_satisfies_policy(&["urn:qid:amr:totp".to_string()], true));
        assert!(policy.step_up_satisfies_policy(&["urn:qid:amr:totp".to_string()], false));
    }

    #[test]
    fn totp_enrollment_builds_disabled_credential_and_url() {
        let plan =
            create_totp_enrollment("totp-1", "user-1", "alice@example.com", "qid", 6, 30, 100)
                .expect("TOTP enrollment");

        assert_eq!(plan.credential.id, "totp-1");
        assert_eq!(plan.credential.user_id, "user-1");
        assert_eq!(plan.credential.created_at, 100);
        assert!(!plan.credential.enabled);
        assert!(plan.otpauth_url.starts_with("otpauth://totp/qid:alice"));
        assert!(plan.otpauth_url.contains("digits=6"));
    }

    #[test]
    fn totp_verify_at_accepts_adjacent_windows_only_when_enabled() {
        let mut plan =
            create_totp_enrollment("totp-1", "user-1", "alice@example.com", "qid", 6, 30, 100)
                .expect("TOTP enrollment");
        let verifier = TotpVerifier::new(6, 30);
        let code = verifier
            .generate_code(&plan.credential.secret, 1_000_000)
            .unwrap();
        assert!(!verify_totp_at(&plan.credential, &code, 1_000_000));
        plan.credential.enabled = true;
        assert!(verify_totp_at(&plan.credential, &code, 1_000_000));
        assert!(verify_totp_at(&plan.credential, &code, 1_000_030));
        assert!(!verify_totp_at(&plan.credential, &code, 1_000_090));
    }

    #[test]
    fn recovery_codes_are_unique_hashed_and_consumable_once() {
        let mut batch = RecoveryCodeBatch::generate(8).expect("recovery codes");
        assert_eq!(batch.codes.len(), 8);
        let display = batch.codes[0].display_code.clone();
        assert_ne!(batch.codes[0].display_code, batch.codes[0].code_hash);
        assert!(batch.codes.iter().all(|code| code.code_hash.len() == 64));
        assert!(batch.verify(&display.to_lowercase()).is_some());
        assert!(batch.consume(&display));
        assert!(!batch.consume(&display));
        assert_eq!(batch.codes.len(), 7);
    }

    #[test]
    fn recovery_code_hash_normalizes_spacing_and_case() {
        assert_eq!(
            hash_recovery_code("abcd-efghij"),
            hash_recovery_code(" ABCDE FGHIJ ")
        );
    }
}
