//! Admission control for TOTP proof attempts.
//!
//! The realm's TOTP policy bounds the failed proofs one account may spend
//! within a fixed window. This limiter counts *admissions*: the proofs that
//! reach verification at all. It answers after the user and the TOTP
//! credential are known and before any code verification, so a spray of
//! guesses costs the deployment nothing once the admission budget is spent.
//! A proof that verifies and wins the step claim gives its admission back;
//! wrong codes, malformed codes, replays and step-claim losers keep the
//! admission they spent.
//!
//! The limiter is process-local memory: restarting the process, or running
//! more than one process, does not share counts. It is not a distributed
//! protection mechanism.

use qid_core::config::TotpConfig;
use qid_http::ratelimit::{AxisLimit, RateLimitConfig, RateLimiter};

/// The admission limiter the TOTP confirmation and authentication paths share.
///
/// The limiter holds no policy of its own: the account's limit and window
/// are the realm's `max_failed_attempts` and `failed_attempt_window_seconds`.
pub struct TotpAttemptLimiter {
    limiter: RateLimiter,
}

impl Default for TotpAttemptLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpAttemptLimiter {
    /// A limiter that takes every limit from the realm's TOTP policy.
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(RateLimitConfig::default()),
        }
    }

    /// The admission key of one account in one realm.
    ///
    /// The realm's own identifier and the exact bytes of the user identifier
    /// name the account, so two realms never share a count. The length
    /// prefix keeps a realm identifier that itself contains a colon from
    /// colliding with another realm and user pair.
    fn account_key(realm: &str, user_id: &str) -> String {
        format!("{}:{realm}:{user_id}", realm.len())
    }

    /// Whether a TOTP proof may reach verification.
    ///
    /// The account's count follows the realm's `max_failed_attempts` and
    /// `failed_attempt_window_seconds`. The window is fixed: attempts do not
    /// extend it, and a TOTP code step rolling over does not reset it. A
    /// proof refused here never reaches code verification, step consumption,
    /// enrolment activation or session creation.
    pub fn admit(&self, realm: &str, user_id: &str, policy: &TotpConfig) -> bool {
        // The tenant axis is absent: each account carries its own budget and
        // there is no realm-wide TOTP aggregate. Its limit is unused.
        let window = policy.failed_attempt_window_seconds;
        self.limiter.check_user_tenant(
            Some(&Self::account_key(realm, user_id)),
            AxisLimit::new(policy.max_failed_attempts, window),
            None,
            AxisLimit::new(u32::MAX, window),
        )
    }

    /// Record a successful TOTP proof of one account in one realm.
    ///
    /// The successful proof gives back the admission it spent, so the count
    /// follows the proofs that failed and the ones still in flight. A failure
    /// before the success is still counted.
    pub fn succeeded(&self, realm: &str, user_id: &str) {
        self.limiter
            .release_user(&Self::account_key(realm, user_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A policy with the numbers a test states.
    fn policy(max_failed_attempts: u32, failed_attempt_window_seconds: u64) -> TotpConfig {
        TotpConfig {
            enabled: true,
            max_failed_attempts,
            failed_attempt_window_seconds,
        }
    }

    #[test]
    fn the_account_limit_follows_the_realm_policy() {
        let limiter = TotpAttemptLimiter::new();
        let policy = policy(2, 300);
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(!limiter.admit("corp", "alice", &policy));
        // Another account of the same realm keeps its own count.
        assert!(limiter.admit("corp", "bob", &policy));
    }

    #[test]
    fn an_expired_window_starts_the_count_over() {
        let limiter = TotpAttemptLimiter::new();
        // A window of zero seconds has passed at once, so every admission
        // finds an expired count and the budget never runs out. The
        // configuration validation forbids a zero window; the limiter
        // accepts it here only to show the reset without sleeping.
        let policy = policy(1, 0);
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(limiter.admit("corp", "alice", &policy));
    }

    #[test]
    fn the_realms_keep_their_own_counts() {
        let limiter = TotpAttemptLimiter::new();
        let policy = policy(1, 300);
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(!limiter.admit("corp", "alice", &policy));
        // The same user identifier in another realm is another account.
        assert!(limiter.admit("other", "alice", &policy));
        assert!(!limiter.admit("other", "alice", &policy));
    }

    #[test]
    fn the_key_prefix_keeps_colon_realms_apart() {
        let limiter = TotpAttemptLimiter::new();
        let policy = policy(1, 300);
        // Without the length prefix, realm "a:b" with user "c" and realm
        // "a" with user "b:c" would share the key "a:b:c".
        assert!(limiter.admit("a:b", "c", &policy));
        assert!(!limiter.admit("a:b", "c", &policy));
        assert!(limiter.admit("a", "b:c", &policy));
        assert!(!limiter.admit("a", "b:c", &policy));
    }

    #[test]
    fn a_successful_proof_gives_the_account_its_admission_back() {
        let limiter = TotpAttemptLimiter::new();
        let policy = policy(2, 300);
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(limiter.admit("corp", "alice", &policy));
        limiter.succeeded("corp", "alice");
        // The account spent one admission on the successful proof, so one
        // attempt is left in the window.
        assert!(limiter.admit("corp", "alice", &policy));
        assert!(!limiter.admit("corp", "alice", &policy));
    }

    #[test]
    fn parallel_admissions_never_exceed_the_limit() {
        let limiter = Arc::new(TotpAttemptLimiter::new());
        let policy = policy(5, 300);
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..20)
                .map(|_| scope.spawn(|| usize::from(limiter.admit("corp", "alice", &policy))))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("admission thread joins"))
                .sum::<usize>()
        });
        assert_eq!(admitted, 5, "exactly the budget admits, no more");
        assert!(!limiter.admit("corp", "alice", &policy));
    }
}
