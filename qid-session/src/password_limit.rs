//! Admission control for password logins.
//!
//! The realm's password policy bounds the failures a login may spend, and
//! the realm's failure budget bounds the failures the realm accepts as a
//! whole. Both count failures, so both are settled after a credential has
//! been verified. This limiter counts *admissions*: the password logins
//! that reach the credential work at all. It answers before the credential
//! lookup and before any Argon2id work, so a spray of guesses costs the
//! deployment nothing once the admission limit is spent.

use qid_http::ratelimit::{AxisLimit, RateLimitConfig, RateLimiter};

use crate::auth::PasswordPolicy;

/// The admission limiter the password login paths share.
///
/// The limiter holds no policy of its own: the account's limit and window
/// are the realm's `max_failed_attempts` and `lockout_duration_seconds`,
/// and the realm's limit and window are the deployment's defaults.
pub struct PasswordAttemptLimiter {
    limiter: RateLimiter,
    tenant_limit: AxisLimit,
}

impl Default for PasswordAttemptLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordAttemptLimiter {
    /// A limiter with the deployment's default realm admission limit.
    pub fn new() -> Self {
        let config = RateLimitConfig::default();
        let tenant_limit = AxisLimit::new(config.max_per_tenant, config.window_seconds);
        Self {
            limiter: RateLimiter::new(config),
            tenant_limit,
        }
    }

    /// The admission key of one account in one realm.
    ///
    /// The realm's own identifier and the exact bytes of the submitted
    /// email address name the account, so two realms never share a count
    /// and an address is never normalized before it is counted.
    fn user_key(realm: &str, email: &str) -> String {
        format!("{}:{realm}:{email}", realm.len())
    }

    /// Whether a password login may reach the credential work.
    ///
    /// The account's count follows the realm's `max_failed_attempts` and
    /// `lockout_duration_seconds`, and the realm's own count follows the
    /// deployment's defaults. A login refused here never spends the
    /// realm's failure budget, so the refusal is a temporary condition of
    /// the deployment rather than a statement about the account the
    /// caller named.
    pub fn admit(&self, realm: &str, email: &str, policy: &PasswordPolicy) -> bool {
        self.limiter.check_user_tenant(
            Some(&Self::user_key(realm, email)),
            AxisLimit::new(policy.max_failed_attempts, policy.lockout_duration_seconds),
            Some(realm),
            self.tenant_limit,
        )
    }

    /// Forget the admission count of one account in one realm.
    ///
    /// A successful login clears the account's own count and leaves the
    /// realm's count alone: the realm's count is the deployment's bound,
    /// not the account's.
    pub fn reset_user(&self, realm: &str, email: &str) {
        self.limiter.reset_user(&Self::user_key(realm, email));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::config::PasswordConfig;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A policy with the numbers a test states.
    fn policy(max_failed_attempts: u32, lockout_duration_seconds: u64) -> PasswordPolicy {
        let mut policy = PasswordPolicy::from_config(&PasswordConfig::default());
        policy.max_failed_attempts = max_failed_attempts;
        policy.lockout_duration_seconds = lockout_duration_seconds;
        policy
    }

    #[test]
    fn the_account_limit_follows_the_realm_policy() {
        let limiter = PasswordAttemptLimiter::new();
        let policy = policy(2, 300);
        assert!(limiter.admit("corp", "alice@example.com", &policy));
        assert!(limiter.admit("corp", "alice@example.com", &policy));
        assert!(!limiter.admit("corp", "alice@example.com", &policy));
        // Another address of the same realm keeps its own count.
        assert!(limiter.admit("corp", "bob@example.com", &policy));
    }

    #[test]
    fn the_window_follows_the_realm_policy() {
        let limiter = PasswordAttemptLimiter::new();
        // A window that has passed at once starts the count over.
        assert!(limiter.admit("corp", "alice@example.com", &policy(1, 0)));
        assert!(limiter.admit("corp", "alice@example.com", &policy(1, 0)));
        // A window that has not passed counts the requests.
        assert!(limiter.admit("corp", "bob@example.com", &policy(1, 300)));
        assert!(!limiter.admit("corp", "bob@example.com", &policy(1, 300)));
    }

    #[test]
    fn the_realms_keep_their_own_counts() {
        let limiter = PasswordAttemptLimiter::new();
        let policy = policy(1, 300);
        assert!(limiter.admit("corp", "alice@example.com", &policy));
        assert!(!limiter.admit("corp", "alice@example.com", &policy));
        // The same address in another realm is another account.
        assert!(limiter.admit("other", "alice@example.com", &policy));
        assert!(!limiter.admit("other", "alice@example.com", &policy));
    }

    #[test]
    fn a_successful_login_clears_the_account_count() {
        let limiter = PasswordAttemptLimiter::new();
        let policy = policy(1, 300);
        assert!(limiter.admit("corp", "alice@example.com", &policy));
        limiter.reset_user("corp", "alice@example.com");
        // The account's count starts over after a successful login.
        assert!(limiter.admit("corp", "alice@example.com", &policy));
    }

    #[test]
    fn resetting_an_account_does_not_reset_the_realm() {
        let limiter = PasswordAttemptLimiter::new();
        let policy = policy(1000, 300);
        for index in 0..100 {
            assert!(limiter.admit("corp", &format!("user-{index}@example.com"), &policy));
        }
        limiter.reset_user("corp", "user-0@example.com");
        assert!(!limiter.admit("corp", "another@example.com", &policy));
    }

    #[test]
    fn the_realm_bounds_the_admissions_it_accepts() {
        let limiter = PasswordAttemptLimiter::new();
        let policy = policy(1000, 300);
        for _ in 0..RateLimitConfig::default().max_per_tenant {
            assert!(limiter.admit("corp", "alice@example.com", &policy));
        }
        // The realm's own count is spent, so another address is refused
        // as well.
        assert!(!limiter.admit("corp", "bob@example.com", &policy));
        // Another realm has its own count.
        assert!(limiter.admit("other", "bob@example.com", &policy));
    }

    #[test]
    fn concurrent_admissions_are_counted_once_each() {
        let limiter = Arc::new(PasswordAttemptLimiter::new());
        let policy = policy(5, 300);
        let admitted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..20 {
                let limiter = Arc::clone(&limiter);
                let admitted = &admitted;
                scope.spawn(move || {
                    if limiter.admit("corp", "alice@example.com", &policy) {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(admitted.load(Ordering::SeqCst), 5);
    }
}
