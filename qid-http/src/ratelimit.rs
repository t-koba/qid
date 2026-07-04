//! In-memory sliding-window rate limiter for authentication endpoints.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of tracked rate-limit windows across all keys.
const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;

/// Multi-axis rate limit counter key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum RateLimitKey {
    User(String),
    Ip(String),
    Device(String),
    Asn(String),
    Tenant(String),
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max attempts per user within the window.
    pub max_per_user: u32,
    /// Max attempts per IP within the window.
    pub max_per_ip: u32,
    /// Max attempts per ASN within the window.
    pub max_per_asn: u32,
    /// Max attempts per device within the window.
    pub max_per_device: u32,
    /// Max attempts per tenant within the window.
    pub max_per_tenant: u32,
    /// Window duration in seconds.
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_user: 5,
            max_per_ip: 20,
            max_per_asn: 50,
            max_per_device: 10,
            max_per_tenant: 100,
            window_seconds: 300,
        }
    }
}

#[derive(Debug)]
struct WindowEntry {
    count: u32,
    window_start: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<HashMap<RateLimitKey, WindowEntry>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Check if a request should be rate limited.
    /// Returns true if the request is allowed, false if rate limited.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        user_id: Option<&str>,
        ip: Option<&str>,
        device_id: Option<&str>,
        asn: Option<&str>,
        tenant: Option<&str>,
    ) -> bool {
        let now = now_seconds();
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };

        if let Some(uid) = user_id {
            let key = RateLimitKey::User(uid.to_string());
            if !self.check_key(&mut map, key, now, self.config.max_per_user) {
                return false;
            }
        }

        if let Some(addr) = ip {
            let key = RateLimitKey::Ip(addr.to_string());
            if !self.check_key(&mut map, key, now, self.config.max_per_ip) {
                return false;
            }
        }

        if let Some(did) = device_id {
            let key = RateLimitKey::Device(did.to_string());
            if !self.check_key(&mut map, key, now, self.config.max_per_device) {
                return false;
            }
        }

        if let Some(asn_str) = asn {
            let key = RateLimitKey::Asn(asn_str.to_string());
            if !self.check_key(&mut map, key, now, self.config.max_per_asn) {
                return false;
            }
        }

        if let Some(tid) = tenant {
            let key = RateLimitKey::Tenant(tid.to_string());
            if !self.check_key(&mut map, key, now, self.config.max_per_tenant) {
                return false;
            }
        }

        true
    }

    fn check_key(
        &self,
        map: &mut HashMap<RateLimitKey, WindowEntry>,
        key: RateLimitKey,
        now: u64,
        max: u32,
    ) -> bool {
        let entry = map.entry(key).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now >= entry.window_start + self.config.window_seconds {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= max {
            return false;
        }

        entry.count += 1;

        if map.len() > MAX_RATE_LIMIT_ENTRIES {
            let mut excess = map.len().saturating_sub(MAX_RATE_LIMIT_ENTRIES);
            map.retain(|_, _| {
                if excess > 0 {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
        }

        true
    }

    /// Reset rate limit counters for a specific user (e.g., after successful login).
    pub fn reset_user(&self, user_id: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(&RateLimitKey::User(user_id.to_string()));
        }
    }

    /// Clear all entries matching a predicate.
    pub fn clear_matching(&self, pred: fn(&RateLimitKey) -> bool) {
        if let Ok(mut map) = self.inner.lock() {
            map.retain(|k, _| !pred(k));
        }
    }
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

    fn make_config() -> RateLimitConfig {
        RateLimitConfig {
            max_per_user: 3,
            max_per_ip: 10,
            max_per_asn: 50,
            max_per_device: 5,
            max_per_tenant: 100,
            window_seconds: 60,
        }
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(make_config());
        assert!(limiter.check(Some("usr-1"), Some("10.0.0.1"), None, None, None));
        assert!(limiter.check(Some("usr-1"), Some("10.0.0.1"), None, None, None));
        assert!(limiter.check(Some("usr-1"), Some("10.0.0.1"), None, None, None));
    }

    #[test]
    fn test_rate_limiter_blocks_excess_user_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_user: 2,
            ..make_config()
        });
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
        assert!(!limiter.check(Some("usr-1"), None, None, None, None));
        // Different user should still be allowed
        assert!(limiter.check(Some("usr-2"), None, None, None, None));
    }

    #[test]
    fn test_rate_limiter_blocks_excess_ip_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_ip: 2,
            ..make_config()
        });
        assert!(limiter.check(Some("usr-1"), Some("10.0.0.1"), None, None, None));
        assert!(limiter.check(Some("usr-2"), Some("10.0.0.1"), None, None, None));
        assert!(!limiter.check(Some("usr-3"), Some("10.0.0.1"), None, None, None));
    }

    #[test]
    fn test_rate_limiter_blocks_excess_device_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_device: 2,
            ..make_config()
        });
        assert!(limiter.check(None, None, Some("dev-1"), None, None));
        assert!(limiter.check(None, None, Some("dev-1"), None, None));
        assert!(!limiter.check(None, None, Some("dev-1"), None, None));
        // Different device should still be allowed
        assert!(limiter.check(None, None, Some("dev-2"), None, None));
    }

    #[test]
    fn test_rate_limiter_blocks_excess_asn_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_asn: 3,
            ..make_config()
        });
        assert!(limiter.check(None, None, None, Some("AS1234"), None));
        assert!(limiter.check(None, Some("10.0.0.1"), None, Some("AS1234"), None));
        assert!(limiter.check(None, Some("10.0.0.2"), None, Some("AS1234"), None));
        assert!(!limiter.check(None, Some("10.0.0.3"), None, Some("AS1234"), None));
    }

    #[test]
    fn test_rate_limiter_blocks_excess_tenant_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_tenant: 2,
            ..make_config()
        });
        assert!(limiter.check(None, None, None, None, Some("tenant-a")));
        assert!(limiter.check(Some("usr-1"), None, None, None, Some("tenant-a")));
        assert!(!limiter.check(Some("usr-2"), None, None, None, Some("tenant-a")));
        // Different tenant should still be allowed
        assert!(limiter.check(None, None, None, None, Some("tenant-b")));
    }

    #[test]
    fn test_rate_limiter_reset_user() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_user: 1,
            ..make_config()
        });
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
        assert!(!limiter.check(Some("usr-1"), None, None, None, None));
        limiter.reset_user("usr-1");
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
    }

    #[test]
    fn test_rate_limiter_clear_matching() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_user: 1,
            ..make_config()
        });
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
        assert!(!limiter.check(Some("usr-1"), None, None, None, None));
        limiter.clear_matching(|k| matches!(k, RateLimitKey::User(u) if u == "usr-1"));
        assert!(limiter.check(Some("usr-1"), None, None, None, None));
    }
}
