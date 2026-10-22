//! In-memory fixed-window rate limiter for authentication endpoints.

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

/// The limit and the window one axis applies.
///
/// The axes of a limiter need not share a window: an account's axis may
/// follow the realm's lockout window while the realm's own axis follows
/// the deployment's window.
#[derive(Debug, Clone, Copy)]
pub struct AxisLimit {
    /// Requests the axis accepts within its window.
    pub max: u32,
    /// Length of the axis's window in seconds.
    pub window_seconds: u64,
}

impl AxisLimit {
    pub fn new(max: u32, window_seconds: u64) -> Self {
        Self {
            max,
            window_seconds,
        }
    }
}

#[derive(Debug)]
struct WindowEntry {
    count: u32,
    window_start: u64,
    /// The window the count was counted in.
    window_seconds: u64,
}

#[derive(Debug)]
struct RateLimitState {
    entries: HashMap<RateLimitKey, WindowEntry>,
    /// A lower bound on the next expiry. Stale values only cause one extra
    /// prune; the map recomputes it whenever pruning is needed.
    next_expiry: u64,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next_expiry: u64::MAX,
        }
    }
}

impl RateLimitState {
    fn prune_expired(&mut self, now: u64) {
        self.entries
            .retain(|_, entry| now < entry.window_start.saturating_add(entry.window_seconds));
        self.next_expiry = self
            .entries
            .values()
            .map(|entry| entry.window_start.saturating_add(entry.window_seconds))
            .min()
            .unwrap_or(u64::MAX);
    }
}

/// What one axis decided about a request.
#[derive(Debug, Clone, Copy)]
enum AxisState {
    /// The axis has room; the count once the request counts.
    Admitted(u32),
    /// The axis has no room.
    Denied,
}

pub struct RateLimiter {
    inner: Mutex<RateLimitState>,
    config: RateLimitConfig,
    max_entries: usize,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RateLimiter")
            .field("config", &self.config)
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self::with_capacity(config, MAX_RATE_LIMIT_ENTRIES)
    }

    /// A limiter that tracks at most `max_entries` keys.
    ///
    /// The bound keeps a caller that invents key names from growing the
    /// map without limit. Once the bound is reached, a key that is not
    /// tracked yet is refused rather than admitted by evicting a counter
    /// that is still counting.
    fn with_capacity(config: RateLimitConfig, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(RateLimitState::default()),
            config,
            max_entries,
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
        let Ok(mut state) = self.inner.lock() else {
            tracing::error!("rate limiter lock poisoned; denying request");
            metrics::counter!("qid_rate_limit_lock_failures_total").increment(1);
            return false;
        };

        if let Some(uid) = user_id
            && !self.check_key(
                &mut state,
                RateLimitKey::User(uid.to_string()),
                now,
                self.config.max_per_user,
                self.config.window_seconds,
            )
        {
            return false;
        }

        if let Some(addr) = ip
            && !self.check_key(
                &mut state,
                RateLimitKey::Ip(addr.to_string()),
                now,
                self.config.max_per_ip,
                self.config.window_seconds,
            )
        {
            return false;
        }

        if let Some(did) = device_id
            && !self.check_key(
                &mut state,
                RateLimitKey::Device(did.to_string()),
                now,
                self.config.max_per_device,
                self.config.window_seconds,
            )
        {
            return false;
        }

        if let Some(asn_str) = asn
            && !self.check_key(
                &mut state,
                RateLimitKey::Asn(asn_str.to_string()),
                now,
                self.config.max_per_asn,
                self.config.window_seconds,
            )
        {
            return false;
        }

        if let Some(tid) = tenant
            && !self.check_key(
                &mut state,
                RateLimitKey::Tenant(tid.to_string()),
                now,
                self.config.max_per_tenant,
                self.config.window_seconds,
            )
        {
            return false;
        }

        true
    }

    /// Admit a request against an account axis and a tenant axis, each
    /// with its own limit and its own window.
    ///
    /// The two axes are decided together: either both count the request
    /// or neither does, so a request the tenant axis refuses does not
    /// spend the account's count, and a request that is admitted counts
    /// once on each axis.
    pub fn check_user_tenant(
        &self,
        user: Option<&str>,
        user_limit: AxisLimit,
        tenant: Option<&str>,
        tenant_limit: AxisLimit,
    ) -> bool {
        let now = now_seconds();
        let Ok(mut state) = self.inner.lock() else {
            tracing::error!("rate limiter lock poisoned; denying request");
            metrics::counter!("qid_rate_limit_lock_failures_total").increment(1);
            return false;
        };

        let mut plan: Vec<(RateLimitKey, AxisLimit, u32)> = Vec::new();
        let axes = [
            user.map(|value| (RateLimitKey::User(value.to_string()), user_limit)),
            tenant.map(|value| (RateLimitKey::Tenant(value.to_string()), tenant_limit)),
        ];
        for (key, limit) in axes.into_iter().flatten() {
            match Self::axis_state(&state.entries, &key, now, limit) {
                AxisState::Denied => return false,
                AxisState::Admitted(count) => plan.push((key, limit, count)),
            }
        }
        // Every key the plan needs must fit before any of them counts.
        if !self.reserve_plan(&mut state, &plan, now) {
            return false;
        }
        for (key, limit, count) in plan {
            Self::commit(&mut state, key, now, limit, count);
        }
        true
    }

    /// Count one request on one axis, if the axis has room for it.
    fn check_key(
        &self,
        state: &mut RateLimitState,
        key: RateLimitKey,
        now: u64,
        max: u32,
        window_seconds: u64,
    ) -> bool {
        let limit = AxisLimit {
            max,
            window_seconds,
        };
        let AxisState::Admitted(count) = Self::axis_state(&state.entries, &key, now, limit) else {
            return false;
        };
        if !self.reserve_key(state, &key, now) {
            return false;
        }
        Self::commit(state, key, now, limit, count);
        true
    }

    /// The count of one axis once a request counts, or a refusal.
    fn axis_state(
        map: &HashMap<RateLimitKey, WindowEntry>,
        key: &RateLimitKey,
        now: u64,
        limit: AxisLimit,
    ) -> AxisState {
        let count = match map.get(key) {
            Some(entry) if now < entry.window_start.saturating_add(limit.window_seconds) => {
                entry.count
            }
            _ => 0,
        };
        if count >= limit.max {
            AxisState::Denied
        } else {
            AxisState::Admitted(count.saturating_add(1))
        }
    }

    /// Make room for a key that is not tracked yet.
    ///
    /// Expired counters are pruned only when their earliest possible expiry
    /// has arrived, avoiding a full-map scan for every refused new key.
    /// Live counters are never evicted to admit a new name.
    fn reserve_key(&self, state: &mut RateLimitState, key: &RateLimitKey, now: u64) -> bool {
        if state.entries.contains_key(key) || state.entries.len() < self.max_entries {
            return true;
        }
        if now >= state.next_expiry {
            state.prune_expired(now);
        }
        if state.entries.contains_key(key) || state.entries.len() < self.max_entries {
            return true;
        }
        self.deny_at_capacity();
        false
    }

    /// Reserve all keys in a multi-axis admission before counting any of them.
    fn reserve_plan(
        &self,
        state: &mut RateLimitState,
        plan: &[(RateLimitKey, AxisLimit, u32)],
        now: u64,
    ) -> bool {
        let needed = plan
            .iter()
            .filter(|(key, _, _)| !state.entries.contains_key(key))
            .count();
        if state.entries.len().saturating_add(needed) > self.max_entries && now >= state.next_expiry
        {
            state.prune_expired(now);
        }
        let needed = plan
            .iter()
            .filter(|(key, _, _)| !state.entries.contains_key(key))
            .count();
        if state.entries.len().saturating_add(needed) > self.max_entries {
            self.deny_at_capacity();
            return false;
        }
        true
    }

    fn deny_at_capacity(&self) {
        tracing::warn!("rate limiter is at capacity; refusing a new key");
        metrics::counter!("qid_rate_limit_capacity_denied_total").increment(1);
    }

    /// Count one request on one axis.
    fn commit(
        state: &mut RateLimitState,
        key: RateLimitKey,
        now: u64,
        limit: AxisLimit,
        count: u32,
    ) {
        let entry = state.entries.entry(key).or_insert(WindowEntry {
            count: 0,
            window_start: now,
            window_seconds: limit.window_seconds,
        });
        if now >= entry.window_start.saturating_add(limit.window_seconds) {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.window_seconds = limit.window_seconds;
        entry.count = count;
        state.next_expiry = state
            .next_expiry
            .min(now.saturating_add(limit.window_seconds));
    }

    /// Give back one admission a request spent on an axis.
    ///
    /// A request that succeeded spends no room of its axes, so the count
    /// of the axis falls by one. An axis whose count reaches zero loses
    /// its entry, and an axis whose window has passed keeps the count it
    /// had.
    fn release_axis(&self, key: RateLimitKey) {
        let now = now_seconds();
        let Ok(mut state) = self.inner.lock() else {
            tracing::error!("rate limiter lock poisoned; keeping the count");
            return;
        };
        let Some(entry) = state.entries.get(&key) else {
            return;
        };
        if now >= entry.window_start.saturating_add(entry.window_seconds) {
            return;
        }
        if entry.count <= 1 {
            state.entries.remove(&key);
        } else if let Some(entry) = state.entries.get_mut(&key) {
            entry.count -= 1;
        }
    }

    /// Give back one admission a user axis spent.
    pub fn release_user(&self, user_id: &str) {
        self.release_axis(RateLimitKey::User(user_id.to_string()));
    }

    /// Give back one admission a tenant axis spent.
    pub fn release_tenant(&self, tenant: &str) {
        self.release_axis(RateLimitKey::Tenant(tenant.to_string()));
    }

    /// Reset rate limit counters for a specific user (e.g., after successful login).
    pub fn reset_user(&self, user_id: &str) {
        if let Ok(mut state) = self.inner.lock() {
            state
                .entries
                .remove(&RateLimitKey::User(user_id.to_string()));
        }
    }

    /// Clear all entries matching a predicate.
    pub fn clear_matching(&self, pred: fn(&RateLimitKey) -> bool) {
        if let Ok(mut state) = self.inner.lock() {
            state.entries.retain(|k, _| !pred(k));
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

    #[test]
    fn the_axes_keep_their_own_windows() {
        let limiter = RateLimiter::new(make_config());
        let account = AxisLimit::new(2, 60);
        let tenant = AxisLimit::new(10, 300);
        assert!(limiter.check_user_tenant(Some("usr-1"), account, Some("t"), tenant));
        assert!(limiter.check_user_tenant(Some("usr-1"), account, Some("t"), tenant));
        assert!(!limiter.check_user_tenant(Some("usr-1"), account, Some("t"), tenant));
        // A window that has passed starts the count of that axis over.
        assert!(limiter.check_user_tenant(Some("usr-1"), AxisLimit::new(2, 0), Some("t"), tenant));
    }

    #[test]
    fn a_refused_tenant_does_not_spend_the_account_count() {
        let limiter = RateLimiter::new(make_config());
        let account = AxisLimit::new(2, 60);
        let tenant = AxisLimit::new(1, 60);
        assert!(limiter.check_user_tenant(Some("usr-1"), account, Some("t"), tenant));
        // The tenant axis has no room, so the request is refused and the
        // account's own count is not spent by it.
        assert!(!limiter.check_user_tenant(Some("usr-1"), account, Some("t"), tenant));
        // The account's count is still the one the admitted request left.
        assert!(limiter.check_user_tenant(Some("usr-1"), account, None, tenant));
        assert!(!limiter.check_user_tenant(Some("usr-1"), account, None, tenant));
    }

    #[test]
    fn a_new_key_is_refused_at_capacity_and_the_live_counters_survive() {
        let limiter = RateLimiter::with_capacity(make_config(), 6);
        let account = AxisLimit::new(10, 60);
        let spent = AxisLimit::new(2, 60);
        let roomy = AxisLimit::new(100, 60);
        assert!(limiter.check_user_tenant(Some("u1"), account, Some("t"), spent));
        assert!(limiter.check_user_tenant(Some("u2"), account, Some("t"), spent));
        // The tenant's own counter is spent.
        assert!(!limiter.check_user_tenant(Some("u3"), account, Some("t"), spent));
        // Another tenant's names fill the bound without evicting a counter
        // that is still counting.
        assert!(limiter.check_user_tenant(Some("u4"), account, Some("t2"), roomy));
        assert!(limiter.check_user_tenant(Some("u5"), account, Some("t2"), roomy));
        // The bound is reached, so a name that is not tracked yet is
        // refused rather than admitted by evicting a live counter.
        assert!(!limiter.check_user_tenant(Some("u6"), account, Some("t2"), roomy));
        // The counters that are still live survived the churn.
        assert!(!limiter.check_user_tenant(Some("u1"), account, Some("t"), spent));
        assert!(limiter.check_user_tenant(Some("u1"), account, Some("t2"), roomy));
    }

    #[test]
    fn a_multi_axis_admission_never_exceeds_capacity() {
        let limiter = RateLimiter::with_capacity(make_config(), 1);
        let account = AxisLimit::new(10, 60);
        let tenant = AxisLimit::new(10, 60);
        assert!(!limiter.check_user_tenant(Some("u"), account, Some("t"), tenant));
        assert_eq!(
            limiter
                .inner
                .lock()
                .expect("rate limiter lock")
                .entries
                .len(),
            0
        );
    }

    #[test]
    fn a_counter_whose_window_passed_frees_its_room() {
        let limiter = RateLimiter::with_capacity(make_config(), 2);
        let expired = AxisLimit::new(10, 0);
        assert!(limiter.check_user_tenant(Some("u1"), expired, None, expired));
        assert!(limiter.check_user_tenant(Some("u2"), expired, None, expired));
        assert!(limiter.check_user_tenant(Some("u3"), expired, None, expired));
    }
}
