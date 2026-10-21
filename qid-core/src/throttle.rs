//! A bounded budget of failures a key may spend within a window.
//!
//! The mechanism holds no policy: the caller states the limit and the
//! window length it enforces, so the numbers a deployment applies stay in
//! its own configuration.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of keys tracked at once.
const MAX_BUDGET_ENTRIES: usize = 1024;

/// The failures a key has spent in the current window.
#[derive(Debug, Clone, Copy)]
struct WindowEntry {
    count: u32,
    window_start: u64,
}

/// A budget of failures per key within a window.
///
/// The budget lives in the process that enforces it, so a deployment
/// with several instances applies the limit to each of them.
#[derive(Debug, Default)]
pub struct FailureBudget {
    inner: Mutex<HashMap<String, WindowEntry>>,
}

impl FailureBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the key has spent its budget in the current window.
    ///
    /// A poisoned lock counts as a spent budget: the failure of the
    /// counter must not open the limit the counter enforces.
    pub fn exhausted(&self, key: &str, limit: u32, window_seconds: u64) -> bool {
        let now = now_seconds();
        let Ok(map) = self.inner.lock() else {
            tracing::error!("failure budget lock poisoned; treating the budget as spent");
            return true;
        };
        match map.get(key) {
            Some(entry) if now < entry.window_start.saturating_add(window_seconds) => {
                entry.count >= limit
            }
            _ => false,
        }
    }

    /// Record one failure against the key's budget.
    ///
    /// Returns whether the budget is spent once this failure is counted.
    pub fn record_failure(&self, key: &str, limit: u32, window_seconds: u64) -> bool {
        let now = now_seconds();
        let Ok(mut map) = self.inner.lock() else {
            tracing::error!("failure budget lock poisoned; treating the budget as spent");
            return true;
        };
        let entry = map.entry(key.to_string()).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });
        if now >= entry.window_start.saturating_add(window_seconds) {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count = entry.count.saturating_add(1);
        let spent = entry.count >= limit;
        evict_oldest(&mut map);
        spent
    }
}

/// Drop the oldest entries once the tracked keys exceed the bound, so a
/// caller that invents key names cannot grow the map without limit.
fn evict_oldest(map: &mut HashMap<String, WindowEntry>) {
    let excess = map.len().saturating_sub(MAX_BUDGET_ENTRIES);
    if excess == 0 {
        return;
    }
    let mut oldest: Vec<(u64, String)> = map
        .iter()
        .map(|(key, entry)| (entry.window_start, key.clone()))
        .collect();
    oldest.sort_by_key(|(window_start, _)| *window_start);
    for (_, key) in oldest.into_iter().take(excess) {
        map.remove(&key);
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

    #[test]
    fn a_key_spends_its_budget_after_the_limit() {
        let budget = FailureBudget::new();
        assert!(!budget.exhausted("realm", 2, 60));
        assert!(!budget.record_failure("realm", 2, 60));
        assert!(!budget.exhausted("realm", 2, 60));
        assert!(budget.record_failure("realm", 2, 60));
        assert!(budget.exhausted("realm", 2, 60));
    }

    #[test]
    fn a_failure_in_one_key_does_not_spend_another_keys_budget() {
        let budget = FailureBudget::new();
        budget.record_failure("realm-a", 1, 60);
        assert!(budget.exhausted("realm-a", 1, 60));
        assert!(!budget.exhausted("realm-b", 1, 60));
    }

    #[test]
    fn a_window_that_has_passed_starts_over() {
        let budget = FailureBudget::new();
        assert!(budget.record_failure("realm", 1, 60));
        assert!(budget.exhausted("realm", 1, 60));
        // A window that ends at once leaves the key with a fresh budget.
        assert!(!budget.exhausted("realm", 1, 0));
    }

    #[test]
    fn the_tracked_keys_stay_bounded() {
        let budget = FailureBudget::new();
        for index in 0..(MAX_BUDGET_ENTRIES + 10) {
            budget.record_failure(&format!("realm-{index}"), 10, 60);
        }
        let tracked = budget.inner.lock().expect("failure budget lock").len();
        assert!(tracked <= MAX_BUDGET_ENTRIES);
    }
}
