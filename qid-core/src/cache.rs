//! Cache types shared across protocol crates.
//!
//! Contains the in-memory cache primitives for DPoP state, policy
//! decisions, and sessions that were previously spread across `dpop.rs`
//! and `state.rs`.

use crate::error::{QidError, QidResult};
use lru::LruCache;
use serde_json::Value;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Generic cache
// ---------------------------------------------------------------------------

/// A cache entry with TTL.
#[derive(Debug, Clone)]
struct CacheEntry {
    value: Vec<u8>,
    expires_at: Instant,
}

/// Generic key-value cache with TTL support.
pub trait SharedCache: Send + Sync {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64);
    fn delete(&self, key: &str);
    fn exists(&self, key: &str) -> bool;
}

/// In-memory cache backed by a HashMap with TTL-based eviction.
pub struct MemoryCache {
    store: Mutex<HashMap<String, CacheEntry>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedCache for MemoryCache {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = store.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.value.clone());
            }
            store.remove(key);
        }
        None
    }

    fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.insert(
            key.to_string(),
            CacheEntry {
                value,
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
            },
        );
    }

    fn delete(&self, key: &str) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.remove(key);
    }

    fn exists(&self, key: &str) -> bool {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.contains_key(key)
    }
}

/// Global cache instance for in-process shared state.
pub static GLOBAL_CACHE: std::sync::LazyLock<MemoryCache> =
    std::sync::LazyLock::new(MemoryCache::new);

#[cfg(feature = "redis-cache")]
pub mod redis_cache {
    //! Redis-backed SharedCache implementation.
    use super::SharedCache;
    use redis::{Client, Commands, Connection, RedisError};
    use std::sync::Mutex;

    /// Redis-backed cache implementing `SharedCache`.
    pub struct RedisCache {
        conn: Mutex<Connection>,
    }

    impl RedisCache {
        pub fn new(redis_url: &str) -> Result<Self, RedisError> {
            let client = Client::open(redis_url)?;
            let conn = client.get_connection()?;
            Ok(Self {
                conn: Mutex::new(conn),
            })
        }
    }

    impl SharedCache for RedisCache {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.get(key).ok()
        }

        fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
            let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let _: Result<(), _> = conn.set_ex(key, value, ttl_seconds);
        }

        fn delete(&self, key: &str) {
            let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let _: Result<(), _> = conn.del(key);
        }

        fn exists(&self, key: &str) -> bool {
            let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.exists(key).unwrap_or(false)
        }
    }
}

// ---------------------------------------------------------------------------
// DPoP state (was in dpop.rs)
// ---------------------------------------------------------------------------

/// TTL in seconds for cached jti replay entries.
const JTI_CACHE_TTL_SECS: u64 = 60;
const NONCE_CACHE_TTL_SECS: u64 = 300;
const MAX_CACHE_ENTRIES: usize = 100_000;

/// Injected DPoP state for replay detection.
#[derive(Debug, Default)]
pub struct DpopState {
    /// Maps replay key -> expiration epoch seconds.
    used_jtis: Mutex<HashMap<String, u64>>,
    /// Maps nonce -> issue timestamp in seconds.
    nonces: Mutex<HashMap<String, u64>>,
}

fn evict_excess(cache: &mut HashMap<String, u64>, max: usize) {
    if cache.len() <= max {
        return;
    }
    let mut excess = cache.len().saturating_sub(max);
    cache.retain(|_, _| {
        if excess > 0 {
            excess -= 1;
            false
        } else {
            true
        }
    });
}

impl DpopState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a short-lived JTI if it has not been used before.
    pub fn record_jti(&self, jti: &str, iat: u64, now: u64) -> QidResult<()> {
        let mut cache = self.used_jtis.lock().map_err(|e| QidError::Internal {
            message: format!("dpop jti cache lock poisoned: {e}"),
        })?;

        cache.retain(|_, expires_at| *expires_at > now);
        evict_excess(&mut cache, MAX_CACHE_ENTRIES);

        if cache.contains_key(jti) {
            return Err(QidError::BadRequest {
                message: "DPoP proof jti already used (replay detected)".to_string(),
            });
        }

        let expires_at = iat
            .saturating_add(JTI_CACHE_TTL_SECS)
            .max(now.saturating_add(JTI_CACHE_TTL_SECS));
        cache.insert(jti.to_string(), expires_at);
        Ok(())
    }

    /// Record a replay key until its protocol expiry time.
    pub fn record_replay_key(
        &self,
        key: &str,
        expires_at: u64,
        now: u64,
        replay_message: &str,
    ) -> QidResult<()> {
        let mut cache = self.used_jtis.lock().map_err(|e| QidError::Internal {
            message: format!("assertion replay cache lock poisoned: {e}"),
        })?;

        cache.retain(|_, stored_expires_at| *stored_expires_at > now);
        evict_excess(&mut cache, MAX_CACHE_ENTRIES);

        if cache.contains_key(key) {
            return Err(QidError::BadRequest {
                message: replay_message.to_string(),
            });
        }

        cache.insert(key.to_string(), expires_at);
        Ok(())
    }

    /// Issue a short-lived DPoP nonce for a client retry.
    pub fn issue_nonce(&self, now: u64) -> QidResult<String> {
        let nonce = format!("dpop_nonce_{}", ulid::Ulid::new());
        let mut cache = self.nonces.lock().map_err(|e| QidError::Internal {
            message: format!("dpop nonce cache lock poisoned: {e}"),
        })?;
        cache.retain(|_, issued_at| now.saturating_sub(*issued_at) < NONCE_CACHE_TTL_SECS);
        evict_excess(&mut cache, MAX_CACHE_ENTRIES);
        cache.insert(nonce.clone(), now);
        Ok(nonce)
    }

    /// Consume a DPoP nonce exactly once.
    pub fn consume_nonce(&self, nonce: &str, now: u64) -> QidResult<()> {
        let mut cache = self.nonces.lock().map_err(|e| QidError::Internal {
            message: format!("dpop nonce cache lock poisoned: {e}"),
        })?;
        cache.retain(|_, issued_at| now.saturating_sub(*issued_at) < NONCE_CACHE_TTL_SECS);
        evict_excess(&mut cache, MAX_CACHE_ENTRIES);
        let Some(issued_at) = cache.remove(nonce) else {
            return Err(QidError::BadRequest {
                message: "DPoP proof nonce is missing, expired, or already used".to_string(),
            });
        };
        if now.saturating_sub(issued_at) >= NONCE_CACHE_TTL_SECS {
            return Err(QidError::BadRequest {
                message: "DPoP proof nonce is expired".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Decision cache (was in state.rs)
// ---------------------------------------------------------------------------

/// Decision cache entry with expiry.
#[derive(Debug, Clone)]
pub struct DecisionCacheEntry {
    pub response_json: Value,
    pub expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Session cache (was in state.rs)
// ---------------------------------------------------------------------------

/// Session cache with LRU capacity limit and TTL.
#[derive(Debug)]
pub struct SessionCache {
    entries: LruCache<String, SessionCacheEntry>,
}

#[derive(Debug, Clone)]
struct SessionCacheEntry {
    value: Vec<u8>,
    expires_at: Instant,
}

impl SessionCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            entries: LruCache::new(cap),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        let now = Instant::now();
        if self.entries.peek(key).is_some_and(|e| e.expires_at <= now) {
            self.entries.pop(key);
            return None;
        }
        self.entries.get(key).map(|e| e.value.clone())
    }

    pub fn put(&mut self, key: String, value: Vec<u8>, ttl_seconds: u64) {
        self.entries.put(
            key,
            SessionCacheEntry {
                value,
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::DpopState;

    #[test]
    fn replay_key_is_single_use_until_expiry() {
        let state = DpopState::new();
        state
            .record_replay_key("saml:resp:assert", 1_100, 1_000, "replay")
            .unwrap();
        let replay = state
            .record_replay_key("saml:resp:assert", 1_100, 1_001, "replay")
            .unwrap_err();
        assert!(replay.message().contains("replay"));
        state
            .record_replay_key("saml:resp:assert", 1_300, 1_101, "replay")
            .unwrap();
    }

    #[test]
    fn replay_key_recording_does_not_evict_live_jti_entries() {
        let state = DpopState::new();
        state.record_jti("jwt-jti", 1_000, 1_000).unwrap();
        state
            .record_replay_key("saml:resp:assert", 1_300, 1_001, "saml replay")
            .unwrap();
        let replay = state.record_jti("jwt-jti", 1_000, 1_002).unwrap_err();
        assert!(replay.message().contains("already used"));
    }
}
