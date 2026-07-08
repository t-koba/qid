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
use std::sync::{Arc, Mutex};
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
    fn set_if_absent(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) -> QidResult<bool>;
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

    fn set_if_absent(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) -> QidResult<bool> {
        let mut store = self.store.lock().map_err(|e| QidError::Internal {
            message: format!("memory cache lock poisoned: {e}"),
        })?;
        let now = Instant::now();
        if let Some(entry) = store.get(key)
            && entry.expires_at > now
        {
            return Ok(false);
        }
        store.insert(
            key.to_string(),
            CacheEntry {
                value,
                expires_at: now + Duration::from_secs(ttl_seconds),
            },
        );
        Ok(true)
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

        fn set_if_absent(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl_seconds: u64,
        ) -> crate::error::QidResult<bool> {
            let mut conn = self
                .conn
                .lock()
                .map_err(|e| crate::error::QidError::Internal {
                    message: format!("redis cache lock poisoned: {e}"),
                })?;
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("NX")
                .arg("EX")
                .arg(ttl_seconds)
                .query::<Option<String>>(&mut *conn)
                .map(|response| response.as_deref() == Some("OK"))
                .map_err(|e| crate::error::QidError::Internal {
                    message: format!("redis cache SET NX EX failed: {e}"),
                })
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

/// Injected DPoP state for replay detection.
pub struct DpopState {
    cache: Arc<dyn SharedCache>,
    replay_namespace: String,
    nonce_namespace: String,
}

impl DpopState {
    pub fn new() -> Self {
        Self::with_cache(Arc::new(MemoryCache::new()))
    }

    pub fn with_cache(cache: Arc<dyn SharedCache>) -> Self {
        Self::with_namespaces(cache, "dpop:jti", "dpop:nonce")
    }

    pub fn assertion_replay(cache: Arc<dyn SharedCache>) -> Self {
        Self::with_namespaces(cache, "assertion:jti", "assertion:nonce")
    }

    fn with_namespaces(
        cache: Arc<dyn SharedCache>,
        replay_namespace: &str,
        nonce_namespace: &str,
    ) -> Self {
        Self {
            cache,
            replay_namespace: replay_namespace.to_string(),
            nonce_namespace: nonce_namespace.to_string(),
        }
    }

    /// Record a short-lived JTI if it has not been used before.
    pub fn record_jti(&self, jti: &str, iat: u64, now: u64) -> QidResult<()> {
        let expires_at = iat
            .saturating_add(JTI_CACHE_TTL_SECS)
            .max(now.saturating_add(JTI_CACHE_TTL_SECS));
        let inserted = self.cache.set_if_absent(
            &format!("{}:{jti}", self.replay_namespace),
            b"1".to_vec(),
            expires_at.saturating_sub(now).max(1),
        )?;
        if !inserted {
            return Err(QidError::BadRequest {
                message: "DPoP proof jti already used (replay detected)".to_string(),
            });
        }
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
        let inserted = self.cache.set_if_absent(
            &format!("{}:{key}", self.replay_namespace),
            b"1".to_vec(),
            expires_at.saturating_sub(now).max(1),
        )?;
        if !inserted {
            return Err(QidError::BadRequest {
                message: replay_message.to_string(),
            });
        }
        Ok(())
    }

    /// Issue a short-lived DPoP nonce for a client retry.
    pub fn issue_nonce(&self, now: u64) -> QidResult<String> {
        let nonce = format!("dpop_nonce_{}", ulid::Ulid::new());
        self.cache.set(
            &format!("{}:{nonce}", self.nonce_namespace),
            now.to_string().into_bytes(),
            NONCE_CACHE_TTL_SECS,
        );
        Ok(nonce)
    }

    /// Consume a DPoP nonce exactly once.
    pub fn consume_nonce(&self, nonce: &str, now: u64) -> QidResult<()> {
        let key = format!("{}:{nonce}", self.nonce_namespace);
        let Some(issued_at_bytes) = self.cache.get(&key) else {
            return Err(QidError::BadRequest {
                message: "DPoP proof nonce is missing, expired, or already used".to_string(),
            });
        };
        self.cache.delete(&key);
        let issued_at = String::from_utf8(issued_at_bytes)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| QidError::Internal {
                message: "DPoP nonce cache entry is invalid".to_string(),
            })?;
        if now.saturating_sub(issued_at) >= NONCE_CACHE_TTL_SECS {
            return Err(QidError::BadRequest {
                message: "DPoP proof nonce is expired".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for DpopState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DpopState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopState")
            .field("replay_namespace", &self.replay_namespace)
            .field("nonce_namespace", &self.nonce_namespace)
            .finish_non_exhaustive()
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
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
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

    pub fn delete(&mut self, key: &str) {
        self.entries.pop(key);
    }
}

#[cfg(test)]
mod tests {
    use super::{DpopState, MemoryCache};
    use std::sync::Arc;

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

    #[test]
    fn replay_cache_is_shared_across_state_instances() {
        let cache = Arc::new(MemoryCache::new());
        let first = DpopState::with_cache(cache.clone());
        let second = DpopState::with_cache(cache);

        first.record_jti("shared-jti", 1_000, 1_000).unwrap();
        let replay = second.record_jti("shared-jti", 1_000, 1_001).unwrap_err();

        assert!(replay.message().contains("already used"));
    }
}
