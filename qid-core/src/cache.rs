//! Cache types shared across protocol crates.
//!
//! Contains the in-memory cache primitives for DPoP state, policy
//! decisions, and sessions that were previously spread across `dpop.rs`
//! and `state.rs`.

use crate::error::{QidError, QidResult};
use lru::LruCache;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
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
    /// Remove and return the live value for `key`, if any. The default splits
    /// get and delete; backends that must uphold single-use under concurrency
    /// override this with an atomic take.
    fn take(&self, key: &str) -> Option<Vec<u8>> {
        let value = self.get(key);
        if value.is_some() {
            self.delete(key);
        }
        value
    }
}

#[derive(Default)]
struct CacheStore {
    entries: HashMap<String, CacheEntry>,
    // Index deadlines so operations visit expired buckets, not all live entries.
    expirations: BTreeMap<Instant, HashSet<String>>,
    #[cfg(test)]
    reaper_visits: usize,
}

impl CacheStore {
    fn next_expiration(&self) -> Option<Instant> {
        self.expirations
            .first_key_value()
            .map(|(&expires_at, _)| expires_at)
    }

    fn insert(&mut self, key: String, entry: CacheEntry) {
        let _ = self.remove(&key);
        self.expirations
            .entry(entry.expires_at)
            .or_default()
            .insert(key.clone());
        self.entries.insert(key, entry);
    }

    fn remove(&mut self, key: &str) -> Option<CacheEntry> {
        let entry = self.entries.remove(key)?;
        let empty_bucket = self
            .expirations
            .get_mut(&entry.expires_at)
            .is_some_and(|keys| {
                keys.remove(key);
                keys.is_empty()
            });
        if empty_bucket {
            self.expirations.remove(&entry.expires_at);
        }
        Some(entry)
    }

    fn remove_expired(&mut self, now: Instant) {
        while let Some((&expires_at, _)) = self.expirations.first_key_value() {
            if expires_at > now {
                break;
            }
            let Some((_, keys)) = self.expirations.pop_first() else {
                break;
            };
            for key in keys {
                if self
                    .entries
                    .get(&key)
                    .is_some_and(|entry| entry.expires_at == expires_at)
                {
                    self.entries.remove(&key);
                }
            }
        }
    }
}

/// One process-wide expiry worker services only caches whose next deadline is due.
/// It keeps weak references and an ordered index, not a registry-wide scan.
type CacheStoreId = usize;

#[derive(Default)]
struct CacheExpiryState {
    stores: HashMap<CacheStoreId, Weak<Mutex<CacheStore>>>,
    deadlines: BTreeMap<Instant, HashSet<CacheStoreId>>,
    scheduled: HashMap<CacheStoreId, Instant>,
}

impl CacheExpiryState {
    fn next_deadline(&self) -> Option<Instant> {
        self.deadlines
            .first_key_value()
            .map(|(&deadline, _)| deadline)
    }

    fn remove_deadline(&mut self, id: CacheStoreId) -> bool {
        let Some(deadline) = self.scheduled.remove(&id) else {
            return false;
        };
        if let Some(ids) = self.deadlines.get_mut(&deadline) {
            ids.remove(&id);
            if ids.is_empty() {
                self.deadlines.remove(&deadline);
            }
        }
        true
    }

    fn set_deadline(&mut self, id: CacheStoreId, next: Option<Instant>) -> bool {
        if self.scheduled.get(&id).copied() == next {
            return false;
        }
        let earliest = self.next_deadline();
        self.remove_deadline(id);
        if let Some(deadline) = next {
            self.deadlines.entry(deadline).or_default().insert(id);
            self.scheduled.insert(id, deadline);
        }
        self.next_deadline() != earliest
    }
}

struct CacheExpiryReaper {
    state: Mutex<CacheExpiryState>,
    changed: Condvar,
}

fn cache_store_id(store: &Arc<Mutex<CacheStore>>) -> CacheStoreId {
    Arc::as_ptr(store) as CacheStoreId
}

impl CacheExpiryReaper {
    fn register(&self, store: &Arc<Mutex<CacheStore>>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .stores
            .insert(cache_store_id(store), Arc::downgrade(store));
    }

    fn update_deadline(&self, id: CacheStoreId, next: Option<Instant>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.stores.contains_key(&id) {
            return;
        }
        if state.set_deadline(id, next) {
            self.changed.notify_one();
        }
    }

    fn unregister(&self, store: &Arc<Mutex<CacheStore>>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let id = cache_store_id(store);
        state.stores.remove(&id);
        if state.set_deadline(id, None) {
            self.changed.notify_one();
        }
    }

    fn run(self: Arc<Self>) {
        loop {
            let due = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                loop {
                    if let Some((&deadline, _)) = state.deadlines.first_key_value() {
                        let timeout = deadline.saturating_duration_since(Instant::now());
                        if timeout.is_zero() {
                            let Some((_, ids)) = state.deadlines.pop_first() else {
                                continue;
                            };
                            for id in &ids {
                                state.scheduled.remove(id);
                            }
                            break ids;
                        }
                        let (next, _) = self
                            .changed
                            .wait_timeout(state, timeout)
                            .unwrap_or_else(|error| error.into_inner());
                        state = next;
                    } else {
                        state = self
                            .changed
                            .wait(state)
                            .unwrap_or_else(|error| error.into_inner());
                    }
                }
            };

            for id in due {
                let store = {
                    let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                    state.stores.get(&id).and_then(Weak::upgrade)
                };
                let Some(store) = store else {
                    let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                    state.stores.remove(&id);
                    continue;
                };
                let mut store = store.lock().unwrap_or_else(|error| error.into_inner());
                #[cfg(test)]
                {
                    store.reaper_visits += 1;
                }
                let now = Instant::now();
                let next = store.next_expiration();
                if next.is_none_or(|deadline| deadline > now) {
                    self.update_deadline(id, next);
                    continue;
                }
                store.remove_expired(now);
                self.update_deadline(id, store.next_expiration());
            }
        }
    }
}

fn cache_expiry_reaper() -> &'static CacheExpiryReaper {
    static REAPER: OnceLock<Arc<CacheExpiryReaper>> = OnceLock::new();
    REAPER
        .get_or_init(|| {
            let reaper = Arc::new(CacheExpiryReaper {
                state: Mutex::new(CacheExpiryState::default()),
                changed: Condvar::new(),
            });
            let worker = Arc::clone(&reaper);
            std::thread::spawn(move || worker.run());
            reaper
        })
        .as_ref()
}

/// In-memory cache backed by a HashMap and expiry-ordered TTL eviction.
pub struct MemoryCache {
    store: Arc<Mutex<CacheStore>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        let store = Arc::new(Mutex::new(CacheStore::default()));
        cache_expiry_reaper().register(&store);
        Self { store }
    }

    fn update_deadline_if_changed(&self, store: &CacheStore, previous: Option<Instant>) {
        let next = store.next_expiration();
        if previous != next {
            cache_expiry_reaper().update_deadline(cache_store_id(&self.store), next);
        }
    }
}

impl Drop for MemoryCache {
    fn drop(&mut self) {
        cache_expiry_reaper().unregister(&self.store);
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedCache for MemoryCache {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut store = self.store.lock().unwrap_or_else(|error| error.into_inner());
        let previous = store.next_expiration();
        store.remove_expired(Instant::now());
        let value = store.entries.get(key).map(|entry| entry.value.clone());
        self.update_deadline_if_changed(&store, previous);
        value
    }

    fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
        let mut store = self.store.lock().unwrap_or_else(|error| error.into_inner());
        let previous = store.next_expiration();
        let now = Instant::now();
        store.remove_expired(now);
        store.insert(
            key.to_string(),
            CacheEntry {
                value,
                expires_at: now + Duration::from_secs(ttl_seconds),
            },
        );
        self.update_deadline_if_changed(&store, previous);
    }

    fn set_if_absent(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) -> QidResult<bool> {
        let mut store = self.store.lock().map_err(|error| QidError::Internal {
            message: format!("memory cache lock poisoned: {error}"),
        })?;
        let previous = store.next_expiration();
        let now = Instant::now();
        store.remove_expired(now);
        if store.entries.contains_key(key) {
            self.update_deadline_if_changed(&store, previous);
            return Ok(false);
        }
        store.insert(
            key.to_string(),
            CacheEntry {
                value,
                expires_at: now + Duration::from_secs(ttl_seconds),
            },
        );
        self.update_deadline_if_changed(&store, previous);
        Ok(true)
    }

    fn delete(&self, key: &str) {
        let mut store = self.store.lock().unwrap_or_else(|error| error.into_inner());
        let previous = store.next_expiration();
        store.remove_expired(Instant::now());
        store.remove(key);
        self.update_deadline_if_changed(&store, previous);
    }

    fn take(&self, key: &str) -> Option<Vec<u8>> {
        let mut store = self.store.lock().unwrap_or_else(|error| error.into_inner());
        let previous = store.next_expiration();
        store.remove_expired(Instant::now());
        let value = store.remove(key).map(|entry| entry.value);
        self.update_deadline_if_changed(&store, previous);
        value
    }
}

#[cfg(feature = "redis-cache")]
pub mod redis_cache {
    //! Redis-backed SharedCache implementation.
    use super::SharedCache;
    use redis::{Client, Commands, Connection, RedisError, Value};
    use std::num::NonZeroU32;
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

        /// Opt-in local-AOF durability qualification; not used by `SharedCache`.
        ///
        /// Requires Redis >= 7.2 with AOF enabled. On this same locked connection,
        /// a new `SET NX EX` is followed by `WAITAOF 1 0 timeout_ms`. The caller
        /// chooses a finite, nonzero server wait in milliseconds (zero would
        /// mean forever in Redis). Only an exact local fsync acknowledgement
        /// succeeds; duplicates return false without waiting. Errors leave any
        /// inserted key in place, rejecting retries rather than undoing a write
        /// whose durability is uncertain. Error text never includes server data.
        ///
        /// This acknowledges one server's AOF, not replica/failover durability or
        /// a production deployment guarantee. Transport deadlines are separate
        /// from the server-side wait; this operation does not change the generic
        /// cache connection's transport settings.
        pub fn set_if_absent_wait_aof(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl_seconds: u64,
            timeout_ms: NonZeroU32,
        ) -> crate::error::QidResult<bool> {
            let unavailable = || crate::error::QidError::Internal {
                message: "redis local AOF acknowledgement unavailable".into(),
            };
            let mut conn = self.conn.lock().map_err(|_| unavailable())?;
            let response = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("NX")
                .arg("EX")
                .arg(ttl_seconds)
                .query::<Value>(&mut *conn)
                .map_err(|_| unavailable())?;
            match response {
                Value::Nil => return Ok(false),
                Value::Okay => {}
                _ => return Err(unavailable()),
            }
            let response = redis::cmd("WAITAOF")
                .arg(1)
                .arg(0)
                .arg(timeout_ms.get())
                .query::<Value>(&mut *conn)
                .map_err(|_| unavailable())?;
            match response {
                Value::Array(counts) if matches!(counts.as_slice(), [Value::Int(1), Value::Int(replicas)] if *replicas >= 0) => {
                    Ok(true)
                }
                _ => Err(unavailable()),
            }
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

        fn take(&self, key: &str) -> Option<Vec<u8>> {
            let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            redis::Script::new(
                r"local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); return v; else return false; end",
            )
            .key(key)
            .invoke::<Option<Vec<u8>>>(&mut *conn)
            .ok()
            .flatten()
        }
    }
}

// ---------------------------------------------------------------------------
// DPoP state (was in dpop.rs)
// ---------------------------------------------------------------------------

/// TTL in seconds for cached jti replay entries.
const JTI_CACHE_TTL_SECS: u64 = 60;
const NONCE_CACHE_TTL_SECS: u64 = 300;

/// Protocol scope for OAuth token-endpoint `private_key_jwt` assertion replay keys.
pub const ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT: &str = "oauth-private-key-jwt";
/// Protocol scope for OAuth JWT-bearer / token-exchange assertion replay keys.
pub const ASSERTION_SCOPE_OAUTH_JWT_BEARER: &str = "oauth-jwt-bearer";
/// Protocol scope for PAR `private_key_jwt` assertion replay keys.
pub const ASSERTION_SCOPE_PAR_PRIVATE_KEY_JWT: &str = "par-private-key-jwt";

/// Build an assertion replay key scoped by protocol and client identity.
///
/// Length-prefixing keeps the encoding unambiguous even when the protocol,
/// client id, or JTI contain separator characters.
fn assertion_replay_key(protocol: &str, client_id: &str, jti: &str) -> String {
    format!(
        "assertion:{}:{}:{}:{}:{}:{}",
        protocol.len(),
        protocol,
        client_id.len(),
        client_id,
        jti.len(),
        jti
    )
}

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

    /// Record a JWT client-assertion JTI until its verified `exp`.
    ///
    /// Callers must pass the verified assertion `exp` as `expires_at` and the
    /// same injected `now` used for expiry validation. The `protocol` scope
    /// keeps OAuth `private_key_jwt`, OAuth JWT-bearer/token-exchange, and PAR
    /// `private_key_jwt` entries distinct from each other; the
    /// `assertion:jti` namespace keeps all of them distinct from DPoP proofs.
    pub fn record_assertion_jti(
        &self,
        protocol: &str,
        client_id: &str,
        jti: &str,
        expires_at: u64,
        now: u64,
        replay_message: &str,
    ) -> QidResult<()> {
        self.record_replay_key(
            &assertion_replay_key(protocol, client_id, jti),
            expires_at,
            now,
            replay_message,
        )
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

    /// Consume a DPoP nonce exactly once. The take is atomic on backends
    /// that override it, so concurrent consumers cannot both succeed.
    pub fn consume_nonce(&self, nonce: &str, now: u64) -> QidResult<()> {
        let key = format!("{}:{nonce}", self.nonce_namespace);
        let Some(issued_at_bytes) = self.cache.take(&key) else {
            return Err(QidError::DpopNonce {
                message: "DPoP proof nonce is missing, expired, or already used".to_string(),
            });
        };
        let issued_at = String::from_utf8(issued_at_bytes)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| QidError::Internal {
                message: "DPoP nonce cache entry is invalid".to_string(),
            })?;
        if now.saturating_sub(issued_at) >= NONCE_CACHE_TTL_SECS {
            return Err(QidError::DpopNonce {
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
    use super::{
        ASSERTION_SCOPE_OAUTH_JWT_BEARER, ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT,
        ASSERTION_SCOPE_PAR_PRIVATE_KEY_JWT, DpopState, MemoryCache, SharedCache,
        assertion_replay_key, cache_expiry_reaper, cache_store_id,
    };
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    #[test]
    fn memory_cache_keeps_zero_ttl_immediately_expired() {
        let cache = MemoryCache::new();
        cache.set("expired", b"value".to_vec(), 0);

        assert_eq!(cache.get("expired"), None);
        let store = cache.store.lock().unwrap_or_else(|e| e.into_inner());
        assert!(store.entries.is_empty());
        assert!(store.expirations.is_empty());
    }

    #[test]
    fn memory_cache_reclaims_expired_entries_while_idle() {
        use std::time::{Duration, Instant};

        let cache = MemoryCache::new();
        cache.set("idle-expired", b"value".to_vec(), 1);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let store = cache.store.lock().unwrap_or_else(|e| e.into_inner());
            if store.entries.is_empty() {
                assert!(store.expirations.is_empty());
                return;
            }
            drop(store);
            assert!(
                Instant::now() < deadline,
                "idle cache entry was not reclaimed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn memory_cache_keeps_expiry_index_consistent_across_mutations() {
        let cache = MemoryCache::new();
        cache.set("overwritten", b"old".to_vec(), 3_600);
        cache.set("overwritten", b"new".to_vec(), 7_200);
        cache.set("deleted", b"delete".to_vec(), 3_600);
        cache.delete("deleted");
        cache.set("taken", b"once".to_vec(), 3_600);
        assert_eq!(cache.take("taken"), Some(b"once".to_vec()));

        assert!(
            !cache
                .set_if_absent("overwritten", b"duplicate".to_vec(), 3_600)
                .unwrap()
        );
        assert!(
            cache
                .set_if_absent("new", b"fresh".to_vec(), 3_600)
                .unwrap()
        );
        let store = cache.store.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(store.entries.len(), 2);
        assert_eq!(
            store
                .expirations
                .values()
                .map(|keys| keys.len())
                .sum::<usize>(),
            2
        );
        assert_eq!(store.entries["overwritten"].value, b"new");
    }

    #[test]
    fn memory_cache_reaper_tracks_deadline_changes_and_drop() {
        let cache = MemoryCache::new();
        let id = cache_store_id(&cache.store);
        cache.set("early", b"early".to_vec(), 3_600);
        cache.set("later", b"later".to_vec(), 7_200);
        assert_eq!(
            Arc::strong_count(&cache.store),
            1,
            "reaper must keep only a weak store reference"
        );
        let early_deadline = cache.store.lock().unwrap().next_expiration().unwrap();
        {
            let state = cache_expiry_reaper().state.lock().unwrap();
            assert_eq!(state.scheduled.get(&id), Some(&early_deadline));
            assert!(state.deadlines[&early_deadline].contains(&id));
        }

        cache.delete("early");
        let later_deadline = cache.store.lock().unwrap().next_expiration().unwrap();
        assert!(later_deadline > early_deadline);
        {
            let state = cache_expiry_reaper().state.lock().unwrap();
            assert_eq!(state.scheduled.get(&id), Some(&later_deadline));
            assert!(
                !state
                    .deadlines
                    .get(&early_deadline)
                    .is_some_and(|ids| ids.contains(&id))
            );
        }

        cache.set("latest", b"latest".to_vec(), 10_800);
        assert_eq!(cache.take("later"), Some(b"later".to_vec()));
        let latest_deadline = cache.store.lock().unwrap().next_expiration().unwrap();
        {
            let state = cache_expiry_reaper().state.lock().unwrap();
            assert_eq!(state.scheduled.get(&id), Some(&latest_deadline));
        }
        drop(cache);
        let state = cache_expiry_reaper().state.lock().unwrap();
        assert!(!state.stores.contains_key(&id));
        assert!(!state.scheduled.contains_key(&id));
        assert!(state.deadlines.values().all(|ids| !ids.contains(&id)));
    }

    #[test]
    fn memory_cache_reaper_deadlines_follow_concurrent_mutations() {
        const WORKERS: usize = 8;
        let cache = Arc::new(MemoryCache::new());
        let barrier = Arc::new(Barrier::new(WORKERS));
        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for index in 0..200 {
                        let key = format!("{worker}-{}", index % 7);
                        cache.set(&key, vec![worker as u8], 3_600 + (index % 60) as u64);
                        let _ = cache.get(&key);
                        if index % 2 == 0 {
                            cache.delete(&key);
                        }
                        if index % 3 == 0 {
                            let _ = cache.take(&key);
                        }
                        if index % 5 == 0 {
                            cache.set_if_absent(&key, vec![index as u8], 7_200).unwrap();
                        }
                    }
                });
            }
        });

        let id = cache_store_id(&cache.store);
        let expected = cache.store.lock().unwrap().next_expiration();
        let state = cache_expiry_reaper().state.lock().unwrap();
        assert_eq!(state.scheduled.get(&id).copied(), expected);
        assert_eq!(
            state
                .deadlines
                .values()
                .filter(|ids| ids.contains(&id))
                .count(),
            usize::from(expected.is_some()),
            "a cache must have exactly one deadline-index entry"
        );
        drop(state);
        drop(cache);
        let state = cache_expiry_reaper().state.lock().unwrap();
        assert!(!state.stores.contains_key(&id));
        assert!(!state.scheduled.contains_key(&id));
    }

    #[test]
    fn memory_cache_reaper_visits_only_due_store_among_thousand_idle_caches() {
        const CACHE_COUNT: usize = 1_000;
        let caches: Vec<_> = (0..CACHE_COUNT)
            .map(|index| {
                let cache = MemoryCache::new();
                cache.set(&format!("live-{index}"), vec![1], 3_600);
                cache
            })
            .collect();
        caches[0].set("short", vec![2], 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let store = caches[0].store.lock().unwrap();
            if store.reaper_visits > 0 {
                assert!(!store.entries.contains_key("short"));
                break;
            }
            drop(store);
            assert!(
                Instant::now() < deadline,
                "reaper did not process the due cache"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let visits: usize = caches
            .iter()
            .map(|cache| cache.store.lock().unwrap().reaper_visits)
            .sum();
        assert_eq!(visits, 1, "expiry swept unrelated live-but-idle caches");
        for cache in &caches[1..] {
            let store = cache.store.lock().unwrap();
            assert_eq!(store.reaper_visits, 0);
            assert_eq!(store.entries.len(), 1);
        }
    }

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
    fn concurrent_nonce_consumers_have_exactly_one_winner() {
        use std::sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        };
        const RACERS: usize = 8;
        let state = DpopState::new();
        let nonce = state.issue_nonce(1_000).unwrap();
        let barrier = Barrier::new(RACERS);
        let wins = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..RACERS {
                scope.spawn(|| {
                    barrier.wait();
                    if state.consume_nonce(&nonce, 1_001).is_ok() {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1);
        assert!(state.consume_nonce(&nonce, 1_002).is_err());
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

    #[test]
    fn assertion_replay_keys_are_scoped_and_unambiguous() {
        // Same JTI/client under different protocols must not collide.
        let oauth_pkj =
            assertion_replay_key(ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT, "client-a", "jti-1");
        let oauth_bearer =
            assertion_replay_key(ASSERTION_SCOPE_OAUTH_JWT_BEARER, "client-a", "jti-1");
        let par_pkj =
            assertion_replay_key(ASSERTION_SCOPE_PAR_PRIVATE_KEY_JWT, "client-a", "jti-1");
        assert_ne!(oauth_pkj, oauth_bearer);
        assert_ne!(oauth_pkj, par_pkj);
        assert_ne!(oauth_bearer, par_pkj);

        // Same JTI under different clients must not collide.
        assert_ne!(
            assertion_replay_key(ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT, "client-a", "jti-1"),
            assertion_replay_key(ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT, "client-b", "jti-1"),
        );

        // Length-prefixing keeps separators unambiguous.
        assert_ne!(
            assertion_replay_key("a:b", "c", "d"),
            assertion_replay_key("a", "b:c", "d"),
        );
        assert_ne!(
            assertion_replay_key("proto", "client:x", "jti-1"),
            assertion_replay_key("proto", "client", "x:jti-1"),
        );

        // Assertion keys must not collide with a bare DPoP JTI entry.
        let cache = Arc::new(MemoryCache::new());
        let dpop = DpopState::with_cache(cache.clone());
        let assertions = DpopState::assertion_replay(cache);
        dpop.record_jti("jti-1", 1_000, 1_000).unwrap();
        assertions
            .record_assertion_jti(
                ASSERTION_SCOPE_OAUTH_PRIVATE_KEY_JWT,
                "client-a",
                "jti-1",
                1_000 + 3600,
                1_000,
                "client_assertion jti already used (replay detected)",
            )
            .unwrap();
    }
}
