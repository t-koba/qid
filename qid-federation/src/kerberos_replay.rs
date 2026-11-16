use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::cache::SharedCache;
use sha2::{Digest, Sha256};
use std::{fmt, io, sync::Arc};

/// Kerberos replay tags stored atomically in an explicitly supplied cache.
///
/// Replay protection has only the sharing and durability that the backend
/// provides. QID's default `MemoryCache` is process-local and is cleared on
/// restart; multi-process acceptors need a shared backend that retains entries
/// for their TTL. The generic Redis `SharedCache` operation is atomic but does
/// not acknowledge durable storage. The isolated Redis qualification fixture
/// uses an explicit local-AOF operation via a test-only adapter; it is not a
/// production backend selection or a multi-host failover guarantee.
pub struct KerberosReplayStore {
    cache: Arc<dyn SharedCache>,
}

impl KerberosReplayStore {
    /// Create a replay store backed by `cache`.
    ///
    /// The backend's `set_if_absent` must be atomic. Backend failures are
    /// returned to the Kerberos acceptor, which must reject the request.
    pub fn new(cache: Arc<dyn SharedCache>) -> Self {
        Self { cache }
    }
}

impl fmt::Debug for KerberosReplayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KerberosReplayStore")
            .finish_non_exhaustive()
    }
}

impl KerberosReplayStore {
    /// Atomically record a replay tag through its inclusive expiry second.
    /// `now` and `expires` are Unix seconds.
    pub fn insert(&self, tag: &[u8], now: i64, expires: i64) -> io::Result<bool> {
        // Match krb5's in-memory store: tags are zero-padded or truncated to
        // the longest supported checksum before they identify a replay.
        let mut canonical_tag = [0; 24];
        let len = tag.len().min(canonical_tag.len());
        canonical_tag[..len].copy_from_slice(&tag[..len]);
        let key = format!(
            "kerberos:replay:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_tag))
        );
        // ReplayStore treats `expires` as inclusive. Its Unix-second `now`
        // is sampled before this relative TTL starts, so retain the entry
        // through the whole expiry second instead of rounding it down.
        let ttl_seconds = expires.saturating_sub(now).saturating_add(1).max(1) as u64;
        self.cache
            .set_if_absent(&key, Vec::new(), ttl_seconds)
            .map_err(|_| io::Error::other("Kerberos replay cache unavailable"))
    }
}
