//! Shared application state for HTTP handlers.

use crate::cache::{DecisionCacheEntry, DpopState, SessionCache};
use crate::config::{QidConfig, ServerPaths};
use crate::error::QidResult;
use crate::plan::RuntimePlan;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Maximum entries in the in-memory decision cache.
const MAX_DECISION_CACHE_ENTRIES: usize = 100_000;

/// Shared state passed to axum handlers.
///
/// This type intentionally stays in `qid-core` so that protocol crates
/// (oidc, oauth, PEP adapters) can depend on it without circular dependencies.
pub struct SharedState<Repository> {
    pub config: QidConfig,
    pub plan: RuntimePlan,
    pub repo: Arc<Repository>,
    pub signer: Arc<dyn crate::jwt::Signer>,
    pub pep_assertion_signers: BTreeMap<String, Arc<dyn crate::jwt::Signer>>,
    pub dpop_state: DpopState,
    pub assertion_replay_cache: DpopState,
    pub policy_bundle_cache: RwLock<Option<(String, Value)>>,
    pub jwks: Value,
    pub paths: ServerPaths,
    /// In-memory pep_decision decision cache (keyed by cache key digest).
    pub decision_cache: RwLock<HashMap<String, DecisionCacheEntry>>,
    /// In-memory session cache (keyed by session id, value is serialized session JSON).
    pub session_cache: RwLock<SessionCache>,
    /// Process-local pepper for short-lived CIAM verification challenges.
    pub ciam_verification_pepper: Vec<u8>,
    /// PEM-encoded workload CA certificate used to issue X.509-SVIDs.
    pub workload_ca_certificate_pem: Option<String>,
    /// PEM-encoded workload CA private key used to issue X.509-SVIDs.
    pub workload_ca_private_key_pem: Option<String>,
}

impl<Repository> SharedState<Repository> {
    pub fn new(
        config: QidConfig,
        repo: Arc<Repository>,
        signer: Arc<dyn crate::jwt::Signer>,
        jwks: Value,
    ) -> QidResult<Self> {
        Self::new_with_pep_assertion_signers(config, repo, signer, BTreeMap::new(), jwks)
    }

    pub fn new_with_pep_assertion_signers(
        config: QidConfig,
        repo: Arc<Repository>,
        signer: Arc<dyn crate::jwt::Signer>,
        pep_assertion_signers: BTreeMap<String, Arc<dyn crate::jwt::Signer>>,
        jwks: Value,
    ) -> QidResult<Self> {
        let plan = RuntimePlan::from_config(&config)?;
        let paths = config.server.paths.clone();
        Ok(Self {
            config,
            plan,
            repo,
            signer,
            pep_assertion_signers,
            dpop_state: DpopState::new(),
            assertion_replay_cache: DpopState::new(),
            policy_bundle_cache: RwLock::new(None),
            decision_cache: RwLock::new(HashMap::new()),
            session_cache: RwLock::new(SessionCache::new(10_000)),
            ciam_verification_pepper: random_pepper(),
            workload_ca_certificate_pem: None,
            workload_ca_private_key_pem: None,
            jwks,
            paths,
        })
    }

    pub fn with_workload_ca(mut self, certificate_pem: String, private_key_pem: String) -> Self {
        self.workload_ca_certificate_pem = Some(certificate_pem);
        self.workload_ca_private_key_pem = Some(private_key_pem);
        self
    }

    pub fn realm(&self, id: &str) -> Option<&crate::plan::RuntimeRealm> {
        self.plan.realm(id)
    }

    pub fn first_realm(&self) -> Option<&crate::plan::RuntimeRealm> {
        self.plan.first_realm()
    }

    pub fn pep_assertion_signer(&self, realm_id: &str) -> Option<&Arc<dyn crate::jwt::Signer>> {
        self.pep_assertion_signers.get(realm_id)
    }

    /// Look up a cached pep_decision decision by cache key digest.
    pub fn decision_cache_get(&self, digest: &str) -> Option<Value> {
        let guard = self.decision_cache.read().ok()?;
        let entry = guard.get(digest)?;
        if entry.expires_at > Instant::now() {
            Some(entry.response_json.clone())
        } else {
            None
        }
    }

    /// Store an pep_decision decision in the cache.
    pub fn decision_cache_put(&self, digest: String, response_json: Value, ttl_seconds: u64) {
        if let Ok(mut guard) = self.decision_cache.write() {
            guard.insert(
                digest,
                DecisionCacheEntry {
                    response_json,
                    expires_at: Instant::now() + std::time::Duration::from_secs(ttl_seconds),
                },
            );
            if guard.len() > MAX_DECISION_CACHE_ENTRIES {
                let mut excess = guard.len().saturating_sub(MAX_DECISION_CACHE_ENTRIES);
                guard.retain(|_, _| {
                    if excess > 0 {
                        excess -= 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }
    }

    /// Look up a cached session by session id.
    pub fn session_cache_get(&self, session_id: &str) -> Option<Vec<u8>> {
        let mut guard = self.session_cache.write().ok()?;
        guard.get(session_id)
    }

    /// Store a session in the cache.
    pub fn session_cache_put(&self, session_id: String, value: Vec<u8>, ttl_seconds: u64) {
        if let Ok(mut guard) = self.session_cache.write() {
            guard.put(session_id, value, ttl_seconds);
        }
    }

    /// Current policy revision (bundle name) from the in-memory cache.
    pub fn policy_revision(&self) -> String {
        self.policy_bundle_cache
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|(name, _)| name.clone()))
            .unwrap_or_default()
    }
}

fn random_pepper() -> Vec<u8> {
    use rand::RngCore;

    let mut pepper = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut pepper);
    pepper
}
