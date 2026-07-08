//! Shared application state for HTTP handlers.

use crate::cache::{DecisionCacheEntry, DpopState, MemoryCache, SessionCache, SharedCache};
use crate::config::{QidConfig, ServerPaths};
use crate::error::QidResult;
use crate::plan::RuntimePlan;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Maximum entries in the in-memory decision cache.
const MAX_DECISION_CACHE_ENTRIES: usize = 100_000;
const DECISION_CACHE_NAMESPACE: &str = "pep:decision";
const SESSION_CACHE_NAMESPACE: &str = "session";
const SESSION_L1_TTL_SECONDS: u64 = 30;

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
    /// Shared L2 cache for replay guards and cross-instance coordination.
    pub shared_cache: Arc<dyn SharedCache>,
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
        let shared_cache: Arc<dyn SharedCache> = Arc::new(MemoryCache::new());
        Ok(Self {
            config,
            plan,
            repo,
            signer,
            pep_assertion_signers,
            dpop_state: DpopState::with_cache(Arc::clone(&shared_cache)),
            assertion_replay_cache: DpopState::assertion_replay(Arc::clone(&shared_cache)),
            policy_bundle_cache: RwLock::new(None),
            decision_cache: RwLock::new(HashMap::new()),
            session_cache: RwLock::new(SessionCache::new(10_000)),
            shared_cache,
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

    pub fn with_shared_cache(mut self, shared_cache: Arc<dyn SharedCache>) -> Self {
        self.dpop_state = DpopState::with_cache(Arc::clone(&shared_cache));
        self.assertion_replay_cache = DpopState::assertion_replay(Arc::clone(&shared_cache));
        self.shared_cache = shared_cache;
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
        if let Ok(guard) = self.decision_cache.read()
            && let Some(entry) = guard.get(digest)
            && entry.expires_at > Instant::now()
        {
            return Some(entry.response_json.clone());
        }
        let bytes = self
            .shared_cache
            .get(&format!("{DECISION_CACHE_NAMESPACE}:{digest}"))?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Store an pep_decision decision in the cache.
    pub fn decision_cache_put(&self, digest: String, response_json: Value, ttl_seconds: u64) {
        if let Ok(bytes) = serde_json::to_vec(&response_json) {
            self.shared_cache.set(
                &format!("{DECISION_CACHE_NAMESPACE}:{digest}"),
                bytes,
                ttl_seconds,
            );
        }
        if let Ok(mut guard) = self.decision_cache.write() {
            guard.insert(
                digest,
                DecisionCacheEntry {
                    response_json,
                    expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
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
        if let Ok(mut guard) = self.session_cache.write()
            && let Some(value) = guard.get(session_id)
        {
            return Some(value);
        }
        self.shared_cache
            .get(&format!("{SESSION_CACHE_NAMESPACE}:{session_id}"))
    }

    /// Store a session in the cache.
    pub fn session_cache_put(&self, session_id: String, value: Vec<u8>, ttl_seconds: u64) {
        self.shared_cache.set(
            &format!("{SESSION_CACHE_NAMESPACE}:{session_id}"),
            value.clone(),
            ttl_seconds,
        );
        if let Ok(mut guard) = self.session_cache.write() {
            guard.put(session_id, value, ttl_seconds.min(SESSION_L1_TTL_SECONDS));
        }
    }

    /// Remove a session from both local and shared caches.
    pub fn session_cache_delete(&self, session_id: &str) {
        self.shared_cache
            .delete(&format!("{SESSION_CACHE_NAMESPACE}:{session_id}"));
        if let Ok(mut guard) = self.session_cache.write() {
            guard.delete(session_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile,
        ObservabilityConfig, OpsConfig, PepRegistrationsConfig, PolicyConfig, ProtocolConfig,
        RealmConfig, ServerConfig, ServerPaths, SessionConfig, StorageConfig,
    };
    use crate::jwt::{JwtClaims, Signer, TokenData};

    struct TestSigner;

    impl Signer for TestSigner {
        fn sign(&self, _claims: &JwtClaims) -> anyhow::Result<String> {
            Ok("test-token".to_string())
        }

        fn sign_with_typ(&self, _claims: &JwtClaims, _typ: &str) -> anyhow::Result<String> {
            Ok("test-token".to_string())
        }

        fn decode_signature_only(&self, _token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
            anyhow::bail!("test signer does not decode tokens")
        }

        fn decode_with_aud(
            &self,
            _token: &str,
            _expected_audience: &str,
        ) -> anyhow::Result<TokenData<JwtClaims>> {
            anyhow::bail!("test signer does not decode tokens")
        }

        fn algorithm(&self) -> &'static str {
            "HS256"
        }
    }

    fn config() -> QidConfig {
        QidConfig {
            include: Vec::new(),
            profile: DeploymentProfile::Oidc,
            server: ServerConfig {
                listen: "127.0.0.1:0".to_string(),
                public_base_url: "https://id.example.com".to_string(),
                tls: None,
                http_message_signatures: Default::default(),
                cors: CorsConfig::default(),
                paths: ServerPaths::default(),
            },
            admin: AdminConfig::default(),
            storage: StorageConfig::default(),
            crypto: CryptoConfig::default(),
            realms: vec![RealmConfig {
                id: "corp".to_string(),
                issuer: "https://id.example.com/realms/corp".to_string(),
                display_name: None,
                tenant_id: None,
                clients: Vec::new(),
                protocols: ProtocolConfig::default(),
                authentication: AuthenticationConfig::default(),
                sessions: SessionConfig::default(),
                pep_registrations: PepRegistrationsConfig::default(),
                policy: PolicyConfig::default(),
            }],
            observability: ObservabilityConfig::default(),
            ops: OpsConfig::default(),
        }
    }

    fn state_with_cache(cache: Arc<dyn SharedCache>) -> SharedState<()> {
        SharedState::new(
            config(),
            Arc::new(()),
            Arc::new(TestSigner),
            serde_json::json!({"keys": []}),
        )
        .expect("test state")
        .with_shared_cache(cache)
    }

    #[test]
    fn decision_cache_is_shared_across_state_instances() {
        let cache: Arc<dyn SharedCache> = Arc::new(MemoryCache::new());
        let first = state_with_cache(Arc::clone(&cache));
        let second = state_with_cache(cache);

        first.decision_cache_put(
            "digest-1".to_string(),
            serde_json::json!({"decision": "allow"}),
            60,
        );

        assert_eq!(
            second.decision_cache_get("digest-1"),
            Some(serde_json::json!({"decision": "allow"}))
        );
    }

    #[test]
    fn session_cache_delete_invalidates_shared_cache() {
        let cache: Arc<dyn SharedCache> = Arc::new(MemoryCache::new());
        let first = state_with_cache(Arc::clone(&cache));
        let second = state_with_cache(cache);

        first.session_cache_put("sid-1".to_string(), br#"{"id":"sid-1"}"#.to_vec(), 60);
        assert_eq!(
            second.session_cache_get("sid-1"),
            Some(br#"{"id":"sid-1"}"#.to_vec())
        );

        first.session_cache_delete("sid-1");

        assert_eq!(second.session_cache_get("sid-1"), None);
    }
}
