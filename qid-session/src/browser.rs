//! Browser session management.

use qid_core::config::BrowserSessionConfig;
use qid_core::error::QidResult;
use qid_core::models::Session;
use qid_core::state::SharedState;
use qid_ops::{CacheKey, CachePut};
use qid_storage::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A browser session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub id: String,
    pub user_id: String,
    pub realm_id: String,
}

/// Manages browser sessions.
/// Invalidates cached browser sessions after authoritative revocation.
pub trait SessionCacheInvalidator: Send + Sync + 'static {
    fn invalidate(&self, session_id: &str);
}

impl<R: Repository> SessionCacheInvalidator for SharedState<R> {
    fn invalidate(&self, session_id: &str) {
        self.session_cache_delete(session_id);
    }
}

pub struct SessionManager<R: SessionRepository + ?Sized> {
    repo: Arc<R>,
    cache: Option<Arc<dyn SessionCacheInvalidator>>,
    idle_timeout_seconds: u64,
    absolute_timeout_seconds: u64,
}

impl<R: SessionRepository + ?Sized> SessionManager<R> {
    pub(crate) fn from_browser_session_config(
        repo: Arc<R>,
        config: &BrowserSessionConfig,
        cache: Arc<dyn SessionCacheInvalidator>,
    ) -> Self {
        let mut manager = Self::new(
            repo,
            config.idle_timeout_minutes,
            config.absolute_timeout_hours,
        );
        manager.cache = Some(cache);
        manager
    }

    pub(crate) fn with_cache(
        repo: Arc<R>,
        idle_timeout_minutes: u64,
        absolute_timeout_hours: u64,
        cache: Arc<dyn SessionCacheInvalidator>,
    ) -> Self {
        let mut manager = Self::new(repo, idle_timeout_minutes, absolute_timeout_hours);
        manager.cache = Some(cache);
        manager
    }

    pub fn new(repo: Arc<R>, idle_timeout_minutes: u64, absolute_timeout_hours: u64) -> Self {
        Self {
            repo,
            cache: None,
            idle_timeout_seconds: idle_timeout_minutes * 60,
            absolute_timeout_seconds: absolute_timeout_hours * 60 * 60,
        }
    }

    pub async fn create(
        &self,
        realm_id: &str,
        user_id: &str,
        acr: &str,
        amr: &[String],
    ) -> QidResult<Session> {
        let now = qid_core::util::now_seconds();
        let session = Session {
            id: generate_session_id(),
            realm_id: realm_id.to_string(),
            user_id: user_id.to_string(),
            auth_time: now,
            acr: Some(acr.to_string()),
            amr: amr.to_vec(),
            idle_expires_at: now + self.idle_timeout_seconds,
            absolute_expires_at: now + self.absolute_timeout_seconds,
            revoked: false,
            created_at: now,
            cnf: None,
        };
        self.repo.create_session(&session).await?;
        Ok(session)
    }

    /// Create a new session after successful authentication, optionally
    /// revoking an existing session to prevent session fixation.
    pub async fn create_with_regeneration(
        &self,
        realm_id: &str,
        user_id: &str,
        acr: &str,
        amr: &[String],
        old_session_id: Option<&str>,
    ) -> QidResult<Session> {
        if let Some(old_id) = old_session_id {
            self.repo.revoke_session(old_id, Some(realm_id)).await?;
            if let Some(cache) = &self.cache {
                cache.invalidate(old_id);
            }
        }
        self.create(realm_id, user_id, acr, amr).await
    }

    pub async fn get(&self, id: &str) -> QidResult<Option<Session>> {
        let session = self.repo.get_session(id).await?;
        if let Some(ref s) = session
            && !session_is_active(s, qid_core::util::now_seconds())
        {
            return Ok(None);
        }
        Ok(session)
    }

    pub async fn revoke(&self, id: &str, realm_scope: Option<&str>) -> QidResult<bool> {
        self.repo.revoke_session(id, realm_scope).await
    }
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("sid_{}", qid_core::util::hex_encode_lower(&bytes))
}

pub fn session_is_active(session: &Session, now_epoch: u64) -> bool {
    session.is_active(now_epoch)
}

pub fn session_cache_key(session_id: &str) -> QidResult<CacheKey> {
    CacheKey::new("session", session_id.as_bytes())
}

pub fn session_cache_put(session: &Session, now_epoch: u64) -> QidResult<Option<CachePut>> {
    if !session_is_active(session, now_epoch) {
        return Ok(None);
    }
    let ttl_seconds = session
        .idle_expires_at
        .min(session.absolute_expires_at)
        .saturating_sub(now_epoch);
    if ttl_seconds == 0 {
        return Ok(None);
    }
    let value = serde_json::to_vec(session).map_err(|err| qid_core::error::QidError::Internal {
        message: format!("failed to encode session cache value: {err}"),
    })?;
    Ok(Some(CachePut {
        key: session_cache_key(&session.id)?,
        value,
        ttl_seconds,
    }))
}

pub fn decode_cached_session(value: &[u8], now_epoch: u64) -> QidResult<Option<Session>> {
    let session: Session =
        serde_json::from_slice(value).map_err(|err| qid_core::error::QidError::Internal {
            message: format!("failed to decode session cache value: {err}"),
        })?;
    if session_is_active(&session, now_epoch) {
        Ok(Some(session))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use qid_ops::{CacheBackendConfig, CacheBackendKind};

    fn session(now: u64) -> Session {
        Session {
            id: "sid_sensitive_cookie_value".to_string(),
            realm_id: "corp".to_string(),
            user_id: "user-1".to_string(),
            auth_time: now,
            acr: Some("urn:qid:acr:password".to_string()),
            amr: vec!["password".to_string()],
            idle_expires_at: now + 60,
            absolute_expires_at: now + 3600,
            revoked: false,
            created_at: now,
            cnf: None,
        }
    }

    #[test]
    fn session_cache_key_hashes_session_id() {
        let key = session_cache_key("sid_sensitive_cookie_value").unwrap();
        let rendered = key
            .render(&CacheBackendConfig {
                kind: CacheBackendKind::Redis,
                endpoints: vec!["redis://127.0.0.1:6379".to_string()],
                key_prefix: "qid".to_string(),
                ttl_seconds: 300,
            })
            .unwrap();

        assert!(rendered.starts_with("qid:session:"));
        assert!(!rendered.contains("sid_sensitive_cookie_value"));
    }

    #[test]
    fn session_cache_put_uses_shorter_session_expiry_as_ttl() {
        let now = 1000;
        let cache_put = session_cache_put(&session(now), now).unwrap().unwrap();

        assert_eq!(cache_put.ttl_seconds, 60);
        let decoded = decode_cached_session(&cache_put.value, now)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.id, "sid_sensitive_cookie_value");
    }

    #[test]
    fn session_cache_skips_revoked_or_expired_sessions() {
        let now = 1000;
        let mut revoked = session(now);
        revoked.revoked = true;
        assert!(session_cache_put(&revoked, now).unwrap().is_none());

        let mut expired = session(now);
        expired.idle_expires_at = now - 1;
        assert!(session_cache_put(&expired, now).unwrap().is_none());

        let value = serde_json::to_vec(&expired).unwrap();
        assert!(decode_cached_session(&value, now).unwrap().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::error::QidError;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct FailingSessionRepo {
        sessions: Mutex<Vec<Session>>,
        fail_revoke: AtomicBool,
        fail_create: AtomicBool,
        create_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SessionRepository for FailingSessionRepo {
        async fn create_session(&self, session: &Session) -> QidResult<()> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_create.load(Ordering::SeqCst) {
                return Err(QidError::Storage {
                    message: "replacement creation failed".to_string(),
                });
            }
            self.sessions.lock().unwrap().push(session.clone());
            Ok(())
        }

        async fn get_session(&self, id: &str) -> QidResult<Option<Session>> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .find(|session| session.id == id)
                .cloned())
        }

        async fn update_session_idle_expiry(
            &self,
            _id: &str,
            _idle_expires_at: u64,
            _realm_scope: Option<&str>,
        ) -> QidResult<bool> {
            Ok(false)
        }

        async fn revoke_session(&self, id: &str, realm_scope: Option<&str>) -> QidResult<bool> {
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(QidError::Storage {
                    message: "old session revocation failed".to_string(),
                });
            }
            let mut sessions = self.sessions.lock().unwrap();
            let Some(session) = sessions.iter_mut().find(|session| {
                session.id == id && realm_scope.is_none_or(|realm| session.realm_id == realm)
            }) else {
                return Ok(false);
            };
            session.revoked = true;
            Ok(true)
        }
    }

    #[tokio::test]
    async fn regeneration_returns_revocation_errors_before_issuing_a_replacement() {
        let repo = Arc::new(FailingSessionRepo::default());
        let now = qid_core::util::now_seconds();
        repo.create_session(&Session {
            id: "old".to_string(),
            realm_id: "corp".to_string(),
            user_id: "user".to_string(),
            auth_time: now,
            acr: Some("pwd".to_string()),
            amr: vec!["pwd".to_string()],
            idle_expires_at: now + 30,
            absolute_expires_at: now + 3600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
        repo.create_calls.store(0, Ordering::SeqCst);
        repo.fail_revoke.store(true, Ordering::SeqCst);
        let manager = SessionManager::new(repo.clone(), 30, 8);
        let amr = vec!["pwd".to_string()];
        let err = manager
            .create_with_regeneration("corp", "user", "pwd", &amr, Some("old"))
            .await
            .unwrap_err();
        assert!(matches!(err, QidError::Storage { .. }));
        assert_eq!(repo.create_calls.load(Ordering::SeqCst), 0);
        assert!(!repo.sessions.lock().unwrap()[0].revoked);

        repo.fail_revoke.store(false, Ordering::SeqCst);
        let replacement = manager
            .create_with_regeneration("corp", "user", "pwd", &amr, Some("old"))
            .await
            .unwrap();
        assert_eq!(repo.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replacement.realm_id, "corp");
        assert!(repo.sessions.lock().unwrap()[0].revoked);
    }
    #[derive(Default)]
    struct RecordingCache {
        invalidated: Mutex<Vec<String>>,
    }

    impl SessionCacheInvalidator for RecordingCache {
        fn invalidate(&self, session_id: &str) {
            self.invalidated
                .lock()
                .unwrap()
                .push(session_id.to_string());
        }
    }

    #[tokio::test]
    async fn regeneration_invalidates_the_old_session_cache_after_revocation() {
        let repo = Arc::new(FailingSessionRepo::default());
        let now = qid_core::util::now_seconds();
        repo.create_session(&Session {
            id: "old".to_string(),
            realm_id: "corp".to_string(),
            user_id: "user".to_string(),
            auth_time: now,
            acr: Some("pwd".to_string()),
            amr: vec!["pwd".to_string()],
            idle_expires_at: now + 30,
            absolute_expires_at: now + 3600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
        let cache = Arc::new(RecordingCache::default());
        let manager = SessionManager::with_cache(repo.clone(), 30, 8, cache.clone());
        let amr = vec!["pwd".to_string()];

        repo.fail_revoke.store(true, Ordering::SeqCst);
        assert!(
            manager
                .create_with_regeneration("corp", "user", "pwd", &amr, Some("old"))
                .await
                .is_err()
        );
        assert!(cache.invalidated.lock().unwrap().is_empty());

        repo.fail_revoke.store(false, Ordering::SeqCst);
        manager
            .create_with_regeneration("corp", "user", "pwd", &amr, Some("old"))
            .await
            .unwrap();
        assert_eq!(cache.invalidated.lock().unwrap().as_slice(), &["old"]);
    }
    #[tokio::test]
    async fn regeneration_invalidates_cache_even_when_replacement_creation_fails() {
        let repo = Arc::new(FailingSessionRepo::default());
        let now = qid_core::util::now_seconds();
        repo.create_session(&Session {
            id: "old".to_string(),
            realm_id: "corp".to_string(),
            user_id: "user".to_string(),
            auth_time: now,
            acr: Some("pwd".to_string()),
            amr: vec!["pwd".to_string()],
            idle_expires_at: now + 30,
            absolute_expires_at: now + 3600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
        repo.create_calls.store(0, Ordering::SeqCst);
        repo.fail_create.store(true, Ordering::SeqCst);
        let cache = Arc::new(RecordingCache::default());
        let manager = SessionManager::with_cache(repo.clone(), 30, 8, cache.clone());
        let err = manager
            .create_with_regeneration("corp", "user", "pwd", &["pwd".to_string()], Some("old"))
            .await
            .unwrap_err();
        assert!(matches!(err, QidError::Storage { .. }));
        assert_eq!(cache.invalidated.lock().unwrap().as_slice(), &["old"]);
        assert!(repo.sessions.lock().unwrap()[0].revoked);
    }
}
