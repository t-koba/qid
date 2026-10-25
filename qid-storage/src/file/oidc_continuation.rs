use super::*;
use crate::{OidcContinuationRepository, oidc_continuation as state};
use async_trait::async_trait;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredContinuation {
    record: OidcAuthorizationContinuation,
    consumed: bool,
}

impl FileRepository {
    // Persist under the save lock before returning success. The detached task
    // completes even if the caller is cancelled; a failed write rolls back state.
    async fn mutate_oidc_continuation<F>(
        &self,
        f: F,
    ) -> QidResult<Option<OidcAuthorizationContinuation>>
    where
        F: FnOnce(
                &mut HashMap<String, StoredContinuation>,
            ) -> QidResult<Option<OidcAuthorizationContinuation>>
            + Send
            + 'static,
    {
        let repo = self.clone();
        tokio::spawn(async move {
            let save_guard = repo.save_lock.lock().await;
            let mut store = repo.store.write().await;
            let before = store.oidc_continuations.clone();
            let result = f(&mut store.oidc_continuations)?;
            if result.is_some() {
                let written = async {
                    let content =
                        serde_json::to_string(&*store).map_err(|_| QidError::Internal {
                            message: "OIDC continuation serialization failed".into(),
                        })?;
                    repo.write_store_content_locked(&save_guard, &content).await
                }
                .await;
                if let Err(error) = written {
                    store.oidc_continuations = before;
                    return Err(error);
                }
            }
            Ok(result)
        })
        .await
        .map_err(|_| QidError::Internal {
            message: "OIDC continuation storage task failed".into(),
        })?
    }
}

#[async_trait]
impl OidcContinuationRepository for FileRepository {
    async fn create_oidc_continuation(
        &self,
        record: &OidcAuthorizationContinuation,
        now: u64,
    ) -> QidResult<()> {
        state::validate_creation(record, now)?;
        let record = record.clone();
        self.mutate_oidc_continuation(move |rows| {
            if rows.contains_key(&record.id) {
                return Err(QidError::Conflict {
                    message: "OIDC continuation ID already exists".into(),
                });
            }
            rows.insert(
                record.id.clone(),
                StoredContinuation {
                    record: record.clone(),
                    consumed: false,
                },
            );
            Ok(Some(record))
        })
        .await?;
        Ok(())
    }

    async fn consume_oidc_continuation(
        &self,
        realm: &RealmId,
        user: &str,
        client: &str,
        id: &str,
        browser_binding_sha256: &[u8; 32],
        now: u64,
    ) -> QidResult<Option<OidcAuthorizationContinuation>> {
        if now > i64::MAX as u64 {
            return Err(state::invalid());
        }
        let (realm, user, client, id, binding) = (
            realm.0.clone(),
            user.to_owned(),
            client.to_owned(),
            id.to_owned(),
            *browser_binding_sha256,
        );
        self.mutate_oidc_continuation(move |rows| {
            let Some(row) = rows.get_mut(&id) else {
                return Ok(None);
            };
            let c = &row.record;
            state::validate(c)?;
            if c.id != id
                || c.realm_id != realm
                || c.user_id != user
                || c.client_id != client
                || c.browser_binding_sha256 != binding
                || row.consumed
                || now < c.created_at
                || now >= c.expires_at
            {
                return Ok(None);
            }
            row.consumed = true;
            Ok(Some(c.clone()))
        })
        .await
    }

    async fn cleanup_expired_oidc_continuations(&self, now: u64, limit: u32) -> QidResult<u64> {
        state::validate_cleanup(now, limit)?;
        let repo = self.clone();
        tokio::spawn(async move {
            let save_guard = repo.save_lock.lock().await;
            let mut store = repo.store.write().await;
            let mut oldest = BinaryHeap::<(u64, String)>::with_capacity(limit as usize);
            for (id, row) in &store.oidc_continuations {
                state::validate(&row.record)?;
                if row.record.id != *id {
                    return Err(state::invalid());
                }
                if row.record.expires_at <= now {
                    let candidate = (row.record.expires_at, id.clone());
                    if oldest.len() < limit as usize {
                        oldest.push(candidate);
                    } else if oldest.peek().is_some_and(|last| candidate < *last) {
                        oldest.pop();
                        oldest.push(candidate);
                    }
                }
            }
            let mut expired = oldest.into_vec();
            expired.sort_unstable();
            let removed: Vec<_> = expired
                .into_iter()
                .filter_map(|(_, id)| store.oidc_continuations.remove(&id).map(|row| (id, row)))
                .collect();
            let deleted = removed.len() as u64;
            if deleted == 0 {
                return Ok(0);
            }
            let written = async {
                let content = serde_json::to_string(&*store).map_err(|_| QidError::Internal {
                    message: "OIDC continuation serialization failed".into(),
                })?;
                repo.write_store_content_locked(&save_guard, &content).await
            }
            .await;
            if let Err(error) = written {
                for (id, row) in removed {
                    store.oidc_continuations.insert(id, row);
                }
                return Err(error);
            }
            Ok(deleted)
        })
        .await
        .map_err(|_| QidError::Internal {
            message: "OIDC continuation cleanup task failed".into(),
        })?
    }
}
