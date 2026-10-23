use async_trait::async_trait;

use super::*;

#[async_trait]
impl RealmRepository for FileRepository {
    async fn create_realm(
        &self,
        tenant: &TenantId,
        realm_id: &RealmId,
        issuer: &str,
        _display_name: Option<&str>,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        reject_duplicate_id(
            store.realm_issuers.contains_key(&realm_id.0)
                || store.realm_tenants.contains_key(&realm_id.0)
                || store
                    .realm_issuers
                    .values()
                    .any(|stored_issuer| stored_issuer == issuer),
            || "realm ID or issuer already exists".to_string(),
        )?;
        store
            .realm_issuers
            .insert(realm_id.0.clone(), issuer.to_string());
        store
            .realm_tenants
            .insert(realm_id.0.clone(), tenant.as_str().to_string());
        drop(store);
        self.save().await
    }

    async fn get_realm_issuer(&self, id: &RealmId) -> QidResult<Option<String>> {
        let store = self.store.read().await;
        Ok(store.realm_issuers.get(&id.0).cloned())
    }

    async fn get_realm_tenant(&self, id: &RealmId) -> QidResult<Option<String>> {
        let store = self.store.read().await;
        Ok(store.realm_tenants.get(&id.0).cloned())
    }

    async fn list_realms(&self) -> QidResult<Vec<(String, String)>> {
        let store = self.store.read().await;
        let mut realms: Vec<_> = store
            .realm_issuers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        realms.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(realms)
    }

    async fn delete_realm(&self, id: &RealmId) -> QidResult<()> {
        if self.flush_mode == FileFlushMode::Immediate {
            // Once started, deletion completes persistence or rollback even if
            // the request future is cancelled during a filesystem await.
            let repo = self.clone();
            let id = id.clone();
            return tokio::spawn(async move { repo.delete_realm_inner(&id).await })
                .await
                .map_err(|error| QidError::Internal {
                    message: format!("realm deletion task failed: {error}"),
                })?;
        }
        self.delete_realm_inner(id).await
    }
}

impl FileRepository {
    async fn delete_realm_inner(&self, id: &RealmId) -> QidResult<()> {
        // Keep both locks through persistence/rollback: no reader can observe a
        // partial deletion and no concurrent save can publish tentative state.
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        let previous = save_guard.as_ref().map(|_| store.clone());
        store.remove_realm(id.as_str());
        if let Some(guard) = save_guard {
            let result = async {
                #[cfg(test)]
                self.before_flush().await?;
                let content = serde_json::to_string(&*store).map_err(|e| QidError::Internal {
                    message: format!("failed to serialize store: {e}"),
                })?;
                self.write_store_content_locked(&guard, &content).await
            }
            .await;
            if result.is_err() {
                *store = previous.unwrap();
            }
            result
        } else {
            // Interval mode accepts the in-memory deletion; failed background
            // persistence leaves it dirty for retry, just like other mutations.
            self.dirty.store(true, Ordering::Release);
            Ok(())
        }
    }
}

impl Store {
    fn remove_realm(&mut self, realm: &str) {
        let users = self
            .users
            .values()
            .filter(|user| user.realm_id == realm)
            .map(|user| user.id.clone())
            .collect();
        self.remove_auth_state(&users, Some(realm));
        self.clients.retain(|_, value| value.realm_id != realm);
        self.service_accounts
            .retain(|_, value| value.realm_id != realm);
        self.policy_bundles
            .retain(|_, value| value.realm_id != realm);
        self.vc_credential_statuses
            .retain(|_, value| value.realm_id != realm);
        self.par_requests.retain(|_, value| value.realm_id != realm);
        self.hr_receipts.remove(realm);
        self.scim_users.retain(|_, value| value.realm_id != realm);
        self.scim_groups.retain(|_, value| value.realm_id != realm);
        self.scim_devices.retain(|_, value| value.realm_id != realm);
        self.scim_event_subscriptions
            .retain(|_, value| value.realm_id != realm);
        self.fedcm_identities
            .retain(|_, value| value.realm_id != realm);
        self.workload_identities
            .retain(|_, value| value.realm_id != realm);
        self.workload_certificates
            .retain(|_, value| value.realm_id != realm);
        self.custom_domains
            .retain(|_, value| value.realm_id != realm);
        self.ciam_brands.retain(|_, value| value.realm_id != realm);
        self.app_catalog_entries
            .retain(|_, value| value.realm_id != realm);
        self.ssf_streams.retain(|_, value| value.realm_id != realm);
        // Replay keys start with the complete realm plus the field separator,
        // not a bare realm prefix (e.g. `corp` must not match `corporate`).
        let replay_prefix = format!("{realm}\u{1f}");
        self.ssf_set_replay
            .retain(|key, _| !key.starts_with(&replay_prefix));
        self.realm_issuers.remove(realm);
        self.realm_tenants.remove(realm);
        // Audit events, retention and SIEM deliveries are independent history.
        // Tenant-scoped and namespace-scoped records are not owned by a realm.
    }
}
