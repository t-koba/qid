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
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
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
        let prepare = |store: &mut Store| {
            store.remove_realm(realm_id.as_str());
            store
                .realm_issuers
                .insert(realm_id.0.clone(), issuer.to_string());
            store
                .realm_tenants
                .insert(realm_id.0.clone(), tenant.as_str().to_string());
        };
        if let Some(guard) = save_guard {
            let mut candidate = store.clone();
            prepare(&mut candidate);
            #[cfg(test)]
            self.before_flush().await?;
            let content = serde_json::to_string(&candidate).map_err(|e| QidError::Internal {
                message: format!("failed to serialize store: {e}"),
            })?;
            self.write_store_content_locked(&guard, &content).await?;
            *store = candidate;
        } else {
            prepare(&mut store);
            self.dirty.store(true, Ordering::Release);
        }
        Ok(())
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

    async fn delete_realm(&self, id: &RealmId, expected_tenant: &TenantId) -> QidResult<()> {
        if self.flush_mode == FileFlushMode::Immediate {
            // Complete persistence or rollback even if cancelled during I/O.
            let repo = self.clone();
            let id = id.clone();
            let expected_tenant = expected_tenant.clone();
            return tokio::spawn(
                async move { repo.delete_realm_inner(&id, &expected_tenant).await },
            )
            .await
            .map_err(|error| QidError::Internal {
                message: format!("realm deletion task failed: {error}"),
            })?;
        }
        self.delete_realm_inner(id, expected_tenant).await
    }
}

impl FileRepository {
    async fn delete_realm_inner(&self, id: &RealmId, expected_tenant: &TenantId) -> QidResult<()> {
        // Hold both locks through persistence; no tentative state is visible.
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        if store.realm_tenants.get(id.as_str()).map(String::as_str)
            != Some(expected_tenant.as_str())
        {
            return Ok(());
        }
        if let Some(guard) = save_guard {
            let mut candidate = store.clone();
            candidate.remove_realm(id.as_str());
            #[cfg(test)]
            self.before_flush().await?;
            let content = serde_json::to_string(&candidate).map_err(|e| QidError::Internal {
                message: format!("failed to serialize store: {e}"),
            })?;
            self.write_store_content_locked(&guard, &content).await?;
            *store = candidate;
        } else {
            store.remove_realm(id.as_str());
            self.dirty.store(true, Ordering::Release);
        }
        Ok(())
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
        // Replay keys use realm plus separator, not bare prefix (corp vs corporate).
        let replay_prefix = format!("{realm}\u{1f}");
        self.ssf_set_replay
            .retain(|key, _| !key.starts_with(&replay_prefix));
        self.realm_issuers.remove(realm);
        self.realm_tenants.remove(realm);
    }
}
