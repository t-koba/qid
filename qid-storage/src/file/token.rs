use async_trait::async_trait;

use super::*;

#[async_trait]
impl TokenRepository for FileRepository {
    async fn create_authorization_code(&self, code: &AuthorizationCode) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .authorization_codes
            .insert(code.code_hash.clone(), code.clone());
        drop(store);
        self.save().await
    }

    async fn get_authorization_code(
        &self,
        code_hash: &str,
    ) -> QidResult<Option<AuthorizationCode>> {
        let store = self.store.read().await;
        Ok(store.authorization_codes.get(code_hash).cloned())
    }

    async fn mark_authorization_code_used(&self, code_hash: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let code = store
            .authorization_codes
            .get_mut(code_hash)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("authorization code {code_hash}"),
            })?;
        if code.used {
            return Err(QidError::Conflict {
                message: "authorization code already consumed".to_string(),
            });
        }
        code.used = true;
        drop(store);
        self.save().await
    }

    async fn create_token_family(&self, family: &TokenFamily) -> QidResult<()> {
        // This operation replaces an existing ID. Serialize it with immediate
        // rotations so their rollback cannot overwrite the replacement's fields.
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        store
            .token_families
            .insert(family.id.clone(), family.clone());
        drop(store);
        match save_guard {
            Some(guard) => self.flush_store_locked(&guard).await,
            None => self.save().await,
        }
    }

    async fn get_token_family(&self, id: &str) -> QidResult<Option<TokenFamily>> {
        Ok(self.map_get(|store| store.token_families.get(id)).await)
    }

    async fn update_token_family_refresh_hash(
        &self,
        id: &str,
        realm_id: &str,
        expected_refresh_hash: &str,
        refresh_hash: &str,
        refresh_expires_at: u64,
    ) -> QidResult<()> {
        // Own persistence before validation/mutation, not just before the write:
        // no other save may snapshot tentative rotation fields before rollback.
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        let family = store
            .token_families
            .get_mut(id)
            .filter(|family| family.realm_id == realm_id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("token family {id}"),
            })?;
        crate::domain::validate_token_family_rotation(family, expected_refresh_hash, refresh_hash)?;
        let previous_hash = family.current_refresh_hash.clone();
        let previous_deadline = family.refresh_expires_at;
        family.current_refresh_hash = refresh_hash.to_string();
        family.refresh_expires_at = Some(refresh_expires_at);
        drop(store);
        #[cfg(test)]
        {
            let hook = self.rotation_hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook.run().await;
            }
        }
        let Some(save_guard) = save_guard else {
            // Interval mode only marks dirty; background flush errors do not
            // undo an accepted in-memory rotation.
            return self.save().await;
        };
        // Handle returned errors while still owning save_lock. This does not
        // provide cancellation safety or hide tentative fields from readers.
        if let Err(save_err) = self.flush_store_locked(&save_guard).await {
            let mut store = self.store.write().await;
            if let Some(family) = store.token_families.get_mut(id) {
                // Preserve concurrent revocation and other unrelated fields.
                family.current_refresh_hash = previous_hash;
                family.refresh_expires_at = previous_deadline;
            }
            return Err(save_err);
        }
        Ok(())
    }

    async fn revoke_token_family(&self, id: &str, realm_id: &str) -> QidResult<()> {
        self.map_write(|store| {
            let family = store.token_families.get_mut(id)?;
            // Revocation is monotonic; foreign realms leave the state unchanged.
            family.revoked |= family.realm_id == realm_id;
            Some(())
        })
        .await
    }

    async fn list_token_families(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
        client_id: Option<&str>,
    ) -> QidResult<Vec<TokenFamily>> {
        let store = self.store.read().await;
        let mut families: Vec<TokenFamily> = store
            .token_families
            .values()
            .filter(|f| f.realm_id == realm_id)
            .filter(|f| user_id.is_none_or(|uid| f.user_id == uid))
            .filter(|f| client_id.is_none_or(|cid| f.client_id == cid))
            .cloned()
            .collect();
        families.sort_by_key(|family| std::cmp::Reverse(family.issued_at));
        Ok(families)
    }

    async fn create_access_token(&self, token: &AccessToken) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.access_tokens.insert(token.jti.clone(), token.clone());
        drop(store);
        self.save().await
    }

    async fn get_access_token(&self, jti: &str) -> QidResult<Option<AccessToken>> {
        Ok(self.map_get(|store| store.access_tokens.get(jti)).await)
    }

    async fn revoke_access_token(&self, jti: &str, realm_id: &str) -> QidResult<()> {
        self.map_write(|store| {
            let token = store.access_tokens.get_mut(jti)?;
            (token.realm_id == realm_id).then(|| token.revoked = true)
        })
        .await
    }

    async fn store_par_request(&self, req: &ParRequest) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.par_requests, req)?;
        drop(store);
        self.save().await
    }

    async fn get_par_request(&self, request_uri: &str) -> QidResult<Option<ParRequest>> {
        Ok(self
            .map_get(|store| store.par_requests.get(request_uri))
            .await)
    }

    async fn mark_par_request_used(&self, request_uri: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let req = store
            .par_requests
            .get_mut(request_uri)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("PAR request {request_uri}"),
            })?;
        if req.used {
            return Err(QidError::Conflict {
                message: "PAR request already consumed".to_string(),
            });
        }
        req.used = true;
        drop(store);
        self.save().await
    }

    async fn store_device_authorization_grant(
        &self,
        grant: &DeviceAuthorizationGrant,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.device_authorization_grants, grant)?;
        drop(store);
        self.save().await
    }

    async fn get_device_authorization_grant(
        &self,
        device_code_hash: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>> {
        let store = self.store.read().await;
        Ok(store
            .device_authorization_grants
            .get(device_code_hash)
            .cloned())
    }

    async fn get_device_authorization_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>> {
        let store = self.store.read().await;
        Ok(store
            .device_authorization_grants
            .values()
            .find(|g| g.user_code == user_code)
            .cloned())
    }

    async fn approve_device_authorization_grant(
        &self,
        user_code: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let Some(grant) = store
            .device_authorization_grants
            .values_mut()
            .find(|grant| grant.user_code == user_code)
        else {
            return Err(QidError::NotFound {
                resource: "device authorization grant".to_string(),
            });
        };
        grant.user_id = Some(user_id.to_string());
        grant.approved_at = Some(approved_at);
        drop(store);
        self.save().await
    }

    async fn record_device_authorization_poll(
        &self,
        device_code_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(grant) = store.device_authorization_grants.get_mut(device_code_hash) {
            grant.last_poll_at = Some(polled_at);
            grant.poll_interval_seconds = poll_interval_seconds;
        }
        drop(store);
        self.save().await
    }

    async fn consume_device_authorization_grant(&self, device_code_hash: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let grant = store
            .device_authorization_grants
            .get_mut(device_code_hash)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("device authorization grant {device_code_hash}"),
            })?;
        if grant.consumed {
            return Err(QidError::Conflict {
                message: "device authorization grant already consumed".to_string(),
            });
        }
        grant.consumed = true;
        drop(store);
        self.save().await
    }

    async fn store_backchannel_authentication_grant(
        &self,
        grant: &BackchannelAuthenticationGrant,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.backchannel_authentication_grants, grant)?;
        drop(store);
        self.save().await
    }

    async fn get_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<Option<BackchannelAuthenticationGrant>> {
        let store = self.store.read().await;
        Ok(store
            .backchannel_authentication_grants
            .get(auth_req_id_hash)
            .cloned())
    }

    async fn approve_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let grant = store
            .backchannel_authentication_grants
            .get_mut(auth_req_id_hash)
            .ok_or_else(|| QidError::NotFound {
                resource: "backchannel authentication grant".to_string(),
            })?;
        grant.user_id = Some(user_id.to_string());
        grant.approved_at = Some(approved_at);
        drop(store);
        self.save().await
    }

    async fn record_backchannel_authentication_poll(
        &self,
        auth_req_id_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(grant) = store
            .backchannel_authentication_grants
            .get_mut(auth_req_id_hash)
        {
            grant.last_poll_at = Some(polled_at);
            grant.poll_interval_seconds = poll_interval_seconds;
        }
        drop(store);
        self.save().await
    }

    async fn consume_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let grant = store
            .backchannel_authentication_grants
            .get_mut(auth_req_id_hash)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("backchannel authentication grant {auth_req_id_hash}"),
            })?;
        if grant.consumed {
            return Err(QidError::Conflict {
                message: "backchannel authentication grant already consumed".to_string(),
            });
        }
        grant.consumed = true;
        drop(store);
        self.save().await
    }
}
