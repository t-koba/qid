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
        let mut store = self.store.write().await;
        store
            .token_families
            .insert(family.id.clone(), family.clone());
        drop(store);
        self.save().await
    }

    async fn get_token_family(&self, id: &str) -> QidResult<Option<TokenFamily>> {
        let store = self.store.read().await;
        Ok(store.token_families.get(id).cloned())
    }

    async fn update_token_family_refresh_hash(
        &self,
        id: &str,
        refresh_hash: &str,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(family) = store.token_families.get_mut(id) {
            crate::domain::validate_token_family_rotation(family, refresh_hash)?;
            family.current_refresh_hash = refresh_hash.to_string();
        }
        drop(store);
        self.save().await
    }

    async fn revoke_token_family(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(family) = store.token_families.get_mut(id) {
            family.revoked = true;
        }
        drop(store);
        self.save().await
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
        let store = self.store.read().await;
        Ok(store.access_tokens.get(jti).cloned())
    }

    async fn revoke_access_token(&self, jti: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(token) = store.access_tokens.get_mut(jti) {
            token.revoked = true;
        }
        drop(store);
        self.save().await
    }

    async fn store_par_request(&self, req: &ParRequest) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .par_requests
            .insert(req.request_uri.clone(), req.clone());
        drop(store);
        self.save().await
    }

    async fn get_par_request(&self, request_uri: &str) -> QidResult<Option<ParRequest>> {
        let store = self.store.read().await;
        Ok(store.par_requests.get(request_uri).cloned())
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
        store
            .device_authorization_grants
            .insert(grant.device_code_hash.clone(), grant.clone());
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
        store
            .backchannel_authentication_grants
            .insert(grant.auth_req_id_hash.clone(), grant.clone());
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
