use async_trait::async_trait;

use super::*;

#[async_trait]
impl CiamRepository for FileRepository {
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()> {
        grant.validate()?;
        crate::domain::validate_ciam_consent_grant_state(grant)?;
        let mut store = self.store.write().await;
        crate::ownership::ensure_same_binding(
            store
                .ciam_consent_grants
                .get(&grant.id)
                .map(|existing| (&existing.realm_id, &existing.user_id, &existing.client_id)),
            (&grant.realm_id, &grant.user_id, &grant.client_id),
            || format!("CIAM consent grant {} belongs to another owner", grant.id),
        )?;
        store
            .ciam_consent_grants
            .insert(grant.id.clone(), grant.clone());
        drop(store);
        self.save().await
    }

    async fn list_ciam_consent_grants(
        &self,
        realm_id: &RealmId,
        user_id: &str,
        client_id: Option<&str>,
    ) -> QidResult<Vec<CiamConsentGrant>> {
        let store = self.store.read().await;
        let mut grants = store
            .ciam_consent_grants
            .values()
            .filter(|grant| grant.realm_id == realm_id.0 && grant.user_id == user_id)
            .filter(|grant| client_id.is_none_or(|client_id| grant.client_id == client_id))
            .cloned()
            .collect::<Vec<_>>();
        grants.sort_by(|a, b| {
            b.granted_at_epoch_seconds
                .cmp(&a.granted_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(grants)
    }

    async fn revoke_ciam_consent_grant(&self, id: &str, _revoked_at: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        let grant = store
            .ciam_consent_grants
            .get_mut(id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("CIAM consent grant {id}"),
            })?;
        grant.revoked = true;
        drop(store);
        self.save().await
    }

    async fn store_ciam_verification_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
    ) -> QidResult<()> {
        challenge.validate()?;
        let mut store = self.store.write().await;
        if store
            .ciam_verification_challenges
            .contains_key(&challenge.id)
        {
            return Err(QidError::Conflict {
                message: format!(
                    "CIAM verification challenge ID {} already exists",
                    challenge.id
                ),
            });
        }
        store
            .ciam_verification_challenges
            .insert(challenge.id.clone(), challenge.clone());
        drop(store);
        self.save().await
    }

    async fn get_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>> {
        let store = self.store.read().await;
        Ok(store
            .ciam_verification_challenges
            .get(id)
            .filter(|challenge| challenge.realm_id == realm_id.0)
            .cloned())
    }

    async fn consume_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
        consumed_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let challenge = store
            .ciam_verification_challenges
            .get_mut(id)
            .filter(|challenge| challenge.realm_id == realm_id.0)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("CIAM verification challenge {id}"),
            })?;
        if challenge.consumed_at_epoch_seconds.is_some() {
            return Err(QidError::Conflict {
                message: "CIAM verification challenge already consumed".to_string(),
            });
        }
        challenge.consumed_at_epoch_seconds = Some(consumed_at);
        drop(store);
        self.save().await
    }

    async fn store_ciam_identity_link(&self, link: &CiamIdentityLink) -> QidResult<()> {
        link.validate()?;
        let mut store = self.store.write().await;
        let existing = store.ciam_identity_links.get(&link.id);
        crate::domain::validate_ciam_identity_link_state(link, existing)?;
        let Some(user) = store.users.get(&link.user_id) else {
            return Err(QidError::BadRequest {
                message: "CIAM identity link user does not exist".to_string(),
            });
        };
        if user.realm_id != link.realm_id {
            return Err(QidError::BadRequest {
                message: "CIAM identity link user belongs to another realm".to_string(),
            });
        }
        if store.ciam_identity_links.values().any(|stored| {
            link.verified
                && stored.verified
                && stored.id != link.id
                && stored.realm_id == link.realm_id
                && stored.provider == link.provider
                && stored.external_subject == link.external_subject
        }) {
            return Err(QidError::BadRequest {
                message: "CIAM identity link external subject is already linked".to_string(),
            });
        }
        store
            .ciam_identity_links
            .insert(link.id.clone(), link.clone());
        drop(store);
        self.save().await
    }

    async fn list_ciam_identity_links(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Vec<CiamIdentityLink>> {
        let store = self.store.read().await;
        let mut links = store
            .ciam_identity_links
            .values()
            .filter(|link| link.realm_id == realm_id.0 && link.user_id == user_id)
            .cloned()
            .collect::<Vec<_>>();
        links.sort_by(|a, b| {
            b.linked_at_epoch_seconds
                .cmp(&a.linked_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(links)
    }

    async fn get_ciam_identity_link(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamIdentityLink>> {
        let store = self.store.read().await;
        Ok(store
            .ciam_identity_links
            .get(id)
            .filter(|link| link.realm_id == realm_id.0)
            .cloned())
    }

    async fn get_ciam_identity_link_by_external_subject(
        &self,
        realm_id: &RealmId,
        provider: &str,
        external_subject: &str,
    ) -> QidResult<Option<CiamIdentityLink>> {
        let store = self.store.read().await;
        Ok(store
            .ciam_identity_links
            .values()
            .find(|link| {
                link.verified
                    && link.realm_id == realm_id.0
                    && link.provider == provider
                    && link.external_subject == external_subject
            })
            .cloned())
    }

    async fn delete_ciam_identity_link(&self, realm_id: &RealmId, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .ciam_identity_links
            .get(id)
            .is_some_and(|link| link.realm_id == realm_id.0)
        {
            store.ciam_identity_links.remove(id);
        }
        drop(store);
        self.save().await
    }

    async fn store_password_reset_token(&self, token: &PasswordResetToken) -> QidResult<()> {
        token.validate()?;
        let mut store = self.store.write().await;
        store
            .password_reset_tokens
            .insert(token.id.clone(), token.clone());
        drop(store);
        self.save().await
    }

    async fn get_password_reset_token(&self, id: &str) -> QidResult<Option<PasswordResetToken>> {
        Ok(self
            .map_get(|store| store.password_reset_tokens.get(id))
            .await)
    }

    async fn consume_password_reset_token(&self, id: &str, consumed_at: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        let token = store
            .password_reset_tokens
            .get_mut(id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("password reset token {id}"),
            })?;
        if token.consumed_at_epoch_seconds.is_some() {
            return Err(QidError::Conflict {
                message: "password reset token already consumed".to_string(),
            });
        }
        token.consumed_at_epoch_seconds = Some(consumed_at);
        drop(store);
        self.save().await
    }

    async fn replace_password_with_reset_token(
        &self,
        id: &str,
        realm_id: &RealmId,
        token_hash: &str,
        device_id: Option<&str>,
        credential: &PasswordCredential,
        consumed_at: u64,
    ) -> QidResult<()> {
        if self.flush_mode != FileFlushMode::Immediate {
            return self
                .replace_password_with_reset_token_inner(
                    id,
                    realm_id,
                    token_hash,
                    device_id,
                    credential,
                    consumed_at,
                )
                .await;
        }
        // Once started, immediate resets finish persistence or rollback even if
        // the caller disappears during a filesystem await. The task owns the
        // repository (including its process lock) until that work is complete.
        let repo = self.clone();
        let id = id.to_owned();
        let realm_id = realm_id.clone();
        let token_hash = token_hash.to_owned();
        let device_id = device_id.map(str::to_owned);
        let credential = credential.clone();
        tokio::spawn(async move {
            repo.replace_password_with_reset_token_inner(
                &id,
                &realm_id,
                &token_hash,
                device_id.as_deref(),
                &credential,
                consumed_at,
            )
            .await
        })
        .await
        .map_err(|e| QidError::Internal {
            message: format!("password reset task failed: {e}"),
        })?
    }

    async fn get_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Option<CiamProgressiveProfile>> {
        let store = self.store.read().await;
        let key = ciam_progressive_profile_key(&realm_id.0, user_id);
        Ok(store.ciam_profiles.get(&key).cloned())
    }

    async fn store_ciam_progressive_profile(
        &self,
        profile: &CiamProgressiveProfile,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let key = ciam_progressive_profile_key(&profile.realm_id, &profile.user_id);
        let incumbent = store.ciam_profiles.get(&key);
        // Preserve legacy file snapshots that already contain duplicate IDs
        // across distinct owners; only a new owner attempting that ID conflicts.
        if incumbent.is_none() {
            for stored in store
                .ciam_profiles
                .values()
                .filter(|stored| stored.id == profile.id)
            {
                crate::ownership::ensure_same_binding(
                    Some((&stored.realm_id, &stored.user_id)),
                    (&profile.realm_id, &profile.user_id),
                    || {
                        format!(
                            "CIAM progressive profile {} belongs to another owner",
                            profile.id
                        )
                    },
                )?;
            }
        }
        crate::ownership::ensure_same_binding(
            incumbent.map(|stored| (&stored.id, &stored.realm_id, &stored.user_id)),
            (&profile.id, &profile.realm_id, &profile.user_id),
            || "CIAM progressive profile identity cannot change".to_string(),
        )?;
        store.ciam_profiles.insert(key, profile.clone());
        drop(store);
        self.save().await
    }

    async fn delete_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let key = ciam_progressive_profile_key(&realm_id.0, user_id);
        store.ciam_profiles.remove(&key);
        drop(store);
        self.save().await
    }

    async fn list_ciam_passwordless_migrations(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<CiamProgressiveProfile>> {
        let store = self.store.read().await;
        let mut profiles = store
            .ciam_profiles
            .values()
            .filter(|p| p.realm_id == realm_id.0 && p.passwordless_migrated_at.is_some())
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(profiles)
    }
}

impl FileRepository {
    async fn replace_password_with_reset_token_inner(
        &self,
        id: &str,
        realm_id: &RealmId,
        token_hash: &str,
        device_id: Option<&str>,
        credential: &PasswordCredential,
        consumed_at: u64,
    ) -> QidResult<()> {
        // Lock order is save -> store. Keep the exclusive Store lock through
        // persistence/rollback so readers and unrelated writers cannot observe
        // tentative credentials or have their changes overwritten by rollback.
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        let token = store
            .password_reset_tokens
            .get(id)
            .ok_or_else(|| QidError::NotFound {
                resource: "password reset token".into(),
            })?;
        crate::domain::validate_password_reset(
            token,
            realm_id,
            token_hash,
            device_id,
            credential,
            consumed_at,
        )?;
        let previous = store
            .credentials_password
            .insert(credential.user_id.clone(), credential.clone());
        store
            .password_reset_tokens
            .get_mut(id)
            .unwrap()
            .consumed_at_epoch_seconds = Some(consumed_at);
        let Some(save_guard) = save_guard else {
            // Mark dirty while still holding Store; interval flushes snapshot
            // both mutations together and retain their existing retry semantics.
            self.dirty.store(true, Ordering::Release);
            return Ok(());
        };
        let result = async {
            #[cfg(test)]
            self.before_flush().await?;
            let content = serde_json::to_string(&*store).map_err(|e| QidError::Internal {
                message: format!("failed to serialize store: {e}"),
            })?;
            self.write_store_content_locked(&save_guard, &content).await
        }
        .await;
        if result.is_err() {
            match previous {
                Some(previous) => {
                    store
                        .credentials_password
                        .insert(credential.user_id.clone(), previous);
                }
                None => {
                    store.credentials_password.remove(&credential.user_id);
                }
            }
            store
                .password_reset_tokens
                .get_mut(id)
                .unwrap()
                .consumed_at_epoch_seconds = None;
        }
        result
    }
}
