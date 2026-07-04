use async_trait::async_trait;

use super::*;

#[async_trait]
impl CiamRepository for FileRepository {
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()> {
        grant.validate()?;
        crate::domain::validate_ciam_consent_grant_state(grant)?;
        let mut store = self.store.write().await;
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
        store
            .ciam_verification_challenges
            .insert(challenge.id.clone(), challenge.clone());
        drop(store);
        self.save().await
    }

    async fn get_ciam_verification_challenge(
        &self,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>> {
        let store = self.store.read().await;
        Ok(store.ciam_verification_challenges.get(id).cloned())
    }

    async fn consume_ciam_verification_challenge(
        &self,
        id: &str,
        consumed_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let challenge = store
            .ciam_verification_challenges
            .get_mut(id)
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
            stored.id != link.id
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
                link.realm_id == realm_id.0
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
        let store = self.store.read().await;
        Ok(store.password_reset_tokens.get(id).cloned())
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

    async fn get_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Option<CiamProgressiveProfile>> {
        let store = self.store.read().await;
        let key = format!("{}:{}", realm_id.0, user_id);
        Ok(store.ciam_profiles.get(&key).cloned())
    }

    async fn store_ciam_progressive_profile(
        &self,
        profile: &CiamProgressiveProfile,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let key = format!("{}:{}", profile.realm_id, profile.user_id);
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
        let key = format!("{}:{}", realm_id.0, user_id);
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
