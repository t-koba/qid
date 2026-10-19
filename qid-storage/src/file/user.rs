use async_trait::async_trait;

use super::*;

#[async_trait]
impl UserRepository for FileRepository {
    async fn create_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store.users.get(id).cloned())
    }

    async fn get_user_by_id_in_realm(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store
            .users
            .get(id)
            .filter(|user| user.realm_id == realm_id.0)
            .cloned())
    }

    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store
            .users
            .values()
            .find(|u| u.realm_id == realm_id.0 && u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn list_users(&self, realm_id: &RealmId) -> QidResult<Vec<User>> {
        self.list_users_page(realm_id, 0, usize::MAX).await
    }

    async fn list_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<User>> {
        let store = self.store.read().await;
        let mut users: Vec<_> = store
            .users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .cloned()
            .collect();
        users.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(users.into_iter().skip(offset).take(limit).collect())
    }

    async fn delete_user(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        // Follow ownership links before removing their parents. All live auth state
        // disappears together under this write lock; realm/client peers are untouched.
        let sessions: std::collections::HashSet<_> = store
            .sessions
            .values()
            .filter(|session| session.user_id == id)
            .map(|session| session.id.clone())
            .collect();
        store.authorization_codes.retain(|_, code| {
            code.user_id != id
                && !code
                    .session_id
                    .as_ref()
                    .is_some_and(|sid| sessions.contains(sid))
        });
        let families: std::collections::HashSet<_> = store
            .token_families
            .values()
            .filter(|family| {
                family.user_id == id
                    || family
                        .session_id
                        .as_ref()
                        .is_some_and(|sid| sessions.contains(sid))
            })
            .map(|family| family.id.clone())
            .collect();
        store.access_tokens.retain(|_, token| {
            token.user_id != id
                && !token
                    .family_id
                    .as_ref()
                    .is_some_and(|fid| families.contains(fid))
        });
        store
            .token_families
            .retain(|fid, _| !families.contains(fid));
        store.sessions.retain(|sid, _| !sessions.contains(sid));
        store.webauthn_credentials.remove(id);
        store.totp_credentials.retain(|_, cred| cred.user_id != id);
        store.devices.retain(|_, device| device.user_id != id);
        store
            .device_authorization_grants
            .retain(|_, grant| grant.user_id.as_deref() != Some(id));
        store
            .backchannel_authentication_grants
            .retain(|_, grant| grant.user_id.as_deref() != Some(id));
        store.users.remove(id);
        store.credentials_password.remove(id);
        store
            .ciam_profiles
            .retain(|_, profile| profile.user_id != id);
        store
            .ciam_consent_grants
            .retain(|_, grant| grant.user_id != id);
        store
            .ciam_verification_challenges
            .retain(|_, challenge| challenge.user_id != id);
        store
            .ciam_identity_links
            .retain(|_, link| link.user_id != id);
        store
            .password_reset_tokens
            .retain(|_, token| token.user_id != id);
        drop(store);
        self.save().await
    }

    async fn update_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .credentials_password
            .insert(cred.user_id.clone(), cred.clone());
        drop(store);
        self.save().await
    }

    async fn get_password_credential(
        &self,
        user_id: &str,
    ) -> QidResult<Option<PasswordCredential>> {
        let store = self.store.read().await;
        Ok(store.credentials_password.get(user_id).cloned())
    }
}
