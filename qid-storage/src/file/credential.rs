use async_trait::async_trait;

use super::*;

#[async_trait]
impl CredentialRepository for FileRepository {
    async fn get_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        let store = self.store.read().await;
        Ok(store
            .webauthn_credentials
            .get(user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn store_webauthn_credential(&self, cred: &WebAuthnCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .webauthn_credentials
            .values()
            .flatten()
            .any(|incumbent| incumbent.id == cred.id)
        {
            return Err(QidError::Conflict {
                message: format!("WebAuthn credential record ID {} already exists", cred.id),
            });
        }
        store
            .webauthn_credentials
            .entry(cred.user_id.clone())
            .or_default()
            .push(cred.clone());
        drop(store);
        self.save().await
    }

    async fn update_webauthn_credential_counter(
        &self,
        user_id: &str,
        id: &str,
        counter: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(cred) = store
            .webauthn_credentials
            .get_mut(user_id)
            .and_then(|creds| creds.iter_mut().find(|c| c.id == id))
        {
            cred.counter = counter;
        }
        drop(store);
        self.save().await
    }

    async fn delete_webauthn_credential(&self, user_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(creds) = store.webauthn_credentials.get_mut(user_id) {
            creds.retain(|c| c.id != id);
        }
        drop(store);
        self.save().await
    }

    async fn store_totp_credential(&self, cred: &TotpCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        crate::ownership::ensure_same_binding(
            store
                .totp_credentials
                .get(&cred.id)
                .map(|stored| stored.user_id.as_str()),
            cred.user_id.as_str(),
            || format!("TOTP credential ID {} belongs to another user", cred.id),
        )?;
        store.totp_credentials.insert(cred.id.clone(), cred.clone());
        drop(store);
        self.save().await
    }

    async fn get_totp_credential(&self, user_id: &str) -> QidResult<Option<TotpCredential>> {
        let store = self.store.read().await;
        Ok(store
            .totp_credentials
            .values()
            .find(|c| c.user_id == user_id)
            .cloned())
    }

    async fn consume_totp_step(&self, cred: &TotpCredential, step: u64) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let Some(stored) = store.totp_credentials.get_mut(&cred.id) else {
            return Ok(false);
        };
        if stored.user_id != cred.user_id || stored.last_used_step.is_some_and(|used| used >= step)
        {
            return Ok(false);
        }
        stored.last_used_step = Some(step);
        drop(store);
        self.save().await?;
        Ok(true)
    }
}
