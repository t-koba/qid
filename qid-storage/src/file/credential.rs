use async_trait::async_trait;

use super::*;

#[async_trait]
impl CredentialRepository for FileRepository {
    async fn get_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        let store = self.store.read().await;
        let credentials = &store.webauthn_credentials;
        let mut ids = std::collections::HashSet::new();
        for credential in credentials.values().flatten() {
            reject_duplicate_id(!ids.insert(&credential.credential_id), || {
                "ambiguous WebAuthn credential ID; repair externally".into()
            })?;
        }
        Ok(credentials.get(user_id).cloned().unwrap_or_default())
    }

    async fn store_webauthn_credential(&self, cred: &WebAuthnCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        let credentials = &mut store.webauthn_credentials;
        reject_duplicate_id(
            credentials
                .values()
                .flatten()
                .any(|c| c.id == cred.id || c.credential_id == cred.credential_id),
            || format!("WebAuthn credential ID conflicts for record {}", cred.id),
        )?;
        credentials
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
            cred.counter = cred.counter.max(counter);
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
        store
            .totp_credentials
            .entry(cred.id.clone())
            .and_modify(|stored| stored.replace_preserving_last_used_step(cred))
            .or_insert_with(|| cred.clone());
        drop(store);
        self.save().await
    }

    async fn get_totp_credential(&self, user_id: &str) -> QidResult<Option<TotpCredential>> {
        Ok(self
            .map_get(|s| s.totp_credentials.values().find(|c| c.user_id == user_id))
            .await)
    }

    async fn consume_totp_step(&self, cred: &TotpCredential, step: u64) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let Some(stored) = store.totp_credentials.get_mut(&cred.id) else {
            return Ok(false);
        };
        if stored.user_id != cred.user_id || stored.last_used_step >= Some(step) {
            return Ok(false);
        }
        stored.last_used_step = Some(step);
        drop(store);
        self.save().await.map(|_| true)
    }
}
