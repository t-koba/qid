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
        store
            .webauthn_credentials
            .entry(cred.user_id.clone())
            .or_default()
            .push(cred.clone());
        drop(store);
        self.save().await
    }

    async fn update_webauthn_credential_counter(&self, id: &str, counter: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        for creds in store.webauthn_credentials.values_mut() {
            if let Some(cred) = creds.iter_mut().find(|c| c.id == id) {
                cred.counter = counter;
                break;
            }
        }
        drop(store);
        self.save().await
    }

    async fn delete_webauthn_credential(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        for creds in store.webauthn_credentials.values_mut() {
            creds.retain(|c| c.id != id);
        }
        drop(store);
        self.save().await
    }

    async fn list_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        let store = self.store.read().await;
        Ok(store
            .webauthn_credentials
            .get(user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn store_totp_credential(&self, cred: &TotpCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
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

    async fn consume_totp_step(&self, credential_id: &str, candidate_step: u64) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let Some(cred) = store.totp_credentials.get_mut(credential_id) else {
            return Ok(false);
        };
        if cred
            .last_used_step
            .is_some_and(|used| used >= candidate_step)
        {
            return Ok(false);
        }
        cred.last_used_step = Some(candidate_step);
        drop(store);
        self.save().await?;
        Ok(true)
    }
}
