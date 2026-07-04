use async_trait::async_trait;

use super::*;

#[async_trait]
impl VcRepository for FileRepository {
    async fn store_vc_credential_status(&self, status: &VcCredentialStatusRecord) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .vc_credential_statuses
            .insert(status.credential_id.clone(), status.clone());
        drop(store);
        self.save().await
    }

    async fn get_vc_credential_status(
        &self,
        credential_id: &str,
    ) -> QidResult<Option<VcCredentialStatusRecord>> {
        let store = self.store.read().await;
        Ok(store.vc_credential_statuses.get(credential_id).cloned())
    }

    async fn revoke_vc_credential(
        &self,
        credential_id: &str,
        reason: &str,
        revoked_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let Some(status) = store.vc_credential_statuses.get_mut(credential_id) else {
            return Err(QidError::NotFound {
                resource: "VC credential status".to_string(),
            });
        };
        status.revoked = true;
        status.revocation_reason = Some(reason.to_string());
        status.revoked_at = Some(revoked_at);
        drop(store);
        self.save().await
    }
}
