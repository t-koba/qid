use async_trait::async_trait;

use super::*;

#[async_trait]
impl FedCmRepository for FileRepository {
    async fn store_fedcm_identity(&self, identity: &FedCmIdentity) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .fedcm_identities
            .insert(identity.id.clone(), identity.clone());
        drop(store);
        self.save().await
    }

    async fn get_fedcm_identities(
        &self,
        realm_id: &RealmId,
        account_id: &str,
    ) -> QidResult<Vec<FedCmIdentity>> {
        let store = self.store.read().await;
        let mut identities: Vec<_> = store
            .fedcm_identities
            .values()
            .filter(|i| i.realm_id == realm_id.0 && i.account_id == account_id)
            .cloned()
            .collect();
        identities.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(identities)
    }

    async fn delete_fedcm_identity(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.fedcm_identities.remove(id);
        drop(store);
        self.save().await
    }
}
