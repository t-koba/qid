use async_trait::async_trait;

use super::*;

#[async_trait]
impl FedCmRepository for FileRepository {
    async fn store_fedcm_identity(&self, identity: &FedCmIdentity) -> QidResult<()> {
        self.insert_id_if_absent(
            |store| &mut store.fedcm_identities,
            identity.id.clone(),
            identity.clone(),
            || format!("fedcm identity record ID {} already exists", identity.id),
        )
        .await
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
        self.map_write(|store| drop(store.fedcm_identities.remove(id)))
            .await
    }
}
