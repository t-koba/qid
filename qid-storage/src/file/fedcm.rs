use async_trait::async_trait;

use super::*;

#[async_trait]
impl FedCmRepository for FileRepository {
    async fn store_fedcm_identity(&self, identity: &FedCmIdentity) -> QidResult<()> {
        let mut store = self.store.write().await;
        // A FedCM identity record ID names one identity, so a store that
        // carries an ID the store already holds is refused instead of
        // replacing the incumbent. The check runs under the store's
        // exclusive write lock, as atomic as the SQL backend's primary key.
        reject_duplicate_id(store.fedcm_identities.contains_key(&identity.id), || {
            format!("fedcm identity record ID {} already exists", identity.id)
        })?;
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
        self.map_write(|store| store.fedcm_identities.remove(id))
            .await
    }
}
