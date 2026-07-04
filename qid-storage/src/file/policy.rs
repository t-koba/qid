use async_trait::async_trait;

use super::*;

#[async_trait]
impl PolicyRepository for FileRepository {
    async fn create_policy_bundle(&self, bundle: &PolicyBundle) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .policy_bundles
            .insert(bundle.id.clone(), bundle.clone());
        drop(store);
        self.save().await
    }

    async fn get_active_policy_bundle(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Option<PolicyBundle>> {
        let store = self.store.read().await;
        Ok(store
            .policy_bundles
            .values()
            .find(|b| b.realm_id == realm_id.0 && b.active)
            .cloned())
    }

    async fn list_policy_bundles(&self, realm_id: &RealmId) -> QidResult<Vec<PolicyBundle>> {
        let store = self.store.read().await;
        let mut bundles: Vec<_> = store
            .policy_bundles
            .values()
            .filter(|b| b.realm_id == realm_id.0)
            .cloned()
            .collect();
        bundles.sort_by_key(|bundle| std::cmp::Reverse(bundle.version));
        Ok(bundles)
    }

    async fn delete_policy_bundle(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.policy_bundles.remove(id);
        drop(store);
        self.save().await
    }
}
