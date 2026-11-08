use async_trait::async_trait;

use super::*;

#[async_trait]
impl PolicyRepository for FileRepository {
    async fn create_policy_bundle(&self, bundle: &PolicyBundle) -> QidResult<()> {
        self.insert_new(bundle, |store| &mut store.policy_bundles)
            .await
    }

    async fn get_active_policy_bundle(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Option<PolicyBundle>> {
        let store = self.store.read().await;
        Ok(unique_match(
            store
                .policy_bundles
                .values()
                .filter(|b| b.realm_id == realm_id.0 && b.active),
            "multiple active policy bundles; repair externally",
        )?
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
        self.map_write(|store| drop(store.policy_bundles.remove(id)))
            .await
    }
}
