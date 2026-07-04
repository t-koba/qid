use async_trait::async_trait;

use super::*;

#[async_trait]
impl ServiceAccountRepository for FileRepository {
    async fn create_service_account(&self, sa: &ServiceAccount) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.service_accounts.insert(sa.id.clone(), sa.clone());
        drop(store);
        self.save().await
    }

    async fn get_service_account_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> QidResult<Option<ServiceAccount>> {
        let store = self.store.read().await;
        Ok(store
            .service_accounts
            .values()
            .find(|sa| sa.realm_id == realm_id && sa.client_id == client_id)
            .cloned())
    }

    async fn list_service_accounts(&self, realm_id: &str) -> QidResult<Vec<ServiceAccount>> {
        let store = self.store.read().await;
        let mut accounts: Vec<_> = store
            .service_accounts
            .values()
            .filter(|sa| sa.realm_id == realm_id)
            .cloned()
            .collect();
        accounts.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(accounts)
    }

    async fn delete_service_account(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.service_accounts.remove(id);
        drop(store);
        self.save().await
    }
}
