use async_trait::async_trait;

use super::*;

#[async_trait]
impl ClientRepository for FileRepository {
    async fn create_client(&self, client: &Client) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.clients.insert(client.id.clone(), client.clone());
        drop(store);
        self.save().await
    }

    async fn update_client(&self, client: &Client) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.clients.insert(client.id.clone(), client.clone());
        drop(store);
        self.save().await
    }

    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>> {
        let store = self.store.read().await;
        Ok(store
            .clients
            .values()
            .find(|c| c.realm_id == realm_id.0 && c.client_id == client_id)
            .cloned())
    }

    async fn list_clients(&self, realm_id: &RealmId) -> QidResult<Vec<Client>> {
        self.list_clients_page(realm_id, 0, usize::MAX).await
    }

    async fn list_clients_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<Client>> {
        let store = self.store.read().await;
        let mut clients: Vec<_> = store
            .clients
            .values()
            .filter(|c| c.realm_id == realm_id.0)
            .cloned()
            .collect();
        clients.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(clients.into_iter().skip(offset).take(limit).collect())
    }

    async fn delete_client(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.clients.remove(id);
        drop(store);
        self.save().await
    }
}
