use async_trait::async_trait;

use super::*;

#[async_trait]
impl ClientRepository for FileRepository {
    async fn create_client(&self, client: &Client) -> QidResult<()> {
        let mut store = self.store.write().await;
        // A client id names one client in a realm, so a second client that
        // carries it is refused instead of stored. The check runs under the
        // store's exclusive write lock, so the refusal is as atomic as the
        // SQL backend's unique constraint.
        reject_duplicate_id(store.clients.contains_key(&client.id), || {
            format!("client record ID {} already exists", client.id)
        })?;
        if store.clients.values().any(|stored| {
            stored.realm_id == client.realm_id && stored.client_id == client.client_id
        }) {
            return Err(QidError::Conflict {
                message: format!(
                    "client id {} already exists in realm {}",
                    client.client_id, client.realm_id
                ),
            });
        }
        store.clients.insert(client.id.clone(), client.clone());
        drop(store);
        self.save().await
    }

    async fn update_client(&self, client: &Client) -> QidResult<()> {
        self.map_write(|store| store.clients.insert(client.id.clone(), client.clone()))
            .await
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

    async fn find_clients_by_client_id(
        &self,
        realm_ids: &[RealmId],
        client_id: &str,
    ) -> QidResult<Vec<Client>> {
        let store = self.store.read().await;
        Ok(store
            .clients
            .values()
            .filter(|c| c.client_id == client_id && realm_ids.iter().any(|r| r.0 == c.realm_id))
            .cloned()
            .collect())
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
        self.map_write(|store| store.clients.remove(id)).await
    }
}
