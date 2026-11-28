use async_trait::async_trait;

use super::*;

#[async_trait]
impl ClientRepository for FileRepository {
    async fn create_client(&self, client: &Client) -> QidResult<()> {
        self.insert_new(client, |store| &mut store.clients).await
    }

    async fn update_client(&self, client: &Client) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store.clients.contains_key(&client.id) {
            crate::ownership::ensure_same_binding(
                store
                    .clients
                    .get(&client.id)
                    .map(|stored| (stored.realm_id.as_str(), stored.client_id.as_str())),
                (client.realm_id.as_str(), client.client_id.as_str()),
                || "client ID belongs to another identity".to_string(),
            )?;
            store.clients.insert(client.id.clone(), client.clone());
        } else {
            super::insert::insert_new_in_store(&mut store, client, |store| &mut store.clients)?;
        }
        drop(store);
        self.save().await
    }

    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>> {
        let store = self.store.read().await;
        super::unique_match(
            store
                .clients
                .values()
                .filter(|client| client.realm_id == realm_id.0 && client.client_id == client_id)
                .cloned(),
            "client identity is ambiguous",
        )
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

    async fn delete_client(&self, realm_id: &RealmId, id: &str) -> QidResult<()> {
        self.map_write(|store| {
            // Grants name the public client id, not the record ID. Take the
            // binding from the registration being removed so a missing or
            // foreign delete cannot end another client's grants.
            let client_id = store
                .clients
                .get(id)
                .filter(|client| client.realm_id.as_str() == realm_id.as_str())
                .map(|client| client.client_id.clone());
            if let Some(client_id) = client_id {
                // Revocation is monotonic; records stay for audit history and
                // other realms and clients keep their grants.
                for family in store.token_families.values_mut() {
                    family.revoked |=
                        family.realm_id == realm_id.as_str() && family.client_id == client_id;
                }
                for token in store.access_tokens.values_mut() {
                    token.revoked |=
                        token.realm_id == realm_id.as_str() && token.client_id == client_id;
                }
                for code in store.authorization_codes.values_mut() {
                    code.used |= code.realm_id == realm_id.as_str() && code.client_id == client_id;
                }
                for grant in store.device_authorization_grants.values_mut() {
                    grant.consumed |=
                        grant.realm_id == realm_id.as_str() && grant.client_id == client_id;
                }
                for grant in store.backchannel_authentication_grants.values_mut() {
                    grant.consumed |=
                        grant.realm_id == realm_id.as_str() && grant.client_id == client_id;
                }
                for par in store.par_requests.values_mut() {
                    par.used |= par.realm_id == realm_id.as_str() && par.client_id == client_id;
                }
                store.clients.remove(id);
            }
        })
        .await
    }
}
