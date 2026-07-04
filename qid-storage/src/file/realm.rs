use async_trait::async_trait;

use super::*;

#[async_trait]
impl RealmRepository for FileRepository {
    async fn create_realm(
        &self,
        tenant: &TenantId,
        realm_id: &RealmId,
        issuer: &str,
        _display_name: Option<&str>,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .realm_issuers
            .insert(realm_id.0.clone(), issuer.to_string());
        store
            .realm_tenants
            .insert(realm_id.0.clone(), tenant.as_str().to_string());
        drop(store);
        self.save().await
    }

    async fn get_realm_issuer(&self, id: &RealmId) -> QidResult<Option<String>> {
        let store = self.store.read().await;
        Ok(store.realm_issuers.get(&id.0).cloned())
    }

    async fn get_realm_tenant(&self, id: &RealmId) -> QidResult<Option<String>> {
        let store = self.store.read().await;
        Ok(store.realm_tenants.get(&id.0).cloned())
    }

    async fn list_realms(&self) -> QidResult<Vec<(String, String)>> {
        let store = self.store.read().await;
        let mut realms: Vec<_> = store
            .realm_issuers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        realms.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(realms)
    }

    async fn delete_realm(&self, id: &RealmId) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.realm_issuers.remove(&id.0);
        store.realm_tenants.remove(&id.0);
        drop(store);
        self.save().await
    }
}
