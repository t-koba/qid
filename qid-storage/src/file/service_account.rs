use async_trait::async_trait;

use super::*;

#[async_trait]
impl ServiceAccountRepository for FileRepository {
    async fn create_service_account(&self, sa: &ServiceAccount) -> QidResult<()> {
        let mut store = self.store.write().await;
        let accounts = &mut store.service_accounts;
        reject_duplicate_id(
            accounts.contains_key(&sa.id)
                || accounts
                    .values()
                    .any(|a| a.realm_id == sa.realm_id && a.client_id == sa.client_id),
            || "service account ID or realm/client already exists".into(),
        )?;
        accounts.insert(sa.id.clone(), sa.clone());
        drop(store);
        self.save().await
    }

    async fn get_service_account_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> QidResult<Option<ServiceAccount>> {
        let store = self.store.read().await;
        let mut matches = store
            .service_accounts
            .values()
            .filter(|sa| sa.realm_id == realm_id && sa.client_id == client_id);
        let account = matches.next();
        reject_duplicate_id(matches.next().is_some(), || {
            "ambiguous service account realm/client identity; repair externally".into()
        })?;
        Ok(account.cloned())
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

    async fn delete_service_account(&self, realm: Option<&str>, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let accounts = &store.service_accounts;
        if realm.is_some_and(|r| accounts.get(id).is_none_or(|a| a.realm_id != r)) {
            return crate::ownership::ensure_row_present(0, || format!("service account {id}"));
        }
        store.service_accounts.remove(id);
        drop(store);
        self.save().await
    }
}
