use async_trait::async_trait;

use super::*;

#[async_trait]
impl UserRepository for FileRepository {
    async fn create_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store.users.get(id).cloned())
    }

    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store
            .users
            .values()
            .find(|u| u.realm_id == realm_id.0 && u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn list_users(&self, realm_id: &RealmId) -> QidResult<Vec<User>> {
        let store = self.store.read().await;
        let mut users: Vec<_> = store
            .users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .cloned()
            .collect();
        users.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(users)
    }

    async fn delete_user(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.users.remove(id);
        store.credentials_password.remove(id);
        drop(store);
        self.save().await
    }

    async fn update_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .credentials_password
            .insert(cred.user_id.clone(), cred.clone());
        drop(store);
        self.save().await
    }

    async fn get_password_credential(
        &self,
        user_id: &str,
    ) -> QidResult<Option<PasswordCredential>> {
        let store = self.store.read().await;
        Ok(store.credentials_password.get(user_id).cloned())
    }
}
