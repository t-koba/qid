use async_trait::async_trait;

use super::*;

#[async_trait]
impl ScimRepository for FileRepository {
    async fn create_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn get_scim_user(&self, id: &str) -> QidResult<Option<ScimUser>> {
        let store = self.store.read().await;
        Ok(store.scim_users.get(id).cloned())
    }

    async fn list_scim_users(&self, realm_id: &RealmId) -> QidResult<Vec<ScimUser>> {
        let store = self.store.read().await;
        let mut users: Vec<_> = store
            .scim_users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .cloned()
            .collect();
        users.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(users)
    }

    async fn update_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn delete_scim_user(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_users.remove(id);
        drop(store);
        self.save().await
    }

    async fn create_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_groups.insert(group.id.clone(), group.clone());
        drop(store);
        self.save().await
    }

    async fn list_scim_groups(&self, realm_id: &RealmId) -> QidResult<Vec<ScimGroup>> {
        let store = self.store.read().await;
        let mut groups: Vec<_> = store
            .scim_groups
            .values()
            .filter(|g| g.realm_id == realm_id.0)
            .cloned()
            .collect();
        groups.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(groups)
    }

    async fn get_scim_group(&self, id: &str) -> QidResult<Option<ScimGroup>> {
        let store = self.store.read().await;
        Ok(store.scim_groups.get(id).cloned())
    }

    async fn update_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_groups.insert(group.id.clone(), group.clone());
        drop(store);
        self.save().await
    }

    async fn delete_scim_group(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_groups.remove(id);
        drop(store);
        self.save().await
    }

    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.scim_devices.insert(device.id.clone(), device.clone());
        drop(store);
        self.save().await
    }

    async fn get_scim_device(&self, id: &str) -> QidResult<Option<ScimDeviceRecord>> {
        let store = self.store.read().await;
        Ok(store.scim_devices.get(id).cloned())
    }

    async fn list_scim_devices(&self, realm_id: &RealmId) -> QidResult<Vec<ScimDeviceRecord>> {
        let store = self.store.read().await;
        let mut devices: Vec<_> = store
            .scim_devices
            .values()
            .filter(|device| device.realm_id == realm_id.0)
            .cloned()
            .collect();
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(devices)
    }

    async fn delete_scim_device(&self, id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let removed = store.scim_devices.remove(id).is_some();
        drop(store);
        if removed {
            self.save().await?;
        }
        Ok(removed)
    }

    async fn upsert_scim_event_subscription(
        &self,
        subscription: &ScimEventSubscriptionRecord,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .scim_event_subscriptions
            .insert(subscription.id.clone(), subscription.clone());
        drop(store);
        self.save().await
    }

    async fn get_scim_event_subscription(
        &self,
        id: &str,
    ) -> QidResult<Option<ScimEventSubscriptionRecord>> {
        let store = self.store.read().await;
        Ok(store.scim_event_subscriptions.get(id).cloned())
    }

    async fn list_scim_event_subscriptions(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<ScimEventSubscriptionRecord>> {
        let store = self.store.read().await;
        let mut subscriptions: Vec<_> = store
            .scim_event_subscriptions
            .values()
            .filter(|subscription| subscription.realm_id == realm_id.0)
            .cloned()
            .collect();
        subscriptions.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(subscriptions)
    }

    async fn delete_scim_event_subscription(&self, id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let removed = store.scim_event_subscriptions.remove(id).is_some();
        drop(store);
        if removed {
            self.save().await?;
        }
        Ok(removed)
    }
}
