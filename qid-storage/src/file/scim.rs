use async_trait::async_trait;

use super::*;
use crate::{ScimMutation, ScimMutator};

#[async_trait]
impl ScimRepository for FileRepository {
    async fn get_hr_receipt(
        &self,
        realm_id: &str,
        provider_id: &str,
    ) -> QidResult<Option<crate::HrReceipt>> {
        self.read_hr_receipt(realm_id, provider_id).await
    }
    async fn apply_hr_batch(&self, batch: &crate::HrBatch) -> QidResult<crate::HrBatchResult> {
        self.commit_hr_batch(batch).await
    }

    async fn create_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.scim_users, user)?;
        drop(store);
        self.save().await
    }

    async fn get_scim_user(&self, id: &str) -> QidResult<Option<ScimUser>> {
        Ok(self.map_get(|store| store.scim_users.get(id)).await)
    }

    async fn list_scim_users(&self, realm_id: &RealmId) -> QidResult<Vec<ScimUser>> {
        self.list_scim_users_page(realm_id, 0, usize::MAX).await
    }

    async fn list_scim_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<ScimUser>> {
        let store = self.store.read().await;
        let mut users: Vec<_> = store
            .scim_users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .cloned()
            .collect();
        users.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(users.into_iter().skip(offset).take(limit).collect())
    }

    async fn count_scim_users(&self, realm_id: &RealmId) -> QidResult<usize> {
        let store = self.store.read().await;
        Ok(store
            .scim_users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .count())
    }

    async fn update_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        self.mutate_scim_user(
            &user.id,
            Box::new(|_| Ok(ScimMutation::Replace(user.clone()))),
        )
        .await
        .map(|_| ())
    }

    async fn mutate_scim_user(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimUser>,
    ) -> QidResult<Option<ScimUser>> {
        self.mutate_resource(
            id,
            mutation,
            |store| &mut store.scim_users,
            |a, b| a.id == b.id && a.realm_id == b.realm_id,
        )
        .await
    }

    async fn delete_scim_user(&self, id: &str) -> QidResult<()> {
        self.map_write(|store| store.scim_users.remove(id)).await
    }

    async fn create_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.scim_groups, group)?;
        drop(store);
        self.save().await
    }

    async fn list_scim_groups(&self, realm_id: &RealmId) -> QidResult<Vec<ScimGroup>> {
        self.list_scim_groups_page(realm_id, 0, usize::MAX).await
    }

    async fn list_scim_groups_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<ScimGroup>> {
        let store = self.store.read().await;
        let mut groups: Vec<_> = store
            .scim_groups
            .values()
            .filter(|g| g.realm_id == realm_id.0)
            .cloned()
            .collect();
        groups.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(groups.into_iter().skip(offset).take(limit).collect())
    }

    async fn count_scim_groups(&self, realm_id: &RealmId) -> QidResult<usize> {
        let store = self.store.read().await;
        Ok(store
            .scim_groups
            .values()
            .filter(|g| g.realm_id == realm_id.0)
            .count())
    }

    async fn get_scim_group(&self, id: &str) -> QidResult<Option<ScimGroup>> {
        Ok(self.map_get(|store| store.scim_groups.get(id)).await)
    }

    async fn update_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        self.map_write(|store| store.scim_groups.insert(group.id.clone(), group.clone()))
            .await
    }

    async fn mutate_scim_group(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimGroup>,
    ) -> QidResult<Option<ScimGroup>> {
        self.mutate_resource(
            id,
            mutation,
            |store| &mut store.scim_groups,
            |a, b| a.id == b.id && a.realm_id == b.realm_id,
        )
        .await
    }

    async fn delete_scim_group(&self, id: &str) -> QidResult<()> {
        self.map_write(|store| store.scim_groups.remove(id)).await
    }

    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()> {
        let mut store = self.store.write().await;
        crate::ownership::ensure_same_binding(
            store
                .scim_devices
                .get(&device.id)
                .map(|existing| &existing.realm_id),
            &device.realm_id,
            || "SCIM device ID belongs to another realm".to_string(),
        )?;
        store.scim_devices.insert(device.id.clone(), device.clone());
        drop(store);
        self.save().await
    }

    async fn get_scim_device(&self, id: &str) -> QidResult<Option<ScimDeviceRecord>> {
        Ok(self.map_get(|store| store.scim_devices.get(id)).await)
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
        crate::ownership::ensure_same_binding(
            store
                .scim_event_subscriptions
                .get(&subscription.id)
                .map(|existing| &existing.realm_id),
            &subscription.realm_id,
            || "SCIM event subscription ID belongs to another realm".to_string(),
        )?;
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

impl FileRepository {
    /// Apply the callback under the exclusive store lock and flush applied writes.
    async fn mutate_resource<T: Clone>(
        &self,
        id: &str,
        mutation: ScimMutator<'_, T>,
        resources: fn(&mut Store) -> &mut HashMap<String, T>,
        same_identity: fn(&T, &T) -> bool,
    ) -> QidResult<Option<T>> {
        let mut store = self.store.write().await;
        let resources = resources(&mut store);
        let Some(current) = resources.get(id) else {
            return Ok(None);
        };
        let result = match mutation(current)? {
            ScimMutation::Reject => return Ok(None),
            ScimMutation::Replace(replacement) => {
                if !same_identity(current, &replacement) {
                    return Err(QidError::BadRequest {
                        message: "serialized mutation cannot change resource identity".into(),
                    });
                }
                resources.insert(id.to_string(), replacement.clone());
                replacement
            }
            ScimMutation::Delete => resources.remove(id).expect("locked row exists"),
        };
        drop(store);
        self.save().await?;
        Ok(Some(result))
    }
}
