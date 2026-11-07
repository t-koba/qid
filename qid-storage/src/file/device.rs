use async_trait::async_trait;

use super::*;

#[async_trait]
impl DeviceRepository for FileRepository {
    async fn register_device(&self, device: &Device) -> QidResult<()> {
        self.insert_id_if_absent(
            |store| &mut store.devices,
            device.id.clone(),
            device.clone(),
            || format!("device record ID {} already exists", device.id),
        )
        .await
    }

    async fn get_device(&self, device_id: &str) -> QidResult<Option<Device>> {
        Ok(self.map_get(|store| store.devices.get(device_id)).await)
    }

    async fn get_user_devices(&self, user_id: &str) -> QidResult<Vec<Device>> {
        let store = self.store.read().await;
        let mut devices: Vec<_> = store
            .devices
            .values()
            .filter(|d| d.user_id == user_id)
            .cloned()
            .collect();
        devices.sort_by_key(|device| device.registered_at);
        Ok(devices)
    }

    async fn update_device_last_seen(&self, device: &Device) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(stored) = store.devices.get_mut(&device.id)
            && stored.realm_id == device.realm_id
            && stored.user_id == device.user_id
        {
            stored.last_seen_at = stored.last_seen_at.max(device.last_seen_at);
        }
        drop(store);
        self.save().await
    }
}
