use async_trait::async_trait;

use super::*;

#[async_trait]
impl DeviceRepository for FileRepository {
    async fn register_device(&self, device: &Device) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.devices.insert(device.id.clone(), device.clone());
        drop(store);
        self.save().await
    }

    async fn get_device(&self, device_id: &str) -> QidResult<Option<Device>> {
        let store = self.store.read().await;
        Ok(store.devices.get(device_id).cloned())
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

    async fn update_device_last_seen(&self, device_id: &str, last_seen_at: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(device) = store.devices.get_mut(device_id) {
            device.last_seen_at = last_seen_at;
        }
        drop(store);
        self.save().await
    }
}
