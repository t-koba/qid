use async_trait::async_trait;

use super::*;

#[async_trait]
impl DeviceRepository for FileRepository {
    async fn register_device(&self, device: &Device) -> QidResult<()> {
        let mut store = self.store.write().await;
        // A device record ID names one device, so a register that carries an
        // ID the store already holds is refused instead of replacing the
        // incumbent. The check runs under the store's exclusive write lock,
        // as atomic as the SQL backend's primary key on `id`.
        if store.devices.contains_key(&device.id) {
            return Err(QidError::Conflict {
                message: format!("device record ID {} already exists", device.id),
            });
        }
        store.devices.insert(device.id.clone(), device.clone());
        drop(store);
        self.save().await
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

    async fn update_device_last_seen(&self, device_id: &str, last_seen_at: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(device) = store.devices.get_mut(device_id) {
            device.last_seen_at = last_seen_at;
        }
        drop(store);
        self.save().await
    }
}
