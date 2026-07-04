use async_trait::async_trait;

use super::*;

#[async_trait]
impl DeviceRepository for SqlRepository {
    async fn register_device(&self, device: &Device) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO devices (id, user_id, realm_id, device_name, device_type, posture, registered_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&device.id)
        .bind(&device.user_id)
        .bind(&device.realm_id)
        .bind(&device.device_name)
        .bind(&device.device_type)
        .bind(serde_json::to_string(&device.posture).unwrap_or_default())
        .bind(device.registered_at as i64)
        .bind(device.last_seen_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_device(&self, device_id: &str) -> QidResult<Option<Device>> {
        let row: Option<DeviceRow> = sqlx::query_as("SELECT * FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_user_devices(&self, user_id: &str) -> QidResult<Vec<Device>> {
        let rows: Vec<DeviceRow> = sqlx::query_as("SELECT * FROM devices WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_device_last_seen(&self, device_id: &str, last_seen_at: u64) -> QidResult<()> {
        sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
            .bind(last_seen_at as i64)
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
