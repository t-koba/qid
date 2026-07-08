use async_trait::async_trait;

use super::*;

#[derive(sqlx::FromRow)]
struct ScimDeviceRow {
    id: String,
    realm_id: String,
    display_name: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    last_seen: Option<i64>,
}

impl From<ScimDeviceRow> for ScimDeviceRecord {
    fn from(row: ScimDeviceRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            display_name: row.display_name,
            manufacturer: row.manufacturer,
            model: row.model,
            os: row.os,
            os_version: row.os_version,
            last_seen: row.last_seen.map(|value| value as u64),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ScimEventSubscriptionRow {
    id: String,
    realm_id: String,
    callback_url: String,
    event_types_json: String,
    enabled: i64,
    created_at: i64,
}

impl From<ScimEventSubscriptionRow> for ScimEventSubscriptionRecord {
    fn from(row: ScimEventSubscriptionRow) -> Self {
        Self {
            id: row.id,
            realm_id: row.realm_id,
            callback_url: row.callback_url,
            event_types: serde_json::from_str(&row.event_types_json).unwrap_or_default(),
            enabled: row.enabled != 0,
            created_at: row.created_at as u64,
        }
    }
}

#[async_trait]
impl ScimRepository for SqlRepository {
    async fn create_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO scim_users (id, realm_id, external_id, user_name, name_json, emails_json, enterprise_json, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&user.id)
        .bind(&user.realm_id)
        .bind(&user.external_id)
        .bind(&user.user_name)
        .bind(user.name_json.to_string())
        .bind(user.emails_json.to_string())
        .bind(user.enterprise_json.to_string())
        .bind(user.active as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_scim_user(&self, id: &str) -> QidResult<Option<ScimUser>> {
        let row: Option<ScimUserRow> = sqlx::query_as("SELECT * FROM scim_users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
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
        let rows: Vec<ScimUserRow> = sqlx::query_as(
            "SELECT * FROM scim_users WHERE realm_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
        )
        .bind(realm_id.as_str())
        .bind(page_bound(limit))
        .bind(page_bound(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn count_scim_users(&self, realm_id: &RealmId) -> QidResult<usize> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scim_users WHERE realm_id = ?")
            .bind(realm_id.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(count.max(0) as usize)
    }

    async fn update_scim_user(&self, user: &ScimUser) -> QidResult<()> {
        sqlx::query("UPDATE scim_users SET external_id = ?, user_name = ?, name_json = ?, emails_json = ?, enterprise_json = ?, active = ?, updated_at = strftime('%s', 'now') WHERE id = ?")
            .bind(&user.external_id)
            .bind(&user.user_name)
            .bind(user.name_json.to_string())
            .bind(user.emails_json.to_string())
            .bind(user.enterprise_json.to_string())
            .bind(user.active as i64)
            .bind(&user.id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn delete_scim_user(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM scim_users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn create_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO scim_groups (id, realm_id, display_name, members_json) VALUES (?, ?, ?, ?)",
        )
        .bind(&group.id)
        .bind(&group.realm_id)
        .bind(&group.display_name)
        .bind(group.members_json.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
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
        let rows: Vec<ScimGroupRow> = sqlx::query_as(
            "SELECT * FROM scim_groups WHERE realm_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
        )
        .bind(realm_id.as_str())
        .bind(page_bound(limit))
        .bind(page_bound(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn count_scim_groups(&self, realm_id: &RealmId) -> QidResult<usize> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM scim_groups WHERE realm_id = ?")
                .bind(realm_id.as_str())
                .fetch_one(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(count.max(0) as usize)
    }

    async fn get_scim_group(&self, id: &str) -> QidResult<Option<ScimGroup>> {
        let row: Option<ScimGroupRow> = sqlx::query_as("SELECT * FROM scim_groups WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn update_scim_group(&self, group: &ScimGroup) -> QidResult<()> {
        sqlx::query("UPDATE scim_groups SET display_name = ?, members_json = ?, updated_at = strftime('%s', 'now') WHERE id = ?")
            .bind(&group.display_name)
            .bind(group.members_json.to_string())
            .bind(&group.id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn delete_scim_group(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM scim_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO scim_devices (id, realm_id, display_name, manufacturer, model, os, os_version, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET realm_id = excluded.realm_id, display_name = excluded.display_name, manufacturer = excluded.manufacturer, model = excluded.model, os = excluded.os, os_version = excluded.os_version, last_seen = excluded.last_seen",
        )
        .bind(&device.id)
        .bind(&device.realm_id)
        .bind(&device.display_name)
        .bind(&device.manufacturer)
        .bind(&device.model)
        .bind(&device.os)
        .bind(&device.os_version)
        .bind(device.last_seen.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_scim_device(&self, id: &str) -> QidResult<Option<ScimDeviceRecord>> {
        let row: Option<ScimDeviceRow> = sqlx::query_as("SELECT * FROM scim_devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_scim_devices(&self, realm_id: &RealmId) -> QidResult<Vec<ScimDeviceRecord>> {
        let rows: Vec<ScimDeviceRow> =
            sqlx::query_as("SELECT * FROM scim_devices WHERE realm_id = ? ORDER BY id ASC")
                .bind(realm_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_scim_device(&self, id: &str) -> QidResult<bool> {
        let result = sqlx::query("DELETE FROM scim_devices WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn upsert_scim_event_subscription(
        &self,
        subscription: &ScimEventSubscriptionRecord,
    ) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO scim_event_subscriptions (id, realm_id, callback_url, event_types_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET realm_id = excluded.realm_id, callback_url = excluded.callback_url, event_types_json = excluded.event_types_json, enabled = excluded.enabled",
        )
        .bind(&subscription.id)
        .bind(&subscription.realm_id)
        .bind(&subscription.callback_url)
        .bind(serde_json::to_string(&subscription.event_types).unwrap_or_default())
        .bind(subscription.enabled as i64)
        .bind(subscription.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_scim_event_subscription(
        &self,
        id: &str,
    ) -> QidResult<Option<ScimEventSubscriptionRecord>> {
        let row: Option<ScimEventSubscriptionRow> =
            sqlx::query_as("SELECT * FROM scim_event_subscriptions WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_scim_event_subscriptions(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<ScimEventSubscriptionRecord>> {
        let rows: Vec<ScimEventSubscriptionRow> = sqlx::query_as(
            "SELECT * FROM scim_event_subscriptions WHERE realm_id = ? ORDER BY id ASC",
        )
        .bind(realm_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_scim_event_subscription(&self, id: &str) -> QidResult<bool> {
        let result = sqlx::query("DELETE FROM scim_event_subscriptions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }
}
