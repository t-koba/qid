use async_trait::async_trait;

use super::*;
use crate::{ScimMutation, ScimMutator};

fn sqlite_deprovisioned_at(value: Option<u64>) -> QidResult<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| QidError::BadRequest {
                message: "deprovisioned_at exceeds the supported SQL timestamp range".to_string(),
            })
        })
        .transpose()
}

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
        let deprovisioned_at = sqlite_deprovisioned_at(user.deprovisioned_at)?;
        sqlx::query(
            "INSERT INTO scim_users (id, realm_id, external_id, user_name, name_json, emails_json, enterprise_json, directory_provider_id, deprovisioned_at, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&user.id)
        .bind(&user.realm_id)
        .bind(&user.external_id)
        .bind(&user.user_name)
        .bind(user.name_json.to_string())
        .bind(user.emails_json.to_string())
        .bind(user.enterprise_json.to_string())
        .bind(&user.directory_provider_id)
        .bind(deprovisioned_at)
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
        let deprovisioned_at = sqlite_deprovisioned_at(user.deprovisioned_at)?;
        sqlx::query("UPDATE scim_users SET external_id = ?, user_name = ?, name_json = ?, emails_json = ?, enterprise_json = ?, directory_provider_id = ?, deprovisioned_at = ?, active = ?, updated_at = strftime('%s', 'now') WHERE id = ?")
            .bind(&user.external_id)
            .bind(&user.user_name)
            .bind(user.name_json.to_string())
            .bind(user.emails_json.to_string())
            .bind(user.enterprise_json.to_string())
            .bind(&user.directory_provider_id)
            .bind(deprovisioned_at)
            .bind(user.active as i64)
            .bind(&user.id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn mutate_scim_user(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimUser>,
    ) -> QidResult<Option<ScimUser>> {
        let (mut tx, current) = self.lock_scim_row::<ScimUserRow>("scim_users", id).await?;
        let Some(current) = current else {
            return Ok(None);
        };
        let current: ScimUser = current.into();
        let result = match mutation(&current)? {
            ScimMutation::Reject => return Ok(None),
            ScimMutation::Replace(replacement) => {
                if replacement.id != current.id || replacement.realm_id != current.realm_id {
                    return Err(QidError::BadRequest {
                        message: "serialized mutation cannot change resource identity".into(),
                    });
                }
                sqlx::query("UPDATE scim_users SET external_id = $1, user_name = $2, name_json = $3, emails_json = $4, enterprise_json = $5, directory_provider_id = $6, deprovisioned_at = $7, active = $8, updated_at = $9 WHERE id = $10")
                    .bind(&replacement.external_id)
                    .bind(&replacement.user_name)
                    .bind(replacement.name_json.to_string())
                    .bind(replacement.emails_json.to_string())
                    .bind(replacement.enterprise_json.to_string())
                    .bind(&replacement.directory_provider_id)
                    .bind(sqlite_deprovisioned_at(replacement.deprovisioned_at)?)
                    .bind(replacement.active as i64)
                    .bind(qid_core::util::now_seconds() as i64)
                    .bind(id)
                    .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
                replacement
            }
            ScimMutation::Delete => {
                delete_scim_row(&mut *tx, "scim_users", id).await?;
                current
            }
        };
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(Some(result))
    }

    async fn delete_scim_user(&self, id: &str) -> QidResult<()> {
        delete_scim_row(&self.pool, "scim_users", id).await
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

    async fn mutate_scim_group(
        &self,
        id: &str,
        mutation: ScimMutator<'_, ScimGroup>,
    ) -> QidResult<Option<ScimGroup>> {
        let (mut tx, current) = self
            .lock_scim_row::<ScimGroupRow>("scim_groups", id)
            .await?;
        let Some(current) = current else {
            return Ok(None);
        };
        let current: ScimGroup = current.into();
        let result = match mutation(&current)? {
            ScimMutation::Reject => return Ok(None),
            ScimMutation::Replace(replacement) => {
                if replacement.id != current.id || replacement.realm_id != current.realm_id {
                    return Err(QidError::BadRequest {
                        message: "serialized mutation cannot change resource identity".into(),
                    });
                }
                sqlx::query("UPDATE scim_groups SET display_name = $1, members_json = $2, updated_at = $3 WHERE id = $4")
                    .bind(&replacement.display_name)
                    .bind(replacement.members_json.to_string())
                    .bind(qid_core::util::now_seconds() as i64)
                    .bind(id)
                    .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
                replacement
            }
            ScimMutation::Delete => {
                delete_scim_row(&mut *tx, "scim_groups", id).await?;
                current
            }
        };
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(Some(result))
    }

    async fn delete_scim_group(&self, id: &str) -> QidResult<()> {
        delete_scim_row(&self.pool, "scim_groups", id).await
    }

    async fn upsert_scim_device(&self, device: &ScimDeviceRecord) -> QidResult<()> {
        let result = sqlx::query(
            "INSERT INTO scim_devices (id, realm_id, display_name, manufacturer, model, os, os_version, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, manufacturer = excluded.manufacturer, model = excluded.model, os = excluded.os, os_version = excluded.os_version, last_seen = excluded.last_seen WHERE scim_devices.realm_id = excluded.realm_id",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            "SCIM device ID belongs to another realm".to_string()
        })
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
        let result = sqlx::query(
            "INSERT INTO scim_event_subscriptions (id, realm_id, callback_url, event_types_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET callback_url = excluded.callback_url, event_types_json = excluded.event_types_json, enabled = excluded.enabled WHERE scim_event_subscriptions.realm_id = excluded.realm_id",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            "SCIM event subscription ID belongs to another realm".to_string()
        })
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

impl SqlRepository {
    /// Lock before reading; Transaction's Drop rolls back early returns,
    /// callback/conversion/query errors, panics and cancellation.
    async fn lock_scim_row<T>(
        &self,
        table: &str,
        id: &str,
    ) -> QidResult<(sqlx::Transaction<'_, sqlx::Any>, Option<T>)>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::any::AnyRow> + Send + Unpin,
    {
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN",
            })
            .await
            .map_err(storage_to_qid_error)?;
        // Table names are internal constants, never request data.
        let lock = match self.database_kind {
            SqlDatabaseKind::Sqlite => "",
            SqlDatabaseKind::Postgres => " FOR UPDATE",
        };
        let current = sqlx::query_as(&format!("SELECT * FROM {table} WHERE id = $1{lock}"))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        Ok((tx, current))
    }
}

async fn delete_scim_row<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    table: &str,
    id: &str,
) -> QidResult<()> {
    sqlx::query(&format!("DELETE FROM {table} WHERE id = $1"))
        .bind(id)
        .execute(executor)
        .await
        .map_err(storage_to_qid_error)?;
    Ok(())
}

#[cfg(test)]
mod deprovisioned_timestamp_tests {
    use super::sqlite_deprovisioned_at;

    #[test]
    fn sqlite_deprovisioned_timestamp_rejects_overflow_without_wrapping() {
        assert_eq!(sqlite_deprovisioned_at(None).unwrap(), None);
        assert_eq!(sqlite_deprovisioned_at(Some(1_050)).unwrap(), Some(1_050));
        assert!(sqlite_deprovisioned_at(Some(u64::MAX)).is_err());
    }
}
