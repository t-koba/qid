use async_trait::async_trait;

use super::*;

#[async_trait]
impl SiemDeliveryRepository for SqlRepository {
    async fn upsert_siem_delivery(&self, delivery: &SiemDeliveryRecord) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO siem_delivery_queue (id, realm_id, endpoint_url, payload_json, attempts, next_retry_at, status, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET realm_id = excluded.realm_id, endpoint_url = excluded.endpoint_url, payload_json = excluded.payload_json, attempts = excluded.attempts, next_retry_at = excluded.next_retry_at, status = excluded.status, last_error = excluded.last_error, updated_at = excluded.updated_at",
        )
        .bind(&delivery.id)
        .bind(&delivery.realm_id)
        .bind(&delivery.endpoint_url)
        .bind(delivery.payload_json.to_string())
        .bind(delivery.attempts as i64)
        .bind(delivery.next_retry_at.map(|value| value as i64))
        .bind(siem_delivery_status_to_str(&delivery.status))
        .bind(&delivery.last_error)
        .bind(delivery.created_at as i64)
        .bind(delivery.updated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_siem_delivery(&self, id: &str) -> QidResult<Option<SiemDeliveryRecord>> {
        let row: Option<SiemDeliveryRow> =
            sqlx::query_as("SELECT * FROM siem_delivery_queue WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_siem_deliveries(
        &self,
        realm_id: Option<&str>,
        status: Option<SiemDeliveryStatus>,
        limit: usize,
    ) -> QidResult<Vec<SiemDeliveryRecord>> {
        let limit = limit.min(1_000) as i64;
        let rows: Vec<SiemDeliveryRow> = match (realm_id, status.as_ref()) {
            (Some(realm_id), Some(status)) => sqlx::query_as(
                "SELECT * FROM siem_delivery_queue WHERE realm_id = ? AND status = ? ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, id ASC LIMIT ?",
            )
            .bind(realm_id)
            .bind(siem_delivery_status_to_str(status))
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?,
            (Some(realm_id), None) => sqlx::query_as(
                "SELECT * FROM siem_delivery_queue WHERE realm_id = ? ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, id ASC LIMIT ?",
            )
            .bind(realm_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?,
            (None, Some(status)) => sqlx::query_as(
                "SELECT * FROM siem_delivery_queue WHERE status = ? ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, id ASC LIMIT ?",
            )
            .bind(siem_delivery_status_to_str(status))
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?,
            (None, None) => sqlx::query_as(
                "SELECT * FROM siem_delivery_queue ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, id ASC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?,
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn mark_siem_delivery_status(
        &self,
        id: &str,
        status: SiemDeliveryStatus,
        attempts: u32,
        next_retry_at: Option<u64>,
        last_error: Option<&str>,
        updated_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE siem_delivery_queue SET status = ?, attempts = ?, next_retry_at = ?, last_error = ?, updated_at = ? WHERE id = ?",
        )
        .bind(siem_delivery_status_to_str(&status))
        .bind(attempts as i64)
        .bind(next_retry_at.map(|value| value as i64))
        .bind(last_error)
        .bind(updated_at as i64)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: format!("siem delivery {id}"),
            });
        }
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SiemDeliveryRow {
    id: String,
    realm_id: Option<String>,
    endpoint_url: String,
    payload_json: String,
    attempts: i64,
    next_retry_at: Option<i64>,
    status: String,
    last_error: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<SiemDeliveryRow> for SiemDeliveryRecord {
    type Error = QidError;

    fn try_from(row: SiemDeliveryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            realm_id: row.realm_id,
            endpoint_url: row.endpoint_url,
            payload_json: serde_json::from_str(&row.payload_json).map_err(|e| {
                QidError::Storage {
                    message: format!("failed to parse SIEM delivery payload: {e}"),
                }
            })?,
            attempts: row.attempts.max(0) as u32,
            next_retry_at: row.next_retry_at.map(|value| value.max(0) as u64),
            status: siem_delivery_status_from_str(&row.status)?,
            last_error: row.last_error,
            created_at: row.created_at.max(0) as u64,
            updated_at: row.updated_at.max(0) as u64,
        })
    }
}

fn siem_delivery_status_to_str(status: &SiemDeliveryStatus) -> &'static str {
    match status {
        SiemDeliveryStatus::Pending => "pending",
        SiemDeliveryStatus::Delivered => "delivered",
        SiemDeliveryStatus::Dead => "dead",
    }
}

fn siem_delivery_status_from_str(value: &str) -> QidResult<SiemDeliveryStatus> {
    match value {
        "pending" => Ok(SiemDeliveryStatus::Pending),
        "delivered" => Ok(SiemDeliveryStatus::Delivered),
        "dead" => Ok(SiemDeliveryStatus::Dead),
        other => Err(QidError::Storage {
            message: format!("unknown SIEM delivery status: {other}"),
        }),
    }
}
