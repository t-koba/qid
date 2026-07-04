use async_trait::async_trait;

use super::*;

#[async_trait]
impl AuditRepository for SqlRepository {
    async fn append_audit_event(&self, event: &AuditEvent) -> QidResult<()> {
        let previous_hash: Option<String> = if let Some(realm_id) = &event.realm_id {
            sqlx::query_scalar(
                "SELECT e.event_hash FROM audit_events e WHERE e.realm_id = ? AND e.event_hash IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_events n WHERE n.realm_id = ? AND n.previous_hash = e.event_hash) ORDER BY e.created_at DESC, e.id DESC LIMIT 1",
            )
            .bind(realm_id)
            .bind(realm_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_scalar(
                "SELECT e.event_hash FROM audit_events e WHERE e.realm_id IS NULL AND e.event_hash IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_events n WHERE n.realm_id IS NULL AND n.previous_hash = e.event_hash) ORDER BY e.created_at DESC, e.id DESC LIMIT 1",
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        let event = event.clone().with_chain_hashes(previous_hash);
        sqlx::query(
            "INSERT INTO audit_events (id, realm_id, actor, action, target_type, target_id, reason, metadata_json, created_at, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&event.id)
        .bind(&event.realm_id)
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.target_type)
        .bind(&event.target_id)
        .bind(&event.reason)
        .bind(event.metadata_json.to_string())
        .bind(event.created_at as i64)
        .bind(&event.previous_hash)
        .bind(&event.event_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        realm_id: Option<&RealmId>,
        limit: usize,
    ) -> QidResult<Vec<AuditEvent>> {
        let limit = limit.min(1_000) as i64;
        let rows: Vec<AuditEventRow> = if let Some(realm_id) = realm_id {
            sqlx::query_as(
                "SELECT * FROM audit_events WHERE realm_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
            )
            .bind(realm_id.as_str())
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as("SELECT * FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn verify_audit_chain(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<AuditChainVerification> {
        let rows: Vec<AuditEventRow> = if let Some(realm_id) = realm_id {
            sqlx::query_as(
                "SELECT * FROM audit_events WHERE realm_id = ? ORDER BY created_at ASC, id ASC",
            )
            .bind(realm_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM audit_events ORDER BY realm_id ASC, created_at ASC, id ASC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        let events: Vec<AuditEvent> = rows.into_iter().map(Into::into).collect();
        if realm_id.is_some() {
            Ok(verify_audit_chain_linked(&events))
        } else {
            Ok(verify_audit_chains_by_realm(&events))
        }
    }

    async fn set_audit_retention_config(&self, config: &AuditRetentionConfig) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO audit_retention_configs (stream_id, realm_id, retention_days, legal_hold, updated_by, reason, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(stream_id) DO UPDATE SET realm_id = excluded.realm_id, retention_days = excluded.retention_days, legal_hold = excluded.legal_hold, updated_by = excluded.updated_by, reason = excluded.reason, updated_at = excluded.updated_at",
        )
        .bind(audit_retention_stream_id(config.realm_id.as_deref()))
        .bind(&config.realm_id)
        .bind(config.retention_days as i64)
        .bind(if config.legal_hold { 1_i64 } else { 0_i64 })
        .bind(&config.updated_by)
        .bind(&config.reason)
        .bind(config.updated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_audit_retention_config(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<Option<AuditRetentionConfig>> {
        let row: Option<AuditRetentionConfigRow> =
            sqlx::query_as("SELECT * FROM audit_retention_configs WHERE stream_id = ?")
                .bind(audit_retention_stream_id(realm_id.map(RealmId::as_str)))
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn plan_audit_retention(
        &self,
        realm_id: Option<&RealmId>,
        now_epoch: u64,
    ) -> QidResult<Option<AuditRetentionEnforcementPlan>> {
        let Some(config) = self.get_audit_retention_config(realm_id).await? else {
            return Ok(None);
        };
        let rows: Vec<AuditEventRow> = if let Some(realm_id) = realm_id {
            sqlx::query_as(
                "SELECT * FROM audit_events WHERE realm_id = ? ORDER BY created_at ASC, id ASC",
            )
            .bind(realm_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as("SELECT * FROM audit_events ORDER BY created_at ASC, id ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
        };
        let events: Vec<AuditEvent> = rows.into_iter().map(Into::into).collect();
        Ok(Some(plan_audit_retention_enforcement(
            &config, now_epoch, &events,
        )))
    }
}
