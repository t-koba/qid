use async_trait::async_trait;

use super::*;

#[derive(sqlx::FromRow)]
struct SsfStreamRow {
    realm_id: String,
    stream_id: String,
    delivery_json: String,
    events_requested_json: String,
    transmitter_issuer: String,
    transmitter_jwks_json: String,
    transmitter_alg: String,
    audience: String,
    status: String,
    created_at: i64,
    updated_at: i64,
}

impl SsfStreamRow {
    fn into_record(self) -> SsfStreamRecord {
        SsfStreamRecord {
            realm_id: self.realm_id,
            stream_id: self.stream_id,
            delivery_json: serde_json::from_str(&self.delivery_json)
                .unwrap_or(serde_json::Value::Null),
            events_requested: serde_json::from_str(&self.events_requested_json).unwrap_or_default(),
            transmitter_issuer: self.transmitter_issuer,
            transmitter_jwks_json: serde_json::from_str(&self.transmitter_jwks_json)
                .unwrap_or(serde_json::Value::Null),
            transmitter_alg: self.transmitter_alg,
            audience: self.audience,
            status: self.status,
            created_at: self.created_at as u64,
            updated_at: self.updated_at as u64,
        }
    }
}

#[async_trait]
impl SsfRepository for SqlRepository {
    async fn upsert_ssf_stream(&self, stream: &SsfStreamRecord) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO ssf_streams \
             (realm_id, stream_id, delivery_json, events_requested_json, transmitter_issuer, transmitter_jwks_json, transmitter_alg, audience, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(realm_id, stream_id) DO UPDATE SET \
             delivery_json = excluded.delivery_json, \
             events_requested_json = excluded.events_requested_json, \
             transmitter_issuer = excluded.transmitter_issuer, \
             transmitter_jwks_json = excluded.transmitter_jwks_json, \
             transmitter_alg = excluded.transmitter_alg, \
             audience = excluded.audience, \
             status = excluded.status, \
             updated_at = excluded.updated_at",
        )
        .bind(&stream.realm_id)
        .bind(&stream.stream_id)
        .bind(stream.delivery_json.to_string())
        .bind(serde_json::to_string(&stream.events_requested).unwrap_or_default())
        .bind(&stream.transmitter_issuer)
        .bind(stream.transmitter_jwks_json.to_string())
        .bind(&stream.transmitter_alg)
        .bind(&stream.audience)
        .bind(&stream.status)
        .bind(stream.created_at as i64)
        .bind(stream.updated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_ssf_streams(&self, realm_id: &str) -> QidResult<Vec<SsfStreamRecord>> {
        let rows: Vec<SsfStreamRow> =
            sqlx::query_as("SELECT * FROM ssf_streams WHERE realm_id = ? ORDER BY stream_id ASC")
                .bind(realm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(SsfStreamRow::into_record).collect())
    }

    async fn get_ssf_stream(
        &self,
        realm_id: &str,
        stream_id: &str,
    ) -> QidResult<Option<SsfStreamRecord>> {
        let row: Option<SsfStreamRow> =
            sqlx::query_as("SELECT * FROM ssf_streams WHERE realm_id = ? AND stream_id = ?")
                .bind(realm_id)
                .bind(stream_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(SsfStreamRow::into_record))
    }

    async fn delete_ssf_stream(&self, realm_id: &str, stream_id: &str) -> QidResult<bool> {
        let result = sqlx::query("DELETE FROM ssf_streams WHERE realm_id = ? AND stream_id = ?")
            .bind(realm_id)
            .bind(stream_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn record_ssf_set_jti(
        &self,
        realm_id: &str,
        issuer: &str,
        stream_id: &str,
        jti: &str,
        expires_at: u64,
        now: u64,
    ) -> QidResult<bool> {
        sqlx::query("DELETE FROM ssf_set_replay WHERE expires_at <= ?")
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        let result = sqlx::query(
            "INSERT INTO ssf_set_replay (realm_id, issuer, stream_id, jti, expires_at) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(realm_id, issuer, stream_id, jti) DO NOTHING",
        )
        .bind(realm_id)
        .bind(issuer)
        .bind(stream_id)
        .bind(jti)
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }
}
