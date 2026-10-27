use async_trait::async_trait;

use super::*;

#[async_trait]
impl ClientRepository for SqlRepository {
    async fn create_client(&self, client: &Client) -> QidResult<()> {
        // The unique constraints of the table hold the invariant, so the
        // insert refuses a client whose record ID or whose client id in the
        // realm is taken. The read names the reason of the refusal.
        let result = sqlx::query(
            "INSERT INTO clients (id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint, require_pushed_authorization_requests) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) ON CONFLICT DO NOTHING",
        )
        .bind(&client.id)
        .bind(&client.realm_id)
        .bind(&client.client_id)
        .bind(match client.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        })
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.client_secret_hash)
        .bind(serde_json::to_string(&client.mtls_certificate_thumbprints).unwrap_or_default())
        .bind(client.jwks.to_string())
        .bind(serde_json::to_string(&client.redirect_uris).unwrap_or_default())
        .bind(serde_json::to_string(&client.grant_types).unwrap_or_default())
        .bind(&client.client_name)
        .bind(&client.client_uri)
        .bind(&client.logo_uri)
        .bind(serde_json::to_string(&client.contacts).unwrap_or_default())
        .bind(serde_json::to_string(&client.post_logout_redirect_uris).unwrap_or_default())
        .bind(client.default_max_age.map(|v| v as i64))
        .bind(client.require_auth_time as i64)
        .bind(&client.sector_identifier_uri)
        .bind(&client.subject_type)
        .bind(&client.backchannel_logout_uri)
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_client_notification_endpoint)
        .bind(client.require_pushed_authorization_requests as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            let incumbent = self
                .find_clients_by_client_id(
                    &[RealmId::from(client.realm_id.clone())],
                    &client.client_id,
                )
                .await?;
            let message = if incumbent.is_empty() {
                format!("client record ID {} already exists", client.id)
            } else {
                format!(
                    "client id {} already exists in realm {}",
                    client.client_id, client.realm_id
                )
            };
            return Err(QidError::Conflict { message });
        }
        Ok(())
    }

    async fn update_client(&self, client: &Client) -> QidResult<()> {
        // The owner/identity predicate holds the invariant atomically: only a
        // row with the same record ID and the same (realm_id, client_id)
        // binding is updated, so a caller cannot move a client to another
        // realm or rename its client ID. No pre-read precedes the write.
        let result = sqlx::query(
            "UPDATE clients SET client_type = $1, token_endpoint_auth_method = $2, client_secret_hash = $3, mtls_certificate_thumbprints = $4, jwks = $5, redirect_uris = $6, grant_types = $7, client_name = $8, client_uri = $9, logo_uri = $10, contacts = $11, post_logout_redirect_uris = $12, default_max_age = $13, require_auth_time = $14, sector_identifier_uri = $15, subject_type = $16, backchannel_logout_uri = $17, frontchannel_logout_uri = $18, backchannel_client_notification_endpoint = $19, require_pushed_authorization_requests = $20 WHERE id = $21 AND realm_id = $22 AND client_id = $23",
        )
        .bind(match client.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        })
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.client_secret_hash)
        .bind(serde_json::to_string(&client.mtls_certificate_thumbprints).unwrap_or_default())
        .bind(client.jwks.to_string())
        .bind(serde_json::to_string(&client.redirect_uris).unwrap_or_default())
        .bind(serde_json::to_string(&client.grant_types).unwrap_or_default())
        .bind(&client.client_name)
        .bind(&client.client_uri)
        .bind(&client.logo_uri)
        .bind(serde_json::to_string(&client.contacts).unwrap_or_default())
        .bind(serde_json::to_string(&client.post_logout_redirect_uris).unwrap_or_default())
        .bind(client.default_max_age.map(|v| v as i64))
        .bind(client.require_auth_time as i64)
        .bind(&client.sector_identifier_uri)
        .bind(&client.subject_type)
        .bind(&client.backchannel_logout_uri)
        .bind(&client.frontchannel_logout_uri)
        .bind(&client.backchannel_client_notification_endpoint)
        .bind(client.require_pushed_authorization_requests as i64)
        .bind(&client.id)
        .bind(&client.realm_id)
        .bind(&client.client_id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            // Classify only after the guarded write failed, never to decide it:
            // a missing ID stays a silent no-op, a present mismatched binding
            // is a conflict, and a present matching binding is the identical
            // update SQLite reports as zero changed rows.
            let incumbent: Option<(String, String)> =
                sqlx::query_as("SELECT realm_id, client_id FROM clients WHERE id = $1")
                    .bind(&client.id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage_to_qid_error)?;
            crate::ownership::ensure_same_binding(
                incumbent,
                (client.realm_id.clone(), client.client_id.clone()),
                || "client ID belongs to another identity".to_string(),
            )?;
        }
        Ok(())
    }

    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>> {
        let row: Option<ClientRow> =
            sqlx::query_as("SELECT id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint, require_pushed_authorization_requests FROM clients WHERE realm_id = $1 AND client_id = $2")
                .bind(realm_id.as_str())
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn find_clients_by_client_id(
        &self,
        realm_ids: &[RealmId],
        client_id: &str,
    ) -> QidResult<Vec<Client>> {
        if realm_ids.is_empty() {
            return Ok(Vec::new());
        }
        // One read answers the client id in every named realm. The index on
        // (client_id, realm_id) keeps it cheap, and the realms outside the
        // list are never read.
        let slots = (2..realm_ids.len() + 2).map(|n| format!("${n}"));
        let placeholders = slots.collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint, require_pushed_authorization_requests FROM clients WHERE client_id = $1 AND realm_id IN ({placeholders})"
        );
        let mut query = sqlx::query_as::<_, ClientRow>(&sql).bind(client_id);
        for realm_id in realm_ids {
            query = query.bind(realm_id.as_str());
        }
        let rows: Vec<ClientRow> = query
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_clients_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<Client>> {
        let rows: Vec<ClientRow> = sqlx::query_as(
            "SELECT id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint, require_pushed_authorization_requests FROM clients WHERE realm_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
        )
            .bind(realm_id.as_str())
            .bind(page_bound(limit))
            .bind(page_bound(offset))
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_client(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM clients WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
