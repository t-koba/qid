use async_trait::async_trait;

use super::*;

#[async_trait]
impl ClientRepository for SqlRepository {
    async fn create_client(&self, client: &Client) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO clients (id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn update_client(&self, client: &Client) -> QidResult<()> {
        sqlx::query(
            "UPDATE clients SET client_type = ?, token_endpoint_auth_method = ?, client_secret_hash = ?, mtls_certificate_thumbprints = ?, jwks = ?, redirect_uris = ?, grant_types = ?, client_name = ?, client_uri = ?, logo_uri = ?, contacts = ?, post_logout_redirect_uris = ?, default_max_age = ?, require_auth_time = ?, sector_identifier_uri = ?, subject_type = ?, backchannel_logout_uri = ?, frontchannel_logout_uri = ?, backchannel_client_notification_endpoint = ? WHERE id = ?",
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
        .bind(&client.id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_client_by_client_id(
        &self,
        realm_id: &RealmId,
        client_id: &str,
    ) -> QidResult<Option<Client>> {
        let row: Option<ClientRow> =
            sqlx::query_as("SELECT id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint FROM clients WHERE realm_id = ? AND client_id = ?")
                .bind(realm_id.as_str())
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_clients(&self, realm_id: &RealmId) -> QidResult<Vec<Client>> {
        let rows: Vec<ClientRow> = sqlx::query_as(
            "SELECT id, realm_id, client_id, client_type, token_endpoint_auth_method, client_secret_hash, mtls_certificate_thumbprints, jwks, redirect_uris, grant_types, client_name, client_uri, logo_uri, contacts, post_logout_redirect_uris, default_max_age, require_auth_time, sector_identifier_uri, subject_type, backchannel_logout_uri, frontchannel_logout_uri, backchannel_client_notification_endpoint FROM clients WHERE realm_id = ?",
        )
            .bind(realm_id.as_str())
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
