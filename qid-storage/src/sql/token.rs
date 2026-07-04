use async_trait::async_trait;

use super::*;

#[async_trait]
impl TokenRepository for SqlRepository {
    async fn create_authorization_code(&self, code: &AuthorizationCode) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO authorization_codes (code_hash, client_id, user_id, realm_id, redirect_uri, state, nonce, auth_time, acr, amr, code_challenge, code_challenge_method, scopes, resource, authorization_details, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&code.code_hash)
        .bind(&code.client_id)
        .bind(&code.user_id)
        .bind(&code.realm_id)
        .bind(&code.redirect_uri)
        .bind(&code.state)
        .bind(&code.nonce)
        .bind(code.auth_time.map(|value| value as i64))
        .bind(&code.acr)
        .bind(serde_json::to_string(&code.amr).unwrap_or_default())
        .bind(&code.code_challenge)
        .bind(&code.code_challenge_method)
        .bind(serde_json::to_string(&code.scopes).unwrap_or_default())
        .bind(serde_json::to_string(&code.resource).unwrap_or_default())
        .bind(code.authorization_details.as_ref().map(|value| value.to_string()))
        .bind(code.expires_at as i64)
        .bind(code.used as i64)
        .bind(code.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_authorization_code(
        &self,
        code_hash: &str,
    ) -> QidResult<Option<AuthorizationCode>> {
        let row: Option<AuthCodeRow> =
            sqlx::query_as("SELECT * FROM authorization_codes WHERE code_hash = ?")
                .bind(code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn mark_authorization_code_used(&self, code_hash: &str) -> QidResult<()> {
        let code = self
            .get_authorization_code(code_hash)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: format!("authorization code {code_hash}"),
            })?;
        crate::domain::validate_authz_code_reuse(&code)?;
        let result =
            sqlx::query("UPDATE authorization_codes SET used = 1 WHERE code_hash = ? AND used = 0")
                .bind(code_hash)
                .execute(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "authorization code already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn create_token_family(&self, family: &TokenFamily) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO token_families (id, user_id, client_id, realm_id, current_refresh_hash, audience, resource, authorization_details, sender_constraint, issued_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&family.id)
        .bind(&family.user_id)
        .bind(&family.client_id)
        .bind(&family.realm_id)
        .bind(&family.current_refresh_hash)
        .bind(serde_json::to_string(&family.audience).unwrap_or_default())
        .bind(serde_json::to_string(&family.resource).unwrap_or_default())
        .bind(
            family
                .authorization_details
                .as_ref()
                .map(|value| value.to_string()),
        )
        .bind(family.sender_constraint.as_ref().map(|value| value.to_string()))
        .bind(family.issued_at as i64)
        .bind(family.revoked as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_token_family(&self, id: &str) -> QidResult<Option<TokenFamily>> {
        let row: Option<TokenFamilyRow> =
            sqlx::query_as("SELECT * FROM token_families WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn update_token_family_refresh_hash(
        &self,
        id: &str,
        refresh_hash: &str,
    ) -> QidResult<()> {
        let family = self
            .get_token_family(id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: format!("token family {id}"),
            })?;
        crate::domain::validate_token_family_rotation(&family, refresh_hash)?;
        sqlx::query("UPDATE token_families SET current_refresh_hash = ? WHERE id = ?")
            .bind(refresh_hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn revoke_token_family(&self, id: &str) -> QidResult<()> {
        let family = self
            .get_token_family(id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: format!("token family {id}"),
            })?;
        crate::domain::validate_token_family_revocation(&family)?;
        sqlx::query("UPDATE token_families SET revoked = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_token_families(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
        client_id: Option<&str>,
    ) -> QidResult<Vec<TokenFamily>> {
        let rows: Vec<TokenFamilyRow> = match (user_id, client_id) {
            (Some(uid), Some(cid)) => {
                sqlx::query_as(
                    "SELECT * FROM token_families WHERE realm_id = ? AND user_id = ? AND client_id = ? ORDER BY issued_at DESC",
                )
                .bind(realm_id)
                .bind(uid)
                .bind(cid)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
            (Some(uid), None) => {
                sqlx::query_as(
                    "SELECT * FROM token_families WHERE realm_id = ? AND user_id = ? ORDER BY issued_at DESC",
                )
                .bind(realm_id)
                .bind(uid)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
            (None, Some(cid)) => {
                sqlx::query_as(
                    "SELECT * FROM token_families WHERE realm_id = ? AND client_id = ? ORDER BY issued_at DESC",
                )
                .bind(realm_id)
                .bind(cid)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
            (None, None) => {
                sqlx::query_as(
                    "SELECT * FROM token_families WHERE realm_id = ? ORDER BY issued_at DESC",
                )
                .bind(realm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn create_access_token(&self, token: &AccessToken) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO access_tokens (jti, family_id, user_id, client_id, realm_id, scopes, audience, resource, authorization_details, cnf, auth_time, acr, amr, nonce, sender_constraint, token_format, expires_at, revoked, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.jti)
        .bind(&token.family_id)
        .bind(&token.user_id)
        .bind(&token.client_id)
        .bind(&token.realm_id)
        .bind(serde_json::to_string(&token.scopes).unwrap_or_default())
        .bind(serde_json::to_string(&token.audience).unwrap_or_default())
        .bind(serde_json::to_string(&token.resource).unwrap_or_default())
        .bind(token.authorization_details.as_ref().map(|value| value.to_string()))
        .bind(token.cnf.as_ref().map(|value| value.to_string()))
        .bind(token.auth_time.map(|value| value as i64))
        .bind(&token.acr)
        .bind(serde_json::to_string(&token.amr).unwrap_or_default())
        .bind(&token.nonce)
        .bind(token.sender_constraint.as_ref().map(|value| value.to_string()))
        .bind(token_format_to_str(token.token_format))
        .bind(token.expires_at as i64)
        .bind(token.revoked as i64)
        .bind(token.issued_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_access_token(&self, jti: &str) -> QidResult<Option<AccessToken>> {
        let row: Option<AccessTokenRow> =
            sqlx::query_as("SELECT * FROM access_tokens WHERE jti = ?")
                .bind(jti)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn revoke_access_token(&self, jti: &str) -> QidResult<()> {
        sqlx::query("UPDATE access_tokens SET revoked = 1 WHERE jti = ?")
            .bind(jti)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_par_request(&self, req: &ParRequest) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO par_requests (request_uri, client_id, realm_id, params_json, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&req.request_uri)
        .bind(&req.client_id)
        .bind(&req.realm_id)
        .bind(req.params_json.to_string())
        .bind(req.expires_at as i64)
        .bind(req.used as i64)
        .bind(req.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_par_request(&self, request_uri: &str) -> QidResult<Option<ParRequest>> {
        let row: Option<ParRequestRow> =
            sqlx::query_as("SELECT * FROM par_requests WHERE request_uri = ?")
                .bind(request_uri)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn mark_par_request_used(&self, request_uri: &str) -> QidResult<()> {
        let result =
            sqlx::query("UPDATE par_requests SET used = 1 WHERE request_uri = ? AND used = 0")
                .bind(request_uri)
                .execute(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "PAR request already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn store_device_authorization_grant(
        &self,
        grant: &DeviceAuthorizationGrant,
    ) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO device_authorization_grants (device_code_hash, user_code, client_id, realm_id, scopes, user_id, expires_at, approved_at, consumed, last_poll_at, poll_interval_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&grant.device_code_hash)
        .bind(&grant.user_code)
        .bind(&grant.client_id)
        .bind(&grant.realm_id)
        .bind(serde_json::to_string(&grant.scopes).unwrap_or_default())
        .bind(&grant.user_id)
        .bind(grant.expires_at as i64)
        .bind(grant.approved_at.map(|approved_at| approved_at as i64))
        .bind(grant.consumed as i64)
        .bind(grant.last_poll_at.map(|polled_at| polled_at as i64))
        .bind(grant.poll_interval_seconds as i64)
        .bind(grant.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_device_authorization_grant(
        &self,
        device_code_hash: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>> {
        let row: Option<DeviceAuthorizationGrantRow> =
            sqlx::query_as("SELECT * FROM device_authorization_grants WHERE device_code_hash = ?")
                .bind(device_code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_device_authorization_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> QidResult<Option<DeviceAuthorizationGrant>> {
        let row: Option<DeviceAuthorizationGrantRow> =
            sqlx::query_as("SELECT * FROM device_authorization_grants WHERE user_code = ?")
                .bind(user_code)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn approve_device_authorization_grant(
        &self,
        user_code: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE device_authorization_grants SET user_id = ?, approved_at = ? WHERE user_code = ?",
        )
        .bind(user_id)
        .bind(approved_at as i64)
        .bind(user_code)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: "device authorization grant".to_string(),
            });
        }
        Ok(())
    }

    async fn record_device_authorization_poll(
        &self,
        device_code_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()> {
        sqlx::query(
            "UPDATE device_authorization_grants SET last_poll_at = ?, poll_interval_seconds = ? WHERE device_code_hash = ?",
        )
        .bind(polled_at as i64)
        .bind(poll_interval_seconds as i64)
        .bind(device_code_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn consume_device_authorization_grant(&self, device_code_hash: &str) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE device_authorization_grants SET consumed = 1 WHERE device_code_hash = ? AND consumed = 0",
        )
        .bind(device_code_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "device authorization grant already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn store_backchannel_authentication_grant(
        &self,
        grant: &BackchannelAuthenticationGrant,
    ) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO backchannel_authentication_grants (auth_req_id_hash, client_id, realm_id, login_hint, binding_message, scopes, user_id, expires_at, approved_at, consumed, last_poll_at, poll_interval_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&grant.auth_req_id_hash)
        .bind(&grant.client_id)
        .bind(&grant.realm_id)
        .bind(&grant.login_hint)
        .bind(&grant.binding_message)
        .bind(serde_json::to_string(&grant.scopes).unwrap_or_default())
        .bind(&grant.user_id)
        .bind(grant.expires_at as i64)
        .bind(grant.approved_at.map(|approved_at| approved_at as i64))
        .bind(grant.consumed as i64)
        .bind(grant.last_poll_at.map(|polled_at| polled_at as i64))
        .bind(grant.poll_interval_seconds as i64)
        .bind(grant.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<Option<BackchannelAuthenticationGrant>> {
        let row: Option<BackchannelAuthenticationGrantRow> = sqlx::query_as(
            "SELECT * FROM backchannel_authentication_grants WHERE auth_req_id_hash = ?",
        )
        .bind(auth_req_id_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn approve_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
        user_id: &str,
        approved_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE backchannel_authentication_grants SET user_id = ?, approved_at = ? WHERE auth_req_id_hash = ?",
        )
        .bind(user_id)
        .bind(approved_at as i64)
        .bind(auth_req_id_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: "backchannel authentication grant".to_string(),
            });
        }
        Ok(())
    }

    async fn record_backchannel_authentication_poll(
        &self,
        auth_req_id_hash: &str,
        polled_at: u64,
        poll_interval_seconds: u64,
    ) -> QidResult<()> {
        sqlx::query(
            "UPDATE backchannel_authentication_grants SET last_poll_at = ?, poll_interval_seconds = ? WHERE auth_req_id_hash = ?",
        )
        .bind(polled_at as i64)
        .bind(poll_interval_seconds as i64)
        .bind(auth_req_id_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn consume_backchannel_authentication_grant(
        &self,
        auth_req_id_hash: &str,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE backchannel_authentication_grants SET consumed = 1 WHERE auth_req_id_hash = ? AND consumed = 0",
        )
        .bind(auth_req_id_hash)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "backchannel authentication grant already consumed".to_string(),
            });
        }
        Ok(())
    }
}
