use async_trait::async_trait;

use super::*;

#[async_trait]
impl WorkloadRepository for SqlRepository {
    async fn create_workload_identity(&self, wi: &WorkloadIdentity) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO workload_identities (id, realm_id, spiffe_id, description, trust_domain, authorities_json) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&wi.id)
        .bind(&wi.realm_id)
        .bind(&wi.spiffe_id)
        .bind(&wi.description)
        .bind(&wi.trust_domain)
        .bind(wi.authorities_json.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_workload_identity_by_spiffe(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> QidResult<Option<WorkloadIdentity>> {
        let row: Option<WorkloadIdentityRow> = sqlx::query_as(
            "SELECT * FROM workload_identities WHERE realm_id = ? AND spiffe_id = ?",
        )
        .bind(realm_id.as_str())
        .bind(spiffe_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_workload_identities(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<WorkloadIdentity>> {
        let rows: Vec<WorkloadIdentityRow> =
            sqlx::query_as("SELECT * FROM workload_identities WHERE realm_id = ?")
                .bind(realm_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_workload_identity(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM workload_identities WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_workload_certificate(&self, certificate: &WorkloadCertificate) -> QidResult<()> {
        certificate.validate()?;
        let workload: Option<(String, String)> =
            sqlx::query_as("SELECT realm_id, spiffe_id FROM workload_identities WHERE id = ?")
                .bind(&certificate.workload_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let Some((workload_realm, workload_spiffe)) = workload else {
            return Err(QidError::BadRequest {
                message: "workload certificate workload does not exist".to_string(),
            });
        };
        if workload_realm != certificate.realm_id || workload_spiffe != certificate.spiffe_id {
            return Err(QidError::BadRequest {
                message: "workload certificate identity does not match workload".to_string(),
            });
        }
        let duplicate_thumbprint: Option<String> = sqlx::query_scalar(
            "SELECT id FROM workload_certificates WHERE realm_id = ? AND x5t_s256 = ? AND id <> ?",
        )
        .bind(&certificate.realm_id)
        .bind(&certificate.x5t_s256)
        .bind(&certificate.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if duplicate_thumbprint.is_some() {
            return Err(QidError::BadRequest {
                message: "workload certificate thumbprint already exists".to_string(),
            });
        }
        sqlx::query(
            "INSERT INTO workload_certificates (id, realm_id, workload_id, spiffe_id, serial_number, x5t_s256, csr_sha256, certificate_pem, issuer_key_ref, issued_at, not_before, not_after, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET serial_number = excluded.serial_number, x5t_s256 = excluded.x5t_s256, csr_sha256 = excluded.csr_sha256, certificate_pem = excluded.certificate_pem, issuer_key_ref = excluded.issuer_key_ref, issued_at = excluded.issued_at, not_before = excluded.not_before, not_after = excluded.not_after, revoked_at = excluded.revoked_at",
        )
        .bind(&certificate.id)
        .bind(&certificate.realm_id)
        .bind(&certificate.workload_id)
        .bind(&certificate.spiffe_id)
        .bind(&certificate.serial_number)
        .bind(&certificate.x5t_s256)
        .bind(&certificate.csr_sha256)
        .bind(&certificate.certificate_pem)
        .bind(&certificate.issuer_key_ref)
        .bind(certificate.issued_at as i64)
        .bind(certificate.not_before as i64)
        .bind(certificate.not_after as i64)
        .bind(certificate.revoked_at.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_workload_certificates(
        &self,
        realm_id: &RealmId,
        workload_id: Option<&str>,
    ) -> QidResult<Vec<WorkloadCertificate>> {
        let rows: Vec<WorkloadCertificateRow> = if let Some(workload_id) = workload_id {
            sqlx::query_as(
                "SELECT * FROM workload_certificates WHERE realm_id = ? AND workload_id = ? ORDER BY not_after DESC, id ASC",
            )
            .bind(realm_id.as_str())
            .bind(workload_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM workload_certificates WHERE realm_id = ? ORDER BY not_after DESC, id ASC",
            )
            .bind(realm_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_workload_certificate(
        &self,
        realm_id: &RealmId,
        id: &str,
        revoked_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE workload_certificates SET revoked_at = ? WHERE realm_id = ? AND id = ?",
        )
        .bind(revoked_at as i64)
        .bind(realm_id.as_str())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: format!("workload certificate {id}"),
            });
        }
        Ok(())
    }
}
