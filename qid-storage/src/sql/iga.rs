use async_trait::async_trait;

use super::*;

#[async_trait]
impl IgaRepository for SqlRepository {
    async fn store_iga_entitlement(&self, entitlement: &IgaEntitlementRecord) -> QidResult<()> {
        entitlement.validate()?;
        sqlx::query(
            "INSERT INTO iga_entitlements (tenant_id, id, display_name, owner, risk_level, conflicting_entitlements_json, max_duration_seconds, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entitlement.tenant_id)
        .bind(&entitlement.id)
        .bind(&entitlement.display_name)
        .bind(&entitlement.owner)
        .bind(&entitlement.risk_level)
        .bind(serde_json::to_string(&entitlement.conflicting_entitlements).unwrap_or_default())
        .bind(entitlement.max_duration_seconds.map(|value| value as i64))
        .bind(entitlement.active as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_entitlements(&self, tenant_id: &str) -> QidResult<Vec<IgaEntitlementRecord>> {
        let rows: Vec<IgaEntitlementRow> =
            sqlx::query_as("SELECT * FROM iga_entitlements WHERE tenant_id = ? ORDER BY id ASC")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_iga_entitlement(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM iga_entitlements WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_iga_access_package(&self, package: &IgaAccessPackageRecord) -> QidResult<()> {
        package.validate()?;
        sqlx::query(
            "INSERT INTO iga_access_packages (id, tenant_id, display_name, owner, entitlement_ids_json, approval_policy_json, max_duration_seconds, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&package.id)
        .bind(&package.tenant_id)
        .bind(&package.display_name)
        .bind(&package.owner)
        .bind(serde_json::to_string(&package.entitlement_ids).unwrap_or_default())
        .bind(package.approval_policy_json.to_string())
        .bind(package.max_duration_seconds.map(|value| value as i64))
        .bind(package.active as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_access_packages(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessPackageRecord>> {
        let rows: Vec<IgaAccessPackageRow> =
            sqlx::query_as("SELECT * FROM iga_access_packages WHERE tenant_id = ? ORDER BY id ASC")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_iga_access_package(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM iga_access_packages WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_iga_access_request(&self, request: &IgaAccessRequestRecord) -> QidResult<()> {
        request.validate()?;
        sqlx::query(
            "INSERT INTO iga_access_requests (id, tenant_id, subject, entitlement, reason, status, approval_steps_json, violations_json, expires_at_epoch_seconds, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&request.id)
        .bind(&request.tenant_id)
        .bind(&request.subject)
        .bind(&request.entitlement)
        .bind(&request.reason)
        .bind(&request.status)
        .bind(request.approval_steps_json.to_string())
        .bind(request.violations_json.to_string())
        .bind(request.expires_at_epoch_seconds.map(|value| value as i64))
        .bind(request.created_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_iga_access_request(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessRequestRecord>> {
        let row: Option<IgaAccessRequestRow> =
            sqlx::query_as("SELECT * FROM iga_access_requests WHERE id = ? AND tenant_id = ?")
                .bind(id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn update_iga_access_request_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> QidResult<()> {
        validate_iga_access_request_status(status)?;
        sqlx::query("UPDATE iga_access_requests SET status = ? WHERE tenant_id = ? AND id = ?")
            .bind(status)
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_access_requests(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessRequestRecord>> {
        let rows: Vec<IgaAccessRequestRow> = sqlx::query_as(
            "SELECT * FROM iga_access_requests WHERE tenant_id = ? ORDER BY created_at_epoch_seconds DESC, id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_iga_approval(&self, approval: &IgaApprovalRecord) -> QidResult<()> {
        approval.validate()?;
        sqlx::query(
            "INSERT INTO iga_approvals (id, tenant_id, request_id, approver, decision, approved_at_epoch_seconds, expires_at_epoch_seconds, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&approval.id)
        .bind(&approval.tenant_id)
        .bind(&approval.request_id)
        .bind(&approval.approver)
        .bind(&approval.decision)
        .bind(approval.approved_at_epoch_seconds as i64)
        .bind(approval.expires_at_epoch_seconds.map(|value| value as i64))
        .bind(&approval.reason)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_approvals(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> QidResult<Vec<IgaApprovalRecord>> {
        let rows: Vec<IgaApprovalRow> = sqlx::query_as(
            "SELECT * FROM iga_approvals WHERE tenant_id = ? AND request_id = ? ORDER BY approved_at_epoch_seconds ASC, id ASC",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_iga_access_grant(&self, grant: &IgaAccessGrantRecord) -> QidResult<()> {
        grant.validate()?;
        sqlx::query(
            "INSERT INTO iga_access_grants (id, tenant_id, request_id, subject, entitlement, granted_at_epoch_seconds, expires_at_epoch_seconds, approval_ids_json, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&grant.id)
        .bind(&grant.tenant_id)
        .bind(&grant.request_id)
        .bind(&grant.subject)
        .bind(&grant.entitlement)
        .bind(grant.granted_at_epoch_seconds as i64)
        .bind(grant.expires_at_epoch_seconds.map(|value| value as i64))
        .bind(serde_json::to_string(&grant.approval_ids).unwrap_or_default())
        .bind(grant.revoked as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_access_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaAccessGrantRecord>> {
        let rows: Vec<IgaAccessGrantRow> = if let Some(subject) = subject {
            sqlx::query_as(
                "SELECT * FROM iga_access_grants WHERE tenant_id = ? AND subject = ? ORDER BY granted_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .bind(subject)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM iga_access_grants WHERE tenant_id = ? ORDER BY granted_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_iga_access_grant(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("UPDATE iga_access_grants SET revoked = 1 WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_iga_jit_privilege_grant(
        &self,
        grant: &IgaJitPrivilegeGrantRecord,
    ) -> QidResult<()> {
        grant.validate()?;
        sqlx::query(
            "INSERT INTO iga_jit_privilege_grants (id, tenant_id, subject, entitlement, requested_by, approved_by, reason, issued_at_epoch_seconds, expires_at_epoch_seconds, revoked, constraints_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&grant.id)
        .bind(&grant.tenant_id)
        .bind(&grant.subject)
        .bind(&grant.entitlement)
        .bind(&grant.requested_by)
        .bind(&grant.approved_by)
        .bind(&grant.reason)
        .bind(grant.issued_at_epoch_seconds as i64)
        .bind(grant.expires_at_epoch_seconds as i64)
        .bind(grant.revoked as i64)
        .bind(grant.constraints_json.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_jit_privilege_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaJitPrivilegeGrantRecord>> {
        let rows: Vec<IgaJitPrivilegeGrantRow> = if let Some(subject) = subject {
            sqlx::query_as(
                "SELECT * FROM iga_jit_privilege_grants WHERE tenant_id = ? AND subject = ? ORDER BY issued_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .bind(subject)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM iga_jit_privilege_grants WHERE tenant_id = ? ORDER BY issued_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_iga_jit_privilege_grant(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query(
            "UPDATE iga_jit_privilege_grants SET revoked = 1 WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_iga_access_review_campaign(
        &self,
        campaign: &IgaAccessReviewCampaignRecord,
    ) -> QidResult<()> {
        campaign.validate()?;
        sqlx::query(
            "INSERT INTO iga_access_review_campaigns (id, tenant_id, reviewer, subjects_json, status, created_at_epoch_seconds, due_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&campaign.id)
        .bind(&campaign.tenant_id)
        .bind(&campaign.reviewer)
        .bind(campaign.subjects_json.to_string())
        .bind(&campaign.status)
        .bind(campaign.created_at_epoch_seconds as i64)
        .bind(campaign.due_at_epoch_seconds.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_iga_access_review_campaign(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessReviewCampaignRecord>> {
        let row: Option<IgaAccessReviewCampaignRow> = sqlx::query_as(
            "SELECT * FROM iga_access_review_campaigns WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_iga_access_review_campaigns(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewCampaignRecord>> {
        let rows: Vec<IgaAccessReviewCampaignRow> = sqlx::query_as(
            "SELECT * FROM iga_access_review_campaigns WHERE tenant_id = ? ORDER BY created_at_epoch_seconds DESC, id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn close_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query(
            "UPDATE iga_access_review_campaigns SET status = 'closed' WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_iga_access_review_decision(
        &self,
        decision: &IgaAccessReviewDecisionRecord,
    ) -> QidResult<()> {
        decision.validate()?;
        sqlx::query(
            "INSERT INTO iga_access_review_decisions (id, tenant_id, campaign_id, subject, reviewer, decision, reason, decided_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&decision.id)
        .bind(&decision.tenant_id)
        .bind(&decision.campaign_id)
        .bind(&decision.subject)
        .bind(&decision.reviewer)
        .bind(&decision.decision)
        .bind(&decision.reason)
        .bind(decision.decided_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_access_review_decisions(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewDecisionRecord>> {
        let rows: Vec<IgaAccessReviewDecisionRow> = sqlx::query_as(
            "SELECT * FROM iga_access_review_decisions WHERE tenant_id = ? AND campaign_id = ? ORDER BY decided_at_epoch_seconds ASC, id ASC",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_iga_certification(
        &self,
        certification: &IgaCertificationRecord,
    ) -> QidResult<()> {
        certification.validate()?;
        sqlx::query(
            "INSERT INTO iga_certifications (id, tenant_id, certification_type, campaign_id, subject, entitlement, certifier, decision, reason, evidence_json, decided_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&certification.id)
        .bind(&certification.tenant_id)
        .bind(&certification.certification_type)
        .bind(&certification.campaign_id)
        .bind(&certification.subject)
        .bind(&certification.entitlement)
        .bind(&certification.certifier)
        .bind(&certification.decision)
        .bind(&certification.reason)
        .bind(certification.evidence_json.to_string())
        .bind(certification.decided_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_certifications(
        &self,
        tenant_id: &str,
        certification_type: Option<&str>,
    ) -> QidResult<Vec<IgaCertificationRecord>> {
        let rows: Vec<IgaCertificationRow> = if let Some(certification_type) = certification_type {
            sqlx::query_as(
                "SELECT * FROM iga_certifications WHERE tenant_id = ? AND certification_type = ? ORDER BY decided_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .bind(certification_type)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM iga_certifications WHERE tenant_id = ? ORDER BY decided_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_iga_finding(&self, finding: &IgaFindingRecord) -> QidResult<()> {
        finding.validate()?;
        sqlx::query(
            "INSERT INTO iga_findings (id, tenant_id, finding_type, subject, severity, evidence_json, detected_at_epoch_seconds, resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&finding.id)
        .bind(&finding.tenant_id)
        .bind(&finding.finding_type)
        .bind(&finding.subject)
        .bind(&finding.severity)
        .bind(finding.evidence_json.to_string())
        .bind(finding.detected_at_epoch_seconds as i64)
        .bind(finding.resolved as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_iga_findings(
        &self,
        tenant_id: &str,
        finding_type: Option<&str>,
    ) -> QidResult<Vec<IgaFindingRecord>> {
        let rows: Vec<IgaFindingRow> = if let Some(finding_type) = finding_type {
            sqlx::query_as(
                "SELECT * FROM iga_findings WHERE tenant_id = ? AND finding_type = ? ORDER BY detected_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .bind(finding_type)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM iga_findings WHERE tenant_id = ? ORDER BY detected_at_epoch_seconds DESC, id ASC",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn resolve_iga_finding(&self, id: &str) -> QidResult<()> {
        sqlx::query("UPDATE iga_findings SET resolved = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}

fn validate_iga_access_request_status(status: &str) -> QidResult<()> {
    match status {
        "auto_approved" | "approval_required" | "approved" | "rejected" => Ok(()),
        _ => Err(qid_core::error::QidError::BadRequest {
            message: "IGA access request status is not supported".to_string(),
        }),
    }
}
