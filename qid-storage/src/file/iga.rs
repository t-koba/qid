use async_trait::async_trait;

use super::*;

#[async_trait]
impl IgaRepository for FileRepository {
    async fn store_iga_entitlement(&self, entitlement: &IgaEntitlementRecord) -> QidResult<()> {
        entitlement.validate()?;
        let mut store = self.store.write().await;
        store.iga_entitlements.insert(
            iga_tenant_scoped_key(&entitlement.tenant_id, &entitlement.id),
            entitlement.clone(),
        );
        drop(store);
        self.save().await
    }

    async fn list_iga_entitlements(&self, tenant_id: &str) -> QidResult<Vec<IgaEntitlementRecord>> {
        let store = self.store.read().await;
        let mut entitlements: Vec<_> = store
            .iga_entitlements
            .values()
            .filter(|entitlement| entitlement.tenant_id == tenant_id)
            .cloned()
            .collect();
        entitlements.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entitlements)
    }

    async fn delete_iga_entitlement(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .iga_entitlements
            .remove(&iga_tenant_scoped_key(tenant_id, id));
        drop(store);
        self.save().await
    }

    async fn store_iga_access_package(&self, package: &IgaAccessPackageRecord) -> QidResult<()> {
        package.validate()?;
        let mut store = self.store.write().await;
        store.iga_access_packages.insert(
            iga_tenant_scoped_key(&package.tenant_id, &package.id),
            package.clone(),
        );
        drop(store);
        self.save().await
    }

    async fn list_iga_access_packages(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessPackageRecord>> {
        let store = self.store.read().await;
        let mut packages: Vec<_> = store
            .iga_access_packages
            .values()
            .filter(|package| package.tenant_id == tenant_id)
            .cloned()
            .collect();
        packages.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(packages)
    }

    async fn delete_iga_access_package(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .iga_access_packages
            .remove(&iga_tenant_scoped_key(tenant_id, id));
        drop(store);
        self.save().await
    }

    async fn store_iga_access_request(&self, request: &IgaAccessRequestRecord) -> QidResult<()> {
        request.validate()?;
        let mut store = self.store.write().await;
        if store.iga_access_requests.contains_key(&request.id) {
            return Err(QidError::Conflict {
                message: format!("IGA access request ID {} already exists", request.id),
            });
        }
        store
            .iga_access_requests
            .insert(request.id.clone(), request.clone());
        drop(store);
        self.save().await
    }

    async fn get_iga_access_request(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessRequestRecord>> {
        let store = self.store.read().await;
        Ok(store
            .iga_access_requests
            .get(id)
            .cloned()
            .filter(|r| r.tenant_id == tenant_id))
    }

    async fn update_iga_access_request_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> QidResult<()> {
        validate_iga_access_request_status(status)?;
        let mut store = self.store.write().await;
        if let Some(request) = store.iga_access_requests.get_mut(id)
            && request.tenant_id == tenant_id
        {
            request.status = status.to_string();
        }
        drop(store);
        self.save().await
    }

    async fn list_iga_access_requests(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessRequestRecord>> {
        let store = self.store.read().await;
        let mut requests: Vec<_> = store
            .iga_access_requests
            .values()
            .filter(|request| request.tenant_id == tenant_id)
            .cloned()
            .collect();
        requests.sort_by(|a, b| {
            b.created_at_epoch_seconds
                .cmp(&a.created_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(requests)
    }

    async fn store_iga_approval(&self, approval: &IgaApprovalRecord) -> QidResult<()> {
        approval.validate()?;
        let mut store = self.store.write().await;
        store
            .iga_approvals
            .insert(approval.id.clone(), approval.clone());
        drop(store);
        self.save().await
    }

    async fn list_iga_approvals(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> QidResult<Vec<IgaApprovalRecord>> {
        let store = self.store.read().await;
        let mut approvals: Vec<_> = store
            .iga_approvals
            .values()
            .filter(|approval| approval.tenant_id == tenant_id && approval.request_id == request_id)
            .cloned()
            .collect();
        approvals.sort_by(|a, b| {
            a.approved_at_epoch_seconds
                .cmp(&b.approved_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(approvals)
    }

    async fn store_iga_access_grant(&self, grant: &IgaAccessGrantRecord) -> QidResult<()> {
        grant.validate()?;
        let mut store = self.store.write().await;
        store
            .iga_access_grants
            .insert(grant.id.clone(), grant.clone());
        drop(store);
        self.save().await
    }

    async fn ensure_iga_access_grants(
        &self,
        candidates: &[IgaAccessGrantRecord],
    ) -> QidResult<Vec<IgaAccessGrantRecord>> {
        crate::iga_grants::validate_candidates(candidates)?;
        if self.flush_mode == FileFlushMode::Immediate {
            // Like realm deletion, finish persistence/rollback if the caller
            // cancels during a filesystem await.
            let repo = self.clone();
            let candidates = candidates.to_vec();
            return tokio::spawn(
                async move { repo.ensure_iga_access_grants_inner(&candidates).await },
            )
            .await
            .map_err(|error| QidError::Internal {
                message: format!("grant materialization task failed: {error}"),
            })?;
        }
        self.ensure_iga_access_grants_inner(candidates).await
    }

    async fn list_iga_access_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaAccessGrantRecord>> {
        let store = self.store.read().await;
        let mut grants: Vec<_> = store
            .iga_access_grants
            .values()
            .filter(|grant| {
                grant.tenant_id == tenant_id && subject.is_none_or(|value| grant.subject == value)
            })
            .cloned()
            .collect();
        grants.sort_by(|a, b| {
            b.granted_at_epoch_seconds
                .cmp(&a.granted_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(grants)
    }

    async fn revoke_iga_access_grant(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(grant) = store.iga_access_grants.get_mut(id)
            && grant.tenant_id == tenant_id
        {
            grant.revoked = true;
        }
        drop(store);
        self.save().await
    }

    async fn store_iga_jit_privilege_grant(
        &self,
        grant: &IgaJitPrivilegeGrantRecord,
    ) -> QidResult<()> {
        grant.validate()?;
        let mut store = self.store.write().await;
        store
            .iga_jit_privilege_grants
            .insert(grant.id.clone(), grant.clone());
        drop(store);
        self.save().await
    }

    async fn list_iga_jit_privilege_grants(
        &self,
        tenant_id: &str,
        subject: Option<&str>,
    ) -> QidResult<Vec<IgaJitPrivilegeGrantRecord>> {
        let store = self.store.read().await;
        let mut grants: Vec<_> = store
            .iga_jit_privilege_grants
            .values()
            .filter(|grant| {
                grant.tenant_id == tenant_id && subject.is_none_or(|value| grant.subject == value)
            })
            .cloned()
            .collect();
        grants.sort_by(|a, b| {
            b.issued_at_epoch_seconds
                .cmp(&a.issued_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(grants)
    }

    async fn revoke_iga_jit_privilege_grant(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(grant) = store.iga_jit_privilege_grants.get_mut(id)
            && grant.tenant_id == tenant_id
        {
            grant.revoked = true;
        }
        drop(store);
        self.save().await
    }

    async fn store_iga_access_review_campaign(
        &self,
        campaign: &IgaAccessReviewCampaignRecord,
    ) -> QidResult<()> {
        campaign.validate()?;
        let mut store = self.store.write().await;
        store
            .iga_access_review_campaigns
            .insert(campaign.id.clone(), campaign.clone());
        drop(store);
        self.save().await
    }

    async fn get_iga_access_review_campaign(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> QidResult<Option<IgaAccessReviewCampaignRecord>> {
        let store = self.store.read().await;
        Ok(store
            .iga_access_review_campaigns
            .get(id)
            .cloned()
            .filter(|c| c.tenant_id == tenant_id))
    }

    async fn list_iga_access_review_campaigns(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewCampaignRecord>> {
        let store = self.store.read().await;
        let mut campaigns: Vec<_> = store
            .iga_access_review_campaigns
            .values()
            .filter(|campaign| campaign.tenant_id == tenant_id)
            .cloned()
            .collect();
        campaigns.sort_by(|a, b| {
            b.created_at_epoch_seconds
                .cmp(&a.created_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(campaigns)
    }

    async fn close_iga_access_review_campaign(&self, tenant_id: &str, id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let closed = if let Some(campaign) = store
            .iga_access_review_campaigns
            .get_mut(id)
            .filter(|c| c.tenant_id == tenant_id)
        {
            campaign.status = "closed".to_string();
            true
        } else {
            false
        };
        drop(store);
        if !closed {
            return Ok(false);
        }
        self.save().await?;
        Ok(true)
    }

    async fn store_iga_access_review_decision(
        &self,
        decision: &IgaAccessReviewDecisionRecord,
    ) -> QidResult<()> {
        decision.validate()?;
        let mut store = self.store.write().await;
        if store.iga_access_review_decisions.contains_key(&decision.id) {
            return Err(QidError::Conflict {
                message: format!(
                    "IGA access review decision ID {} already exists",
                    decision.id
                ),
            });
        }
        store
            .iga_access_review_decisions
            .insert(decision.id.clone(), decision.clone());
        drop(store);
        self.save().await
    }

    async fn list_iga_access_review_decisions(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> QidResult<Vec<IgaAccessReviewDecisionRecord>> {
        let store = self.store.read().await;
        let mut decisions: Vec<_> = store
            .iga_access_review_decisions
            .values()
            .filter(|decision| {
                decision.tenant_id == tenant_id && decision.campaign_id == campaign_id
            })
            .cloned()
            .collect();
        decisions.sort_by(|a, b| {
            a.decided_at_epoch_seconds
                .cmp(&b.decided_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(decisions)
    }

    async fn store_iga_certification(
        &self,
        certification: &IgaCertificationRecord,
    ) -> QidResult<()> {
        certification.validate()?;
        let mut store = self.store.write().await;
        if store.iga_certifications.contains_key(&certification.id) {
            return Err(QidError::Conflict {
                message: format!("IGA certification ID {} already exists", certification.id),
            });
        }
        store
            .iga_certifications
            .insert(certification.id.clone(), certification.clone());
        drop(store);
        self.save().await
    }

    async fn list_iga_certifications(
        &self,
        tenant_id: &str,
        certification_type: Option<&str>,
    ) -> QidResult<Vec<IgaCertificationRecord>> {
        let store = self.store.read().await;
        let mut certifications: Vec<_> = store
            .iga_certifications
            .values()
            .filter(|certification| {
                certification.tenant_id == tenant_id
                    && certification_type
                        .is_none_or(|value| certification.certification_type == value)
            })
            .cloned()
            .collect();
        certifications.sort_by(|a, b| {
            b.decided_at_epoch_seconds
                .cmp(&a.decided_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(certifications)
    }

    async fn store_iga_finding(&self, finding: &IgaFindingRecord) -> QidResult<()> {
        finding.validate()?;
        let mut store = self.store.write().await;
        if store.iga_findings.contains_key(&finding.id) {
            return Err(QidError::Conflict {
                message: format!("IGA finding ID {} already exists", finding.id),
            });
        }
        store
            .iga_findings
            .insert(finding.id.clone(), finding.clone());
        drop(store);
        self.save().await
    }

    async fn list_iga_findings(
        &self,
        tenant_id: &str,
        finding_type: Option<&str>,
    ) -> QidResult<Vec<IgaFindingRecord>> {
        let store = self.store.read().await;
        let mut findings: Vec<_> = store
            .iga_findings
            .values()
            .filter(|finding| {
                finding.tenant_id == tenant_id
                    && finding_type.is_none_or(|value| finding.finding_type == value)
            })
            .cloned()
            .collect();
        findings.sort_by(|a, b| {
            b.detected_at_epoch_seconds
                .cmp(&a.detected_at_epoch_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(findings)
    }

    async fn resolve_iga_finding(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(finding) = store.iga_findings.get_mut(id) {
            finding.resolved = true;
        }
        drop(store);
        self.save().await
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

impl FileRepository {
    async fn ensure_iga_access_grants_inner(
        &self,
        candidates: &[IgaAccessGrantRecord],
    ) -> QidResult<Vec<IgaAccessGrantRecord>> {
        let first = &candidates[0];
        let save_guard = if self.flush_mode == FileFlushMode::Immediate {
            Some(self.save_lock.lock().await)
        } else {
            None
        };
        let mut store = self.store.write().await;
        let request = store
            .iga_access_requests
            .get(&first.request_id)
            .filter(|request| request.tenant_id == first.tenant_id)
            .ok_or_else(|| QidError::BadRequest {
                message: "IGA access request not found".to_string(),
            })?;
        let incumbents: Vec<_> = store
            .iga_access_grants
            .values()
            .filter(|grant| {
                grant.tenant_id == first.tenant_id && grant.request_id == first.request_id
            })
            .cloned()
            .collect();
        let missing = crate::iga_grants::missing_grants(candidates, request, &incumbents)?;
        for candidate in candidates {
            if let Some(incumbent) = store.iga_access_grants.get(&candidate.id)
                && (incumbent.tenant_id != candidate.tenant_id
                    || incumbent.request_id != candidate.request_id
                    || incumbent.subject != candidate.subject
                    || incumbent.entitlement != candidate.entitlement)
            {
                return Err(QidError::BadRequest {
                    message: "IGA grant ID belongs to another binding".to_string(),
                });
            }
        }
        if missing.is_empty() {
            return Ok(missing);
        }
        // Stage and validate before mutation. Hold both locks through the one
        // persistence attempt and rollback so no tentative state is visible.
        let previous = save_guard.as_ref().map(|_| store.clone());
        for grant in &missing {
            store
                .iga_access_grants
                .insert(grant.id.clone(), grant.clone());
        }
        if let Some(guard) = save_guard {
            let result = async {
                #[cfg(test)]
                self.before_flush().await?;
                let content =
                    serde_json::to_string(&*store).map_err(|error| QidError::Internal {
                        message: format!("failed to serialize store: {error}"),
                    })?;
                self.write_store_content_locked(&guard, &content).await
            }
            .await;
            if let Err(error) = result {
                *store = previous.unwrap();
                return Err(error);
            }
        } else {
            self.dirty.store(true, Ordering::Release);
        }
        Ok(missing)
    }
}
