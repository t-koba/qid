use async_trait::async_trait;

use super::*;

#[async_trait]
impl WorkloadRepository for FileRepository {
    async fn create_workload_identity(&self, wi: &WorkloadIdentity) -> QidResult<()> {
        let mut store = self.store.write().await;
        crate::ownership::ensure_same_binding(
            store
                .workload_identities
                .get(&wi.id)
                .map(|stored| (&stored.realm_id, &stored.spiffe_id)),
            (&wi.realm_id, &wi.spiffe_id),
            || "workload identity ID belongs to another identity".to_string(),
        )?;
        if store.workload_identities.values().any(|stored| {
            stored.id != wi.id && stored.realm_id == wi.realm_id && stored.spiffe_id == wi.spiffe_id
        }) {
            return Err(QidError::BadRequest {
                message: "SPIFFE identity already registered in this realm".to_string(),
            });
        }
        store.workload_identities.insert(wi.id.clone(), wi.clone());
        drop(store);
        self.save().await
    }

    async fn get_workload_identity_by_spiffe(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> QidResult<Option<WorkloadIdentity>> {
        let store = self.store.read().await;
        store
            .workload_identities
            .values()
            .filter(|wi| wi.realm_id == realm_id.0 && wi.spiffe_id == spiffe_id)
            .try_fold(None, |found, wi| match found {
                None => Ok(Some(wi.clone())),
                Some(_) => Err(QidError::Internal {
                    message: "ambiguous SPIFFE binding; repair file store, then retry".into(),
                }),
            })
    }

    async fn list_workload_identities(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<WorkloadIdentity>> {
        let store = self.store.read().await;
        let mut identities: Vec<_> = store
            .workload_identities
            .values()
            .filter(|wi| wi.realm_id == realm_id.0)
            .cloned()
            .collect();
        identities.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(identities)
    }

    async fn delete_workload_identity(&self, realm_id: &RealmId, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let owned = store
            .workload_identities
            .get(id)
            .is_some_and(|stored| stored.realm_id == realm_id.0);
        if !owned {
            return Err(QidError::NotFound {
                resource: format!("workload identity {id}"),
            });
        }
        store.workload_identities.remove(id);
        drop(store);
        self.save().await
    }

    async fn store_workload_certificate(&self, certificate: &WorkloadCertificate) -> QidResult<()> {
        certificate.validate()?;
        let mut store = self.store.write().await;
        let workload = store.workload_identities.get(&certificate.workload_id);
        certificate.validate_workload_identity_binding(
            workload.map(|workload| (workload.realm_id.as_str(), workload.spiffe_id.as_str())),
        )?;
        if store
            .workload_certificates
            .get(&certificate.id)
            .is_some_and(|stored| stored.revoked_at.is_some())
        {
            return Err(QidError::Conflict {
                message: "workload certificate ID is revoked or belongs to another identity"
                    .to_string(),
            });
        }
        crate::ownership::ensure_same_binding(
            store
                .workload_certificates
                .get(&certificate.id)
                .map(|stored| (&stored.realm_id, &stored.workload_id, &stored.spiffe_id)),
            (
                &certificate.realm_id,
                &certificate.workload_id,
                &certificate.spiffe_id,
            ),
            || "workload certificate ID is revoked or belongs to another identity".to_string(),
        )?;
        if store.workload_certificates.values().any(|stored| {
            stored.id != certificate.id
                && stored.realm_id == certificate.realm_id
                && stored.x5t_s256 == certificate.x5t_s256
        }) {
            return Err(QidError::BadRequest {
                message: "workload certificate thumbprint already exists".to_string(),
            });
        }
        store
            .workload_certificates
            .insert(certificate.id.clone(), certificate.clone());
        drop(store);
        self.save().await
    }

    async fn list_workload_certificates(
        &self,
        realm_id: &RealmId,
        workload_id: Option<&str>,
    ) -> QidResult<Vec<WorkloadCertificate>> {
        let store = self.store.read().await;
        let mut certificates = store
            .workload_certificates
            .values()
            .filter(|certificate| {
                certificate.realm_id == realm_id.0
                    && workload_id.is_none_or(|id| certificate.workload_id == id)
            })
            .cloned()
            .collect::<Vec<_>>();
        certificates.sort_by(|a, b| b.not_after.cmp(&a.not_after).then_with(|| a.id.cmp(&b.id)));
        Ok(certificates)
    }

    async fn has_eligible_cert(&self, workload: &WorkloadIdentity, now: u64) -> QidResult<bool> {
        let store = self.store.read().await;
        Ok(store
            .workload_certificates
            .values()
            .any(|cert| cert.is_eligible_for(workload, now)))
    }

    async fn revoke_workload_certificate(
        &self,
        realm_id: &RealmId,
        id: &str,
        revoked_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let mut updated = store
            .workload_certificates
            .get(id)
            .filter(|certificate| certificate.realm_id == realm_id.0)
            .cloned()
            .ok_or_else(|| QidError::NotFound {
                resource: format!("workload certificate {id}"),
            })?;
        updated.revoked_at = Some(revoked_at);
        updated.validate()?;
        store.workload_certificates.insert(id.to_string(), updated);
        drop(store);
        self.save().await
    }
}
