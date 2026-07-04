use async_trait::async_trait;

use super::*;

#[async_trait]
impl WorkloadRepository for FileRepository {
    async fn create_workload_identity(&self, wi: &WorkloadIdentity) -> QidResult<()> {
        let mut store = self.store.write().await;
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
        Ok(store
            .workload_identities
            .values()
            .find(|wi| wi.realm_id == realm_id.0 && wi.spiffe_id == spiffe_id)
            .cloned())
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

    async fn delete_workload_identity(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.workload_identities.remove(id);
        drop(store);
        self.save().await
    }

    async fn store_workload_certificate(&self, certificate: &WorkloadCertificate) -> QidResult<()> {
        certificate.validate()?;
        let mut store = self.store.write().await;
        let Some(workload) = store.workload_identities.get(&certificate.workload_id) else {
            return Err(QidError::BadRequest {
                message: "workload certificate workload does not exist".to_string(),
            });
        };
        if workload.realm_id != certificate.realm_id || workload.spiffe_id != certificate.spiffe_id
        {
            return Err(QidError::BadRequest {
                message: "workload certificate identity does not match workload".to_string(),
            });
        }
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
            .filter(|certificate| certificate.realm_id == realm_id.0)
            .filter(|certificate| {
                workload_id.is_none_or(|workload_id| certificate.workload_id == workload_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        certificates.sort_by(|a, b| b.not_after.cmp(&a.not_after).then_with(|| a.id.cmp(&b.id)));
        Ok(certificates)
    }

    async fn revoke_workload_certificate(
        &self,
        realm_id: &RealmId,
        id: &str,
        revoked_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let certificate = store
            .workload_certificates
            .get_mut(id)
            .filter(|certificate| certificate.realm_id == realm_id.0)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("workload certificate {id}"),
            })?;
        certificate.revoked_at = Some(revoked_at);
        certificate.validate()?;
        drop(store);
        self.save().await
    }
}
