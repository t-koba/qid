use async_trait::async_trait;

use super::*;

#[async_trait]
impl AdminRepository for FileRepository {
    async fn get_admin(&self, tenant_id: &str, subject: &str) -> QidResult<Option<Admin>> {
        let store = self.store.read().await;
        Ok(store
            .admins
            .values()
            .find(|a| a.tenant_id == tenant_id && a.subject == subject)
            .cloned())
    }

    async fn get_admin_by_id(&self, id: &str) -> QidResult<Option<Admin>> {
        Ok(self.map_get(|store| store.admins.get(id)).await)
    }

    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(incumbent) = store
            .admins
            .values_mut()
            .find(|a| a.tenant_id == admin.tenant_id && a.subject == admin.subject)
        {
            incumbent.roles.clone_from(&admin.roles);
        } else {
            store.admins.insert(admin.id.clone(), admin.clone());
        }
        drop(store);
        self.save().await
    }

    async fn get_admin_elevation(&self, id: &str) -> QidResult<Option<AdminElevation>> {
        Ok(self.map_get(|store| store.admin_elevations.get(id)).await)
    }

    async fn store_admin_elevation(&self, elevation: &AdminElevation) -> QidResult<()> {
        let mut store = self.store.write().await;
        reject_duplicate_id(store.admin_elevations.contains_key(&elevation.id), || {
            format!("Admin elevation ID {} already exists", elevation.id)
        })?;
        store
            .admin_elevations
            .insert(elevation.id.clone(), elevation.clone());
        drop(store);
        self.save().await
    }

    async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>> {
        Ok(self.map_get(|store| store.admin_approvals.get(id)).await)
    }

    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()> {
        let mut store = self.store.write().await;
        reject_duplicate_id(store.admin_approvals.contains_key(&approval.id), || {
            format!("Admin approval ID {} already exists", approval.id)
        })?;
        store
            .admin_approvals
            .insert(approval.id.clone(), approval.clone());
        drop(store);
        self.save().await
    }

    async fn consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let Some(approval) = store.admin_approvals.get_mut(id).filter(|a| !a.consumed) else {
            return Ok(false);
        };
        approval.consumed = true;
        drop(store);
        self.save().await?;
        Ok(true)
    }
}
