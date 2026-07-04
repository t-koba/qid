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
        let store = self.store.read().await;
        Ok(store.admins.get(id).cloned())
    }

    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()> {
        let mut store = self.store.write().await;
        // Remove existing entry with same tenant_id + subject before inserting
        store
            .admins
            .retain(|_, a| !(a.tenant_id == admin.tenant_id && a.subject == admin.subject));
        store.admins.insert(admin.id.clone(), admin.clone());
        drop(store);
        self.save().await
    }

    async fn get_admin_elevation(&self, id: &str) -> QidResult<Option<AdminElevation>> {
        let store = self.store.read().await;
        Ok(store.admin_elevations.get(id).cloned())
    }

    async fn store_admin_elevation(&self, elevation: &AdminElevation) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .admin_elevations
            .insert(elevation.id.clone(), elevation.clone());
        drop(store);
        self.save().await
    }

    async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>> {
        let store = self.store.read().await;
        Ok(store.admin_approvals.get(id).cloned())
    }

    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .admin_approvals
            .insert(approval.id.clone(), approval.clone());
        drop(store);
        self.save().await
    }

    async fn consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let consumed = if let Some(approval) = store.admin_approvals.get_mut(id) {
            if approval.consumed {
                false
            } else {
                approval.consumed = true;
                true
            }
        } else {
            false
        };
        drop(store);
        if consumed {
            self.save().await?;
        }
        Ok(consumed)
    }
}
