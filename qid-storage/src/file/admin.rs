use async_trait::async_trait;

use super::*;

#[async_trait]
impl AdminRepository for FileRepository {
    async fn get_admin(&self, tenant_id: &str, subject: &str) -> QidResult<Option<Admin>> {
        let admins = &self.store.read().await.admins;
        let matches = admins
            .values()
            .filter(|a| a.tenant_id == tenant_id && a.subject == subject);
        Ok(unique_match(matches, "ambiguous admin identity")?.cloned())
    }

    async fn get_admin_by_id(&self, id: &str) -> QidResult<Option<Admin>> {
        Ok(self.map_get(|store| store.admins.get(id)).await)
    }

    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()> {
        let mut store = self.store.write().await;
        crate::ownership::ensure_same_binding(
            store
                .admins
                .get(&admin.id)
                .map(|a| (&a.tenant_id, &a.subject)),
            (&admin.tenant_id, &admin.subject),
            || format!("Admin ID {} belongs to another identity", admin.id),
        )?;
        let matches = store
            .admins
            .values_mut()
            .filter(|a| a.tenant_id == admin.tenant_id && a.subject == admin.subject);
        if let Some(incumbent) = unique_match(matches, "ambiguous admin identity")? {
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
        self.insert_id_if_absent(
            |store| &mut store.admin_elevations,
            elevation.id.clone(),
            elevation.clone(),
            || format!("Admin elevation ID {} already exists", elevation.id),
        )
        .await
    }

    async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>> {
        Ok(self.map_get(|store| store.admin_approvals.get(id)).await)
    }

    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()> {
        self.insert_id_if_absent(
            |store| &mut store.admin_approvals,
            approval.id.clone(),
            approval.clone(),
            || format!("Admin approval ID {} already exists", approval.id),
        )
        .await
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
