use async_trait::async_trait;

use super::*;
use crate::oidc_continuation as state;

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
        let mut store = self.store.write().await;
        let elevations = &mut store.admin_elevations;
        reject_duplicate_id(elevations.contains_key(&elevation.id), || {
            format!("Admin elevation ID {} already exists", elevation.id)
        })?;
        elevations.insert(elevation.id.clone(), elevation.clone());
        store
            .admin_elevation_expiries
            .insert((elevation.elevation_expires_at, elevation.id.clone()));
        drop(store);
        self.save().await
    }

    async fn cleanup_expired_admin_elevations(&self, now: u64, limit: u32) -> QidResult<u64> {
        state::validate_cleanup(now, limit)?;
        let repo = self.clone();
        tokio::spawn(async move {
            let save_guard = repo.save_lock.lock().await;
            let mut store = repo.store.write().await;
            // Validation bounds now to i64::MAX, so the next expiry cannot
            // overflow. Its exclusive bound includes every id expiring at now.
            let mut oldest = Vec::new();
            // Validate the complete batch before mutating either structure.
            for (expiry, id) in store
                .admin_elevation_expiries
                .range(..(now + 1, String::new()))
                .take(limit as usize)
            {
                #[cfg(test)]
                repo.admin_elevation_cleanup_visits
                    .fetch_add(1, Ordering::Relaxed);
                if !store
                    .admin_elevations
                    .get(id)
                    .is_some_and(|row| row.id == *id && row.elevation_expires_at == *expiry)
                {
                    return Err(QidError::Internal {
                        message: "admin elevation index is inconsistent".into(),
                    });
                }
                oldest.push((*expiry, id.clone()));
            }
            let removed: Vec<_> = oldest
                .into_iter()
                .filter_map(|entry| {
                    store.admin_elevation_expiries.remove(&entry);
                    let (_, id) = entry;
                    store.admin_elevations.remove(&id).map(|row| (id, row))
                })
                .collect();
            let deleted = removed.len() as u64;
            if deleted == 0 {
                return Ok(0);
            }
            let written = async {
                let content = serde_json::to_string(&*store).map_err(|_| QidError::Internal {
                    message: "admin elevation cleanup serialization failed".into(),
                })?;
                repo.write_store_content_locked(&save_guard, &content).await
            }
            .await;
            if let Err(error) = written {
                for (id, row) in removed {
                    store
                        .admin_elevation_expiries
                        .insert((row.elevation_expires_at, id.clone()));
                    store.admin_elevations.insert(id, row);
                }
                return Err(error);
            }
            Ok(deleted)
        })
        .await
        .map_err(|_| QidError::Internal {
            message: "admin elevation cleanup task failed".into(),
        })?
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
