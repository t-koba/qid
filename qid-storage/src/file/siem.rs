use async_trait::async_trait;

use super::*;

#[async_trait]
impl SiemDeliveryRepository for FileRepository {
    async fn upsert_siem_delivery(&self, delivery: &SiemDeliveryRecord) -> QidResult<()> {
        let mut store = self.store.write().await;
        let incumbent = store.siem_deliveries.get(&delivery.id);
        crate::ownership::ensure_same_binding(
            incumbent.map(|existing| &existing.realm_id),
            &delivery.realm_id,
            || "SIEM delivery ID belongs to a different realm scope".to_string(),
        )?;
        let incumbent_created_at = incumbent.map(|existing| existing.created_at);
        let mut stored = delivery.clone();
        if let Some(created_at) = incumbent_created_at {
            stored.created_at = created_at;
        }
        store.siem_deliveries.insert(delivery.id.clone(), stored);
        drop(store);
        self.save().await
    }

    async fn get_siem_delivery(&self, id: &str) -> QidResult<Option<SiemDeliveryRecord>> {
        Ok(self.map_get(|store| store.siem_deliveries.get(id)).await)
    }

    async fn list_siem_deliveries(
        &self,
        realm_id: Option<&str>,
        status: Option<SiemDeliveryStatus>,
        limit: usize,
    ) -> QidResult<Vec<SiemDeliveryRecord>> {
        let store = self.store.read().await;
        let mut deliveries = store
            .siem_deliveries
            .values()
            .filter(|delivery| {
                realm_id
                    .map(|realm| delivery.realm_id.as_deref() == Some(realm))
                    .unwrap_or(true)
            })
            .filter(|delivery| {
                status
                    .as_ref()
                    .map(|status| delivery.status == *status)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        deliveries.sort_by(|a, b| {
            a.next_retry_at
                .unwrap_or(a.created_at)
                .cmp(&b.next_retry_at.unwrap_or(b.created_at))
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        deliveries.truncate(limit.min(1_000));
        Ok(deliveries)
    }

    async fn mark_siem_delivery_status(
        &self,
        id: &str,
        status: SiemDeliveryStatus,
        attempts: u32,
        next_retry_at: Option<u64>,
        last_error: Option<&str>,
        updated_at: u64,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        let delivery = store
            .siem_deliveries
            .get_mut(id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("siem delivery {id}"),
            })?;
        delivery.status = status;
        delivery.attempts = attempts;
        delivery.next_retry_at = next_retry_at;
        delivery.last_error = last_error.map(str::to_string);
        delivery.updated_at = updated_at;
        drop(store);
        self.save().await
    }
}
