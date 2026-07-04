use async_trait::async_trait;

use super::*;

#[async_trait]
impl AuditRepository for FileRepository {
    async fn append_audit_event(&self, event: &AuditEvent) -> QidResult<()> {
        let mut store = self.store.write().await;
        let previous_hash = store
            .audit_events
            .iter()
            .rev()
            .find(|stored| stored.realm_id == event.realm_id)
            .and_then(|event| event.event_hash.clone());
        store
            .audit_events
            .push(event.clone().with_chain_hashes(previous_hash));
        drop(store);
        self.save().await
    }

    async fn list_audit_events(
        &self,
        realm_id: Option<&RealmId>,
        limit: usize,
    ) -> QidResult<Vec<AuditEvent>> {
        let store = self.store.read().await;
        let mut events: Vec<_> = store
            .audit_events
            .iter()
            .filter(|event| {
                realm_id
                    .map(|realm| event.realm_id.as_deref() == Some(realm.as_str()))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        events.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        events.truncate(limit);
        Ok(events)
    }

    async fn verify_audit_chain(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<AuditChainVerification> {
        let store = self.store.read().await;
        let events: Vec<_> = store
            .audit_events
            .iter()
            .filter(|event| {
                realm_id
                    .map(|realm| event.realm_id.as_deref() == Some(realm.as_str()))
                    .unwrap_or(true)
            })
            .collect();
        if realm_id.is_some() {
            Ok(verify_audit_chain_linked(events))
        } else {
            Ok(verify_audit_chains_by_realm(events))
        }
    }

    async fn set_audit_retention_config(&self, config: &AuditRetentionConfig) -> QidResult<()> {
        let key = audit_retention_key(config.realm_id.as_deref());
        let mut store = self.store.write().await;
        store.audit_retention_configs.insert(key, config.clone());
        drop(store);
        self.save().await
    }

    async fn get_audit_retention_config(
        &self,
        realm_id: Option<&RealmId>,
    ) -> QidResult<Option<AuditRetentionConfig>> {
        let store = self.store.read().await;
        Ok(store
            .audit_retention_configs
            .get(&audit_retention_key(realm_id.map(RealmId::as_str)))
            .cloned())
    }

    async fn plan_audit_retention(
        &self,
        realm_id: Option<&RealmId>,
        now_epoch: u64,
    ) -> QidResult<Option<AuditRetentionEnforcementPlan>> {
        let store = self.store.read().await;
        let Some(config) = store
            .audit_retention_configs
            .get(&audit_retention_key(realm_id.map(RealmId::as_str)))
        else {
            return Ok(None);
        };
        let events: Vec<_> = store
            .audit_events
            .iter()
            .filter(|event| {
                realm_id
                    .map(|realm| event.realm_id.as_deref() == Some(realm.as_str()))
                    .unwrap_or(true)
            })
            .collect();
        Ok(Some(plan_audit_retention_enforcement(
            config, now_epoch, events,
        )))
    }
}
