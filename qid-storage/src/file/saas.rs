use async_trait::async_trait;

use super::*;

#[async_trait]
impl SaasRepository for FileRepository {
    async fn list_saas_tenant_ids(&self) -> QidResult<Vec<String>> {
        let store = self.store.read().await;
        let mut tenant_ids = std::collections::BTreeSet::new();
        tenant_ids.extend(
            store
                .custom_domains
                .values()
                .map(|domain| domain.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .ciam_brands
                .values()
                .map(|brand| brand.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .app_catalog_entries
                .values()
                .map(|entry| entry.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .marketplace_connectors
                .values()
                .map(|connector| connector.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .usage_billing_events
                .values()
                .map(|event| event.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .compliance_evidence_packs
                .values()
                .map(|pack| pack.tenant_id.clone()),
        );
        tenant_ids.extend(
            store
                .delegated_tenant_admins
                .values()
                .map(|admin| admin.tenant_id.clone()),
        );
        Ok(tenant_ids.into_iter().collect())
    }

    async fn store_custom_domain(&self, domain: &CustomDomain) -> QidResult<()> {
        domain.validate()?;
        let mut store = self.store.write().await;
        let Some(realm_tenant) = store.realm_tenants.get(&domain.realm_id) else {
            return Err(QidError::Storage {
                message: "custom domain realm does not exist".to_string(),
            });
        };
        if realm_tenant != &domain.tenant_id {
            return Err(QidError::Storage {
                message: "custom domain realm belongs to another tenant".to_string(),
            });
        }
        if store.custom_domains.values().any(|stored| {
            stored.id != domain.id && stored.hostname.eq_ignore_ascii_case(&domain.hostname)
        }) {
            return Err(QidError::Storage {
                message: "custom domain hostname already exists".to_string(),
            });
        }
        store
            .custom_domains
            .insert(domain.id.clone(), domain.clone());
        drop(store);
        self.save().await
    }

    async fn list_custom_domains(&self, tenant_id: &str) -> QidResult<Vec<CustomDomain>> {
        let store = self.store.read().await;
        let mut domains: Vec<_> = store
            .custom_domains
            .values()
            .filter(|domain| domain.tenant_id == tenant_id)
            .cloned()
            .collect();
        domains.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(domains)
    }

    async fn delete_custom_domain(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .custom_domains
            .get(id)
            .is_some_and(|domain| domain.tenant_id == tenant_id)
        {
            store.custom_domains.remove(id);
        }
        drop(store);
        self.save().await
    }

    async fn store_ciam_brand(&self, brand: &CiamBrand) -> QidResult<()> {
        brand.validate()?;
        let mut store = self.store.write().await;
        let Some(realm_tenant) = store.realm_tenants.get(&brand.realm_id) else {
            return Err(QidError::Storage {
                message: "CIAM brand realm does not exist".to_string(),
            });
        };
        if realm_tenant != &brand.tenant_id {
            return Err(QidError::Storage {
                message: "CIAM brand realm belongs to another tenant".to_string(),
            });
        }
        store.ciam_brands.insert(brand.id.clone(), brand.clone());
        drop(store);
        self.save().await
    }

    async fn list_ciam_brands(&self, tenant_id: &str) -> QidResult<Vec<CiamBrand>> {
        let store = self.store.read().await;
        let mut brands: Vec<_> = store
            .ciam_brands
            .values()
            .filter(|brand| brand.tenant_id == tenant_id)
            .cloned()
            .collect();
        brands.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(brands)
    }

    async fn delete_ciam_brand(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .ciam_brands
            .get(id)
            .is_some_and(|brand| brand.tenant_id == tenant_id)
        {
            store.ciam_brands.remove(id);
        }
        drop(store);
        self.save().await
    }

    async fn store_app_catalog_entry(&self, entry: &AppCatalogEntry) -> QidResult<()> {
        entry.validate()?;
        let mut store = self.store.write().await;
        let Some(realm_tenant) = store.realm_tenants.get(&entry.realm_id) else {
            return Err(QidError::Storage {
                message: "app catalog realm does not exist".to_string(),
            });
        };
        if realm_tenant != &entry.tenant_id {
            return Err(QidError::Storage {
                message: "app catalog realm belongs to another tenant".to_string(),
            });
        }
        if let Some(oidc_client_id) = &entry.oidc_client_id {
            let client_exists = store.clients.values().any(|client| {
                client.realm_id == entry.realm_id && client.client_id == *oidc_client_id
            });
            if !client_exists {
                return Err(QidError::Storage {
                    message: "app catalog OIDC client does not exist in realm".to_string(),
                });
            }
        }
        if let Some(connector_id) = &entry.marketplace_connector_id {
            let Some(connector) = store.marketplace_connectors.get(connector_id) else {
                return Err(QidError::Storage {
                    message: "app catalog marketplace connector does not exist".to_string(),
                });
            };
            if connector.tenant_id != entry.tenant_id {
                return Err(QidError::Storage {
                    message: "app catalog marketplace connector belongs to another tenant"
                        .to_string(),
                });
            }
            if let Some(saml_entity_id) = &entry.saml_entity_id {
                if connector.connector_type != MarketplaceConnectorType::Saml {
                    return Err(QidError::Storage {
                        message:
                            "app catalog SAML entry must reference a SAML marketplace connector"
                                .to_string(),
                    });
                }
                if connector.config_json["entity_id"].as_str() != Some(saml_entity_id.as_str()) {
                    return Err(QidError::Storage {
                        message: "app catalog SAML connector entity_id does not match".to_string(),
                    });
                }
            }
        }
        store
            .app_catalog_entries
            .insert(entry.id.clone(), entry.clone());
        drop(store);
        self.save().await
    }

    async fn list_app_catalog_entries(&self, tenant_id: &str) -> QidResult<Vec<AppCatalogEntry>> {
        let store = self.store.read().await;
        let mut entries: Vec<_> = store
            .app_catalog_entries
            .values()
            .filter(|entry| entry.tenant_id == tenant_id)
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    async fn delete_app_catalog_entry(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .app_catalog_entries
            .get(id)
            .is_some_and(|entry| entry.tenant_id == tenant_id)
        {
            store.app_catalog_entries.remove(id);
        }
        drop(store);
        self.save().await
    }

    async fn store_marketplace_connector(&self, connector: &MarketplaceConnector) -> QidResult<()> {
        connector.validate()?;
        let mut store = self.store.write().await;
        store
            .marketplace_connectors
            .insert(connector.id.clone(), connector.clone());
        drop(store);
        self.save().await
    }

    async fn list_marketplace_connectors(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<MarketplaceConnector>> {
        let store = self.store.read().await;
        let mut connectors: Vec<_> = store
            .marketplace_connectors
            .values()
            .filter(|connector| connector.tenant_id == tenant_id)
            .cloned()
            .collect();
        connectors.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(connectors)
    }

    async fn delete_marketplace_connector(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store.app_catalog_entries.values().any(|entry| {
            entry.tenant_id == tenant_id && entry.marketplace_connector_id.as_deref() == Some(id)
        }) {
            return Err(QidError::Storage {
                message: "marketplace connector is referenced by app catalog entries".to_string(),
            });
        }
        if store
            .marketplace_connectors
            .get(id)
            .is_some_and(|connector| connector.tenant_id == tenant_id)
        {
            store.marketplace_connectors.remove(id);
        }
        drop(store);
        self.save().await
    }

    async fn store_usage_billing_event(&self, event: &UsageBillingEvent) -> QidResult<()> {
        event.validate()?;
        let mut store = self.store.write().await;
        if store.usage_billing_events.values().any(|stored| {
            stored.id != event.id
                && stored.tenant_id == event.tenant_id
                && stored.idempotency_key == event.idempotency_key
        }) {
            return Err(QidError::Storage {
                message: "usage billing idempotency key already exists for tenant".to_string(),
            });
        }
        store
            .usage_billing_events
            .insert(event.id.clone(), event.clone());
        drop(store);
        self.save().await
    }

    async fn list_usage_billing_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> QidResult<Vec<UsageBillingEvent>> {
        let store = self.store.read().await;
        let mut events: Vec<_> = store
            .usage_billing_events
            .values()
            .filter(|event| event.tenant_id == tenant_id)
            .cloned()
            .collect();
        events.sort_by(|a, b| {
            b.occurred_at
                .cmp(&a.occurred_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        events.truncate(limit);
        Ok(events)
    }

    async fn store_compliance_evidence_pack(&self, pack: &ComplianceEvidencePack) -> QidResult<()> {
        pack.validate()?;
        let mut store = self.store.write().await;
        store
            .compliance_evidence_packs
            .insert(pack.id.clone(), pack.clone());
        drop(store);
        self.save().await
    }

    async fn list_compliance_evidence_packs(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<ComplianceEvidencePack>> {
        let store = self.store.read().await;
        let mut packs: Vec<_> = store
            .compliance_evidence_packs
            .values()
            .filter(|pack| pack.tenant_id == tenant_id)
            .cloned()
            .collect();
        packs.sort_by(|a, b| {
            b.generated_at
                .cmp(&a.generated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(packs)
    }

    async fn store_delegated_tenant_admin(&self, admin: &DelegatedTenantAdmin) -> QidResult<()> {
        admin.validate()?;
        let store = self.store.read().await;
        for realm_id in &admin.allowed_realm_ids {
            match store.realm_tenants.get(realm_id) {
                Some(tenant_id) if tenant_id == &admin.tenant_id => {}
                Some(_) => {
                    return Err(QidError::BadRequest {
                        message: "delegated tenant admin realm belongs to another tenant"
                            .to_string(),
                    });
                }
                None => {
                    return Err(QidError::BadRequest {
                        message: "delegated tenant admin realm does not exist".to_string(),
                    });
                }
            }
        }
        drop(store);
        let mut store = self.store.write().await;
        store
            .delegated_tenant_admins
            .insert(admin.id.clone(), admin.clone());
        drop(store);
        self.save().await
    }

    async fn list_delegated_tenant_admins(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<DelegatedTenantAdmin>> {
        let store = self.store.read().await;
        let mut admins = store
            .delegated_tenant_admins
            .values()
            .filter(|admin| admin.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        admins.sort_by(|a, b| {
            b.granted_at
                .cmp(&a.granted_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(admins)
    }

    async fn revoke_delegated_tenant_admin(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        let admin = store
            .delegated_tenant_admins
            .get_mut(id)
            .filter(|admin| admin.tenant_id == tenant_id)
            .ok_or_else(|| QidError::NotFound {
                resource: format!("delegated tenant admin {id}"),
            })?;
        admin.revoked = true;
        drop(store);
        self.save().await
    }
}
