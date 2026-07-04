use async_trait::async_trait;

use super::*;

#[async_trait]
impl SaasRepository for SqlRepository {
    async fn list_saas_tenant_ids(&self) -> QidResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT tenant_id FROM custom_domains
             UNION
             SELECT tenant_id FROM ciam_brands
             UNION
             SELECT tenant_id FROM app_catalog_entries
             UNION
             SELECT tenant_id FROM marketplace_connectors
             UNION
             SELECT tenant_id FROM usage_billing_events
             UNION
             SELECT tenant_id FROM compliance_evidence_packs
             UNION
             SELECT tenant_id FROM delegated_tenant_admins
             ORDER BY tenant_id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(|row| row.0).collect())
    }

    async fn store_custom_domain(&self, domain: &CustomDomain) -> QidResult<()> {
        domain.validate()?;
        let realm_tenant: Option<(String,)> =
            sqlx::query_as("SELECT tenant_id FROM realms WHERE id = ?")
                .bind(&domain.realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let Some((realm_tenant,)) = realm_tenant else {
            return Err(QidError::Storage {
                message: "custom domain realm does not exist".to_string(),
            });
        };
        if realm_tenant != domain.tenant_id {
            return Err(QidError::Storage {
                message: "custom domain realm belongs to another tenant".to_string(),
            });
        }
        sqlx::query(
            "INSERT INTO custom_domains (id, tenant_id, realm_id, hostname, certificate_ref, verified, verification_status, dns_challenge_name, dns_challenge_value, certificate_expires_at, certificate_renew_after, last_verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET hostname = excluded.hostname, certificate_ref = excluded.certificate_ref, verified = excluded.verified, verification_status = excluded.verification_status, dns_challenge_name = excluded.dns_challenge_name, dns_challenge_value = excluded.dns_challenge_value, certificate_expires_at = excluded.certificate_expires_at, certificate_renew_after = excluded.certificate_renew_after, last_verified_at = excluded.last_verified_at",
        )
        .bind(&domain.id)
        .bind(&domain.tenant_id)
        .bind(&domain.realm_id)
        .bind(&domain.hostname)
        .bind(&domain.certificate_ref)
        .bind(domain.verified as i64)
        .bind(&domain.verification_status)
        .bind(&domain.dns_challenge_name)
        .bind(&domain.dns_challenge_value)
        .bind(domain.certificate_expires_at.map(|value| value as i64))
        .bind(domain.certificate_renew_after.map(|value| value as i64))
        .bind(domain.last_verified_at.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_custom_domains(&self, tenant_id: &str) -> QidResult<Vec<CustomDomain>> {
        let rows: Vec<CustomDomainRow> =
            sqlx::query_as("SELECT * FROM custom_domains WHERE tenant_id = ? ORDER BY id ASC")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_custom_domain(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM custom_domains WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_ciam_brand(&self, brand: &CiamBrand) -> QidResult<()> {
        brand.validate()?;
        let realm_tenant: Option<(String,)> =
            sqlx::query_as("SELECT tenant_id FROM realms WHERE id = ?")
                .bind(&brand.realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let Some((realm_tenant,)) = realm_tenant else {
            return Err(QidError::Storage {
                message: "CIAM brand realm does not exist".to_string(),
            });
        };
        if realm_tenant != brand.tenant_id {
            return Err(QidError::Storage {
                message: "CIAM brand realm belongs to another tenant".to_string(),
            });
        }
        sqlx::query(
            "INSERT INTO ciam_brands (id, tenant_id, realm_id, display_name, primary_color, logo_uri, privacy_policy_uri, support_uri, terms_version, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, primary_color = excluded.primary_color, logo_uri = excluded.logo_uri, privacy_policy_uri = excluded.privacy_policy_uri, support_uri = excluded.support_uri, terms_version = excluded.terms_version, active = excluded.active",
        )
        .bind(&brand.id)
        .bind(&brand.tenant_id)
        .bind(&brand.realm_id)
        .bind(&brand.display_name)
        .bind(&brand.primary_color)
        .bind(&brand.logo_uri)
        .bind(&brand.privacy_policy_uri)
        .bind(&brand.support_uri)
        .bind(&brand.terms_version)
        .bind(brand.active as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_ciam_brands(&self, tenant_id: &str) -> QidResult<Vec<CiamBrand>> {
        let rows: Vec<CiamBrandRow> =
            sqlx::query_as("SELECT * FROM ciam_brands WHERE tenant_id = ? ORDER BY id ASC")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_ciam_brand(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM ciam_brands WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_app_catalog_entry(&self, entry: &AppCatalogEntry) -> QidResult<()> {
        entry.validate()?;
        let realm_tenant: Option<(String,)> =
            sqlx::query_as("SELECT tenant_id FROM realms WHERE id = ?")
                .bind(&entry.realm_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let Some((realm_tenant,)) = realm_tenant else {
            return Err(QidError::Storage {
                message: "app catalog realm does not exist".to_string(),
            });
        };
        if realm_tenant != entry.tenant_id {
            return Err(QidError::Storage {
                message: "app catalog realm belongs to another tenant".to_string(),
            });
        }
        if let Some(oidc_client_id) = &entry.oidc_client_id {
            let client_exists: Option<(String,)> =
                sqlx::query_as("SELECT id FROM clients WHERE realm_id = ? AND client_id = ?")
                    .bind(&entry.realm_id)
                    .bind(oidc_client_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage_to_qid_error)?;
            if client_exists.is_none() {
                return Err(QidError::Storage {
                    message: "app catalog OIDC client does not exist in realm".to_string(),
                });
            }
        }
        if let Some(connector_id) = &entry.marketplace_connector_id {
            let connector_row: Option<(String, String, String)> =
                sqlx::query_as("SELECT tenant_id, connector_type, config_json FROM marketplace_connectors WHERE id = ?")
                    .bind(connector_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage_to_qid_error)?;
            let Some((connector_tenant, connector_type, connector_config_json)) = connector_row
            else {
                return Err(QidError::Storage {
                    message: "app catalog marketplace connector does not exist".to_string(),
                });
            };
            if connector_tenant != entry.tenant_id {
                return Err(QidError::Storage {
                    message: "app catalog marketplace connector belongs to another tenant"
                        .to_string(),
                });
            }
            if let Some(saml_entity_id) = &entry.saml_entity_id {
                if connector_type != "saml" {
                    return Err(QidError::Storage {
                        message:
                            "app catalog SAML entry must reference a SAML marketplace connector"
                                .to_string(),
                    });
                }
                let connector_config: serde_json::Value =
                    serde_json::from_str(&connector_config_json).map_err(|e| {
                        QidError::Storage {
                            message: format!(
                                "app catalog marketplace connector config is invalid JSON: {e}"
                            ),
                        }
                    })?;
                if connector_config["entity_id"].as_str() != Some(saml_entity_id.as_str()) {
                    return Err(QidError::Storage {
                        message: "app catalog SAML connector entity_id does not match".to_string(),
                    });
                }
            }
        }
        sqlx::query(
            "INSERT INTO app_catalog_entries (id, tenant_id, realm_id, display_name, category, oidc_client_id, saml_entity_id, scim_enabled, marketplace_connector_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.id)
        .bind(&entry.tenant_id)
        .bind(&entry.realm_id)
        .bind(&entry.display_name)
        .bind(&entry.category)
        .bind(&entry.oidc_client_id)
        .bind(&entry.saml_entity_id)
        .bind(entry.scim_enabled as i64)
        .bind(&entry.marketplace_connector_id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_app_catalog_entries(&self, tenant_id: &str) -> QidResult<Vec<AppCatalogEntry>> {
        let rows: Vec<AppCatalogEntryRow> =
            sqlx::query_as("SELECT * FROM app_catalog_entries WHERE tenant_id = ? ORDER BY id ASC")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_app_catalog_entry(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM app_catalog_entries WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_marketplace_connector(&self, connector: &MarketplaceConnector) -> QidResult<()> {
        connector.validate()?;
        sqlx::query(
            "INSERT INTO marketplace_connectors (id, tenant_id, provider, connector_type, config_json, enabled) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&connector.id)
        .bind(&connector.tenant_id)
        .bind(&connector.provider)
        .bind(marketplace_connector_type_as_str(&connector.connector_type))
        .bind(connector.config_json.to_string())
        .bind(connector.enabled as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_marketplace_connectors(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<MarketplaceConnector>> {
        let rows: Vec<MarketplaceConnectorRow> = sqlx::query_as(
            "SELECT * FROM marketplace_connectors WHERE tenant_id = ? ORDER BY id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_marketplace_connector(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let referenced: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM app_catalog_entries WHERE tenant_id = ? AND marketplace_connector_id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if referenced.0 > 0 {
            return Err(QidError::Storage {
                message: "marketplace connector is referenced by app catalog entries".to_string(),
            });
        }
        sqlx::query("DELETE FROM marketplace_connectors WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_usage_billing_event(&self, event: &UsageBillingEvent) -> QidResult<()> {
        event.validate()?;
        sqlx::query(
            "INSERT INTO usage_billing_events (id, tenant_id, meter, quantity, occurred_at, idempotency_key, dimensions_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(&event.meter)
        .bind(event.quantity as i64)
        .bind(event.occurred_at as i64)
        .bind(&event.idempotency_key)
        .bind(serde_json::to_string(&event.dimensions).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_usage_billing_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> QidResult<Vec<UsageBillingEvent>> {
        let rows: Vec<UsageBillingEventRow> = sqlx::query_as(
            "SELECT * FROM usage_billing_events WHERE tenant_id = ? ORDER BY occurred_at DESC, id ASC LIMIT ?",
        )
        .bind(tenant_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_compliance_evidence_pack(&self, pack: &ComplianceEvidencePack) -> QidResult<()> {
        pack.validate()?;
        sqlx::query(
            "INSERT INTO compliance_evidence_packs (id, tenant_id, period_start, period_end, controls_json, object_uri, sha256_hex, generated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&pack.id)
        .bind(&pack.tenant_id)
        .bind(pack.period_start as i64)
        .bind(pack.period_end as i64)
        .bind(serde_json::to_string(&pack.controls).unwrap_or_default())
        .bind(&pack.object_uri)
        .bind(&pack.sha256_hex)
        .bind(pack.generated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_compliance_evidence_packs(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<ComplianceEvidencePack>> {
        let rows: Vec<ComplianceEvidencePackRow> = sqlx::query_as(
            "SELECT * FROM compliance_evidence_packs WHERE tenant_id = ? ORDER BY generated_at DESC, id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn store_delegated_tenant_admin(&self, admin: &DelegatedTenantAdmin) -> QidResult<()> {
        admin.validate()?;
        for realm_id in &admin.allowed_realm_ids {
            let realm_tenant: Option<String> =
                sqlx::query_scalar("SELECT tenant_id FROM realms WHERE id = ?")
                    .bind(realm_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage_to_qid_error)?;
            match realm_tenant {
                Some(tenant_id) if tenant_id == admin.tenant_id => {}
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
        sqlx::query(
            "INSERT INTO delegated_tenant_admins (id, tenant_id, subject, roles_json, allowed_realm_ids_json, granted_by, granted_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET subject = excluded.subject, roles_json = excluded.roles_json, allowed_realm_ids_json = excluded.allowed_realm_ids_json, granted_by = excluded.granted_by, granted_at = excluded.granted_at, expires_at = excluded.expires_at, revoked = excluded.revoked",
        )
        .bind(&admin.id)
        .bind(&admin.tenant_id)
        .bind(&admin.subject)
        .bind(serde_json::to_string(&admin.roles).unwrap_or_default())
        .bind(serde_json::to_string(&admin.allowed_realm_ids).unwrap_or_default())
        .bind(&admin.granted_by)
        .bind(admin.granted_at as i64)
        .bind(admin.expires_at.map(|value| value as i64))
        .bind(admin.revoked as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_delegated_tenant_admins(
        &self,
        tenant_id: &str,
    ) -> QidResult<Vec<DelegatedTenantAdmin>> {
        let rows: Vec<DelegatedTenantAdminRow> = sqlx::query_as(
            "SELECT * FROM delegated_tenant_admins WHERE tenant_id = ? ORDER BY granted_at DESC, id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_delegated_tenant_admin(&self, tenant_id: &str, id: &str) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE delegated_tenant_admins SET revoked = 1 WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: format!("delegated tenant admin {id}"),
            });
        }
        Ok(())
    }
}
