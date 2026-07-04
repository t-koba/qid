use super::*;

pub async fn check_storage_saas(config: &QidConfig) -> Vec<CheckItem> {
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    match AnyRepository::connect(&storage_url).await {
        Ok(repo) => match check_storage_saas_with_repo(config, &repo).await {
            Ok(checks) => checks,
            Err(message) => vec![check_error("storage.saas", message)],
        },
        Err(err) => vec![check_error(
            "storage.saas",
            format!("storage audit could not connect to repository: {err}"),
        )],
    }
}

pub async fn check_storage_saas_with_repo<R: Repository>(
    config: &QidConfig,
    repo: &R,
) -> Result<Vec<CheckItem>, String> {
    let tenant_ids = repo
        .list_saas_tenant_ids()
        .await
        .map_err(|err| format!("storage audit could not list SaaS tenants: {err}"))?;
    if tenant_ids.is_empty() {
        return Ok(vec![CheckItem {
            name: "storage.saas".to_string(),
            status: CheckStatus::NotApplicable,
            message: "no SaaS tenant data found in storage".to_string(),
        }]);
    }

    let mut checks = Vec::new();
    for tenant_id in tenant_ids {
        let connectors = repo
            .list_marketplace_connectors(&tenant_id)
            .await
            .map_err(|err| {
                format!(
                    "storage audit could not list marketplace connectors for {tenant_id}: {err}"
                )
            })?;
        let connector_by_id = connectors
            .iter()
            .map(|connector| (connector.id.as_str(), connector))
            .collect::<std::collections::BTreeMap<_, _>>();
        let domains = repo.list_custom_domains(&tenant_id).await.map_err(|err| {
            format!("storage audit could not list custom domains for {tenant_id}: {err}")
        })?;
        let entries = repo
            .list_app_catalog_entries(&tenant_id)
            .await
            .map_err(|err| {
                format!("storage audit could not list app catalog entries for {tenant_id}: {err}")
            })?;

        let before = checks.len();
        for domain in &domains {
            checks.extend(check_storage_custom_domain(repo, &tenant_id, domain).await?);
        }
        for entry in &entries {
            checks.extend(
                check_storage_app_catalog_entry(config, repo, &tenant_id, entry, &connector_by_id)
                    .await?,
            );
        }
        if checks.len() == before {
            checks.push(check_ok(
                format!("storage.saas.{tenant_id}"),
                format!(
                    "SaaS storage references are consistent: custom_domains={}, app_catalog_entries={}, marketplace_connectors={}",
                    domains.len(),
                    entries.len(),
                    connectors.len()
                ),
            ));
        }
    }
    Ok(checks)
}

pub(crate) async fn check_storage_custom_domain<R: Repository>(
    repo: &R,
    tenant_id: &str,
    domain: &qid_core::models::CustomDomain,
) -> Result<Vec<CheckItem>, String> {
    let name = format!("storage.saas.{tenant_id}.custom_domain.{}", domain.id);
    let mut checks = Vec::new();
    if let Err(err) = domain.validate() {
        checks.push(check_error(
            name.clone(),
            format!("invalid custom domain: {err}"),
        ));
    }
    checks.extend(check_storage_realm_tenant(repo, &name, tenant_id, &domain.realm_id).await?);
    Ok(checks)
}

pub(crate) async fn check_storage_app_catalog_entry<R: Repository>(
    config: &QidConfig,
    repo: &R,
    tenant_id: &str,
    entry: &AppCatalogEntry,
    connector_by_id: &std::collections::BTreeMap<&str, &MarketplaceConnector>,
) -> Result<Vec<CheckItem>, String> {
    let name = format!("storage.saas.{tenant_id}.app_catalog.{}", entry.id);
    let mut checks = Vec::new();
    if let Err(err) = entry.validate() {
        checks.push(check_error(
            name.clone(),
            format!("invalid app catalog entry: {err}"),
        ));
    }
    checks.extend(check_storage_realm_tenant(repo, &name, tenant_id, &entry.realm_id).await?);
    if let Some(client_id) = &entry.oidc_client_id {
        let client = repo
            .get_client_by_client_id(&RealmId::from(entry.realm_id.clone()), client_id)
            .await
            .map_err(|err| {
                format!("storage audit could not load OIDC client {client_id}: {err}")
            })?;
        if client.is_none() {
            checks.push(check_error(
                name.clone(),
                format!(
                    "OIDC client {client_id} is not present in realm {}",
                    entry.realm_id
                ),
            ));
        }
    }
    if let Some(saml_entity_id) = &entry.saml_entity_id {
        match storage_saml_reference_status(config, &entry.realm_id, saml_entity_id) {
            Ok(()) => {}
            Err(message) => checks.push(check_error(name.clone(), message)),
        }
    }
    if let Some(connector_id) = &entry.marketplace_connector_id {
        match connector_by_id.get(connector_id.as_str()) {
            Some(connector) => {
                if connector.tenant_id != tenant_id {
                    checks.push(check_error(
                        name.clone(),
                        format!("marketplace connector {connector_id} belongs to another tenant"),
                    ));
                }
                if let Some(saml_entity_id) = &entry.saml_entity_id {
                    check_storage_saml_connector(&name, connector, saml_entity_id, &mut checks);
                }
            }
            None => checks.push(check_error(
                name.clone(),
                format!(
                    "marketplace connector {connector_id} is not present in tenant {tenant_id}"
                ),
            )),
        }
    }
    Ok(checks)
}

pub(crate) async fn check_storage_realm_tenant<R: Repository>(
    repo: &R,
    name: &str,
    tenant_id: &str,
    realm_id: &str,
) -> Result<Vec<CheckItem>, String> {
    let tenant = repo
        .get_realm_tenant(&RealmId::from(realm_id.to_string()))
        .await
        .map_err(|err| format!("storage audit could not load realm {realm_id}: {err}"))?;
    Ok(match tenant {
        Some(realm_tenant) if realm_tenant == tenant_id => Vec::new(),
        Some(realm_tenant) => vec![check_error(
            name.to_string(),
            format!("realm {realm_id} belongs to tenant {realm_tenant}, not {tenant_id}"),
        )],
        None => vec![check_error(
            name.to_string(),
            format!("realm {realm_id} is not present in storage"),
        )],
    })
}

pub(crate) fn storage_saml_reference_status(
    config: &QidConfig,
    realm_id: &str,
    saml_entity_id: &str,
) -> Result<(), String> {
    let realm = config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| format!("SAML realm {realm_id} is not present in config"))?;
    if !realm.protocols.saml.enabled {
        return Err(format!("SAML realm {realm_id} is disabled in config"));
    }
    if !realm
        .protocols
        .saml
        .service_providers
        .iter()
        .any(|sp| sp.entity_id == saml_entity_id)
    {
        return Err(format!(
            "SAML entity {saml_entity_id} is not configured for realm {realm_id}"
        ));
    }
    Ok(())
}

pub(crate) fn check_storage_saml_connector(
    name: &str,
    connector: &MarketplaceConnector,
    saml_entity_id: &str,
    checks: &mut Vec<CheckItem>,
) {
    if connector.connector_type != MarketplaceConnectorType::Saml {
        checks.push(check_error(
            name.to_string(),
            format!(
                "SAML app references non-SAML marketplace connector {}",
                connector.id
            ),
        ));
    }
    if connector.config_json["entity_id"].as_str() != Some(saml_entity_id) {
        checks.push(check_error(
            name.to_string(),
            format!(
                "SAML connector {} entity_id does not match {saml_entity_id}",
                connector.id
            ),
        ));
    }
}
