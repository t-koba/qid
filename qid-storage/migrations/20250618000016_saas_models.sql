CREATE TABLE IF NOT EXISTS custom_domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    certificate_ref TEXT NOT NULL,
    verified INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custom_domains_tenant_id
    ON custom_domains (tenant_id);

CREATE TABLE IF NOT EXISTS app_catalog_entries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    category TEXT NOT NULL,
    oidc_client_id TEXT,
    saml_entity_id TEXT,
    scim_enabled INTEGER NOT NULL,
    marketplace_connector_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_catalog_entries_tenant_id
    ON app_catalog_entries (tenant_id);

CREATE TABLE IF NOT EXISTS marketplace_connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_marketplace_connectors_tenant_id
    ON marketplace_connectors (tenant_id);

CREATE TABLE IF NOT EXISTS usage_billing_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    meter TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    occurred_at INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    dimensions_json TEXT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_usage_billing_events_tenant_id_occurred_at
    ON usage_billing_events (tenant_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS compliance_evidence_packs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    period_start INTEGER NOT NULL,
    period_end INTEGER NOT NULL,
    controls_json TEXT NOT NULL,
    object_uri TEXT NOT NULL,
    sha256_hex TEXT NOT NULL,
    generated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_packs_tenant_id_generated_at
    ON compliance_evidence_packs (tenant_id, generated_at DESC);
