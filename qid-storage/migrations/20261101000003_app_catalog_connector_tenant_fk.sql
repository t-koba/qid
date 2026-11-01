-- Refuse and roll back if an existing catalog reference is missing or owned by
-- another tenant. See docs/storage-ownership.md for the inspection/repair query.
CREATE UNIQUE INDEX idx_marketplace_connectors_tenant_id_id
    ON marketplace_connectors (tenant_id, id);

CREATE TEMP TABLE app_catalog_connector_migration_guard (
    valid INTEGER CONSTRAINT app_catalog_connector_tenant_preflight CHECK (valid = 1)
);

INSERT INTO app_catalog_connector_migration_guard (valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM app_catalog_entries AS e
    LEFT JOIN marketplace_connectors AS c ON c.id = e.marketplace_connector_id
    WHERE e.marketplace_connector_id IS NOT NULL
      AND (c.id IS NULL OR c.tenant_id <> e.tenant_id)
);

DROP TABLE app_catalog_connector_migration_guard;

CREATE TABLE app_catalog_entries_new (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    category TEXT NOT NULL,
    oidc_client_id TEXT,
    saml_entity_id TEXT,
    scim_enabled INTEGER NOT NULL,
    marketplace_connector_id TEXT,
    realm_id TEXT NOT NULL DEFAULT '',
    CONSTRAINT app_catalog_entries_connector_tenant_fk
        FOREIGN KEY (tenant_id, marketplace_connector_id)
        REFERENCES marketplace_connectors (tenant_id, id) ON DELETE RESTRICT
);

INSERT INTO app_catalog_entries_new
    (id, tenant_id, display_name, category, oidc_client_id, saml_entity_id,
     scim_enabled, marketplace_connector_id, realm_id)
SELECT id, tenant_id, display_name, category, oidc_client_id, saml_entity_id,
       scim_enabled, marketplace_connector_id, realm_id
FROM app_catalog_entries;

DROP TABLE app_catalog_entries;
ALTER TABLE app_catalog_entries_new RENAME TO app_catalog_entries;

CREATE INDEX IF NOT EXISTS idx_app_catalog_entries_tenant_id
    ON app_catalog_entries (tenant_id);
CREATE INDEX IF NOT EXISTS idx_app_catalog_entries_realm_id
    ON app_catalog_entries (realm_id);
