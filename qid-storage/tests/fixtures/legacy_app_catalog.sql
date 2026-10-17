CREATE TABLE realms (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL UNIQUE,
    display_name TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE app_catalog_entries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    category TEXT NOT NULL,
    oidc_client_id TEXT,
    saml_entity_id TEXT,
    scim_enabled INTEGER NOT NULL,
    marketplace_connector_id TEXT
);

INSERT INTO realms (id, tenant_id, issuer) VALUES
    ('realm-single', 'tenant-single', 'https://single.example.com'),
    ('realm-multi-a', 'tenant-multi', 'https://multi-a.example.com'),
    ('realm-multi-b', 'tenant-multi', 'https://multi-b.example.com');
