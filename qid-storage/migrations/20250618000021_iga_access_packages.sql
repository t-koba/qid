CREATE TABLE IF NOT EXISTS iga_access_packages (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    owner TEXT NOT NULL,
    entitlement_ids_json TEXT NOT NULL,
    approval_policy_json TEXT NOT NULL,
    max_duration_seconds INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_access_packages_tenant
    ON iga_access_packages (tenant_id, id ASC);
