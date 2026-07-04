CREATE TABLE IF NOT EXISTS iga_entitlements (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    owner TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    conflicting_entitlements_json TEXT NOT NULL,
    max_duration_seconds INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iga_entitlements_tenant
    ON iga_entitlements (tenant_id, id ASC);
