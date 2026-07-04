CREATE TABLE IF NOT EXISTS audit_retention_configs (
    stream_id TEXT PRIMARY KEY,
    realm_id TEXT,
    retention_days INTEGER NOT NULL,
    legal_hold INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_retention_configs_realm ON audit_retention_configs(realm_id);
