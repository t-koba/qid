CREATE TABLE IF NOT EXISTS delegated_tenant_admins (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    allowed_realm_ids_json TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delegated_tenant_admins_tenant_subject
    ON delegated_tenant_admins (tenant_id, subject);

CREATE INDEX IF NOT EXISTS idx_delegated_tenant_admins_tenant_revoked
    ON delegated_tenant_admins (tenant_id, revoked);
