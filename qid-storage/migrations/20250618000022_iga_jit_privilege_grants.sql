CREATE TABLE IF NOT EXISTS iga_jit_privilege_grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    entitlement TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    reason TEXT NOT NULL,
    issued_at_epoch_seconds INTEGER NOT NULL,
    expires_at_epoch_seconds INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    constraints_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iga_jit_privilege_grants_tenant_subject
    ON iga_jit_privilege_grants (tenant_id, subject, issued_at_epoch_seconds DESC);
