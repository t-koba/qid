CREATE TABLE IF NOT EXISTS iga_access_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    entitlement TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL,
    approval_steps_json TEXT NOT NULL,
    violations_json TEXT NOT NULL,
    expires_at_epoch_seconds INTEGER,
    created_at_epoch_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iga_access_requests_tenant
    ON iga_access_requests (tenant_id, created_at_epoch_seconds DESC, id ASC);

CREATE TABLE IF NOT EXISTS iga_approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    decision TEXT NOT NULL,
    approved_at_epoch_seconds INTEGER NOT NULL,
    expires_at_epoch_seconds INTEGER,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_iga_approvals_request
    ON iga_approvals (tenant_id, request_id, approved_at_epoch_seconds ASC, id ASC);

CREATE TABLE IF NOT EXISTS iga_access_grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    entitlement TEXT NOT NULL,
    granted_at_epoch_seconds INTEGER NOT NULL,
    expires_at_epoch_seconds INTEGER,
    approval_ids_json TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_iga_access_grants_tenant_subject
    ON iga_access_grants (tenant_id, subject, granted_at_epoch_seconds DESC, id ASC);
