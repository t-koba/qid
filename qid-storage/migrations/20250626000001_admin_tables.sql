CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    roles_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    UNIQUE(tenant_id, subject)
);

CREATE TABLE IF NOT EXISTS admin_elevations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    admin_id TEXT NOT NULL,
    acr TEXT,
    amr_json TEXT NOT NULL DEFAULT '[]',
    elevation_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins(id)
);

CREATE TABLE IF NOT EXISTS admin_approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    approver_admin_id TEXT NOT NULL,
    target_admin_id TEXT NOT NULL,
    reason TEXT,
    approved_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (approver_admin_id) REFERENCES admins(id),
    FOREIGN KEY (target_admin_id) REFERENCES admins(id)
);
