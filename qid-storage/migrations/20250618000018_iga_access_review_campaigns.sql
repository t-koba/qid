CREATE TABLE IF NOT EXISTS iga_access_review_campaigns (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    subjects_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_epoch_seconds INTEGER NOT NULL,
    due_at_epoch_seconds INTEGER
);

CREATE INDEX IF NOT EXISTS idx_iga_access_review_campaigns_tenant
    ON iga_access_review_campaigns (tenant_id, created_at_epoch_seconds DESC, id ASC);
