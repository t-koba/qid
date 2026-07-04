CREATE TABLE IF NOT EXISTS iga_access_review_decisions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    decided_at_epoch_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iga_access_review_decisions_campaign
    ON iga_access_review_decisions (tenant_id, campaign_id, decided_at_epoch_seconds ASC, id ASC);
