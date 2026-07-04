CREATE TABLE IF NOT EXISTS iga_certifications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    certification_type TEXT NOT NULL,
    campaign_id TEXT,
    subject TEXT NOT NULL,
    entitlement TEXT NOT NULL,
    certifier TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    evidence_json TEXT NOT NULL,
    decided_at_epoch_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iga_certifications_tenant_type
    ON iga_certifications (tenant_id, certification_type, decided_at_epoch_seconds DESC);
