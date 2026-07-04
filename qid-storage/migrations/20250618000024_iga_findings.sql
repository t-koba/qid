CREATE TABLE IF NOT EXISTS iga_findings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    detected_at_epoch_seconds INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_iga_findings_tenant_type
    ON iga_findings (tenant_id, finding_type, detected_at_epoch_seconds DESC);
