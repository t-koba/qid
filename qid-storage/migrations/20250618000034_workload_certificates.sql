CREATE TABLE IF NOT EXISTS workload_certificates (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    spiffe_id TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    x5t_s256 TEXT NOT NULL,
    csr_sha256 TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    issuer_key_ref TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_workload_certificates_x5t
    ON workload_certificates (realm_id, x5t_s256);

CREATE INDEX IF NOT EXISTS idx_workload_certificates_workload
    ON workload_certificates (realm_id, workload_id, not_after DESC);
