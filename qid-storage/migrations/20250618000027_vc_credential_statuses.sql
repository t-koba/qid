CREATE TABLE IF NOT EXISTS vc_credential_statuses (
    credential_id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    status_list_uri TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revocation_reason TEXT,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_vc_credential_statuses_realm_subject
    ON vc_credential_statuses (realm_id, subject);
