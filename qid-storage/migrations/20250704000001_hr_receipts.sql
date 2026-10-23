CREATE TABLE hr_receipts (
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    digest TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    PRIMARY KEY (realm_id, provider_id)
);
