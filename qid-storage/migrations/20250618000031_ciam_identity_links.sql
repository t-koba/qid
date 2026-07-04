CREATE TABLE IF NOT EXISTS ciam_identity_links (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    external_email TEXT,
    profile_json TEXT NOT NULL,
    linked_at_epoch_seconds INTEGER NOT NULL,
    verified INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ciam_identity_links_external_subject
    ON ciam_identity_links (realm_id, provider, external_subject);

CREATE INDEX IF NOT EXISTS idx_ciam_identity_links_user
    ON ciam_identity_links (realm_id, user_id, linked_at_epoch_seconds DESC);
