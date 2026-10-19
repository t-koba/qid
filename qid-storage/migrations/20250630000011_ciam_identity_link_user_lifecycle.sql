-- Rebuild portably for SQLite and PostgreSQL, dropping legacy orphaned bindings.
CREATE TABLE ciam_identity_links_with_user (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    external_email TEXT,
    profile_json TEXT NOT NULL,
    linked_at_epoch_seconds INTEGER NOT NULL,
    verified INTEGER NOT NULL
);

INSERT INTO ciam_identity_links_with_user (
    id, realm_id, user_id, provider, external_subject, external_email,
    profile_json, linked_at_epoch_seconds, verified
)
SELECT id, realm_id, user_id, provider, external_subject, external_email,
       profile_json, linked_at_epoch_seconds, verified
FROM ciam_identity_links
WHERE EXISTS (SELECT 1 FROM users WHERE users.id = ciam_identity_links.user_id);

DROP TABLE ciam_identity_links;
ALTER TABLE ciam_identity_links_with_user RENAME TO ciam_identity_links;

CREATE UNIQUE INDEX idx_ciam_identity_links_external_subject
    ON ciam_identity_links (realm_id, provider, external_subject)
    WHERE verified = 1;

CREATE INDEX idx_ciam_identity_links_user
    ON ciam_identity_links (realm_id, user_id, linked_at_epoch_seconds DESC);
