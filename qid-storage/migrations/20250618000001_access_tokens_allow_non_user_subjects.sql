-- Allow access tokens to represent service accounts as well as users.

PRAGMA foreign_keys = off;

ALTER TABLE access_tokens RENAME TO access_tokens_old;

CREATE TABLE access_tokens (
    jti TEXT PRIMARY KEY,
    family_id TEXT REFERENCES token_families(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    scopes TEXT,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    issued_at INTEGER NOT NULL
);

INSERT INTO access_tokens (
    jti,
    family_id,
    user_id,
    client_id,
    realm_id,
    scopes,
    expires_at,
    revoked,
    issued_at
)
SELECT
    jti,
    family_id,
    user_id,
    client_id,
    realm_id,
    scopes,
    expires_at,
    revoked,
    issued_at
FROM access_tokens_old;

DROP TABLE access_tokens_old;

CREATE INDEX IF NOT EXISTS idx_access_tokens_family ON access_tokens(family_id);

PRAGMA foreign_keys = on;
