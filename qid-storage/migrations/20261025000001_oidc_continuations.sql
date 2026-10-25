-- Protocol continuation only: never authentication or code-issuance authority.
-- Keep consumed rows as ID tombstones; an ID cannot be recreated after consume.
CREATE TABLE IF NOT EXISTS oidc_authorization_continuations (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    context_json TEXT NOT NULL,
    browser_binding_sha256 TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    CHECK (created_at >= 0 AND expires_at > created_at),
    CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at))
);

CREATE INDEX IF NOT EXISTS oidc_authorization_continuations_expiry
    ON oidc_authorization_continuations (expires_at, id);
