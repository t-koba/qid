CREATE TABLE IF NOT EXISTS ciam_consent_grants (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    granted_claims_json TEXT NOT NULL,
    terms_version TEXT,
    granted_at_epoch_seconds INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ciam_consent_realm_user_client
    ON ciam_consent_grants (realm_id, user_id, client_id, granted_at_epoch_seconds DESC);

CREATE TABLE IF NOT EXISTS ciam_verification_challenges (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    address TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at_epoch_seconds INTEGER NOT NULL,
    consumed_at_epoch_seconds INTEGER,
    created_at_epoch_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciam_verification_user_purpose
    ON ciam_verification_challenges (realm_id, user_id, purpose, created_at_epoch_seconds DESC);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    device_id TEXT,
    risk_json TEXT NOT NULL,
    expires_at_epoch_seconds INTEGER NOT NULL,
    consumed_at_epoch_seconds INTEGER,
    created_at_epoch_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_reset_user
    ON password_reset_tokens (realm_id, user_id, created_at_epoch_seconds DESC);
