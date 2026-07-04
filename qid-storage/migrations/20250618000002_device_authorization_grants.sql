CREATE TABLE IF NOT EXISTS device_authorization_grants (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    user_id TEXT,
    expires_at INTEGER NOT NULL,
    approved_at INTEGER,
    consumed INTEGER NOT NULL DEFAULT 0,
    last_poll_at INTEGER,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 5,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorization_grants(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires ON device_authorization_grants(expires_at);
