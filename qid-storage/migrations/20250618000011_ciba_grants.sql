CREATE TABLE IF NOT EXISTS backchannel_authentication_grants (
    auth_req_id_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    login_hint TEXT NOT NULL,
    binding_message TEXT,
    scopes TEXT NOT NULL DEFAULT '[]',
    user_id TEXT,
    expires_at INTEGER NOT NULL,
    approved_at INTEGER,
    consumed INTEGER NOT NULL DEFAULT 0,
    last_poll_at INTEGER,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 5,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciba_grants_expires ON backchannel_authentication_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_ciba_grants_client ON backchannel_authentication_grants(client_id);
