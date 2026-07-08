CREATE INDEX IF NOT EXISTS idx_users_realm_created
    ON users (realm_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_clients_realm_created
    ON clients (realm_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sessions_realm_user_created
    ON sessions (realm_id, user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_token_families_realm_user_client_issued
    ON token_families (realm_id, user_id, client_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_token_families_realm_client_issued
    ON token_families (realm_id, client_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_access_tokens_realm_client_expires
    ON access_tokens (realm_id, client_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_revoked
    ON access_tokens (expires_at, revoked);

CREATE INDEX IF NOT EXISTS idx_auth_codes_realm_expires
    ON authorization_codes (realm_id, expires_at);
