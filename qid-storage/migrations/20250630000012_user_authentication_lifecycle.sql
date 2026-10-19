-- User-owned codes and approved grants must not outlive their user.
-- Rebuild portably, discarding legacy orphaned owners but retaining NULL
-- owners on pending grants. Access-token subjects intentionally keep no user FK.

CREATE TABLE authorization_codes_with_user (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    scopes TEXT, -- JSON array
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    authorization_details TEXT,
    state TEXT,
    nonce TEXT,
    auth_time INTEGER,
    acr TEXT,
    amr TEXT,
    resource TEXT,
    session_id TEXT
);

INSERT INTO authorization_codes_with_user (code_hash, client_id, user_id, realm_id, redirect_uri, code_challenge, code_challenge_method, scopes, expires_at, used, created_at, state, nonce, auth_time, acr, amr, resource, authorization_details, session_id)
SELECT code_hash, client_id, user_id, realm_id, redirect_uri, code_challenge, code_challenge_method, scopes, expires_at, used, created_at, state, nonce, auth_time, acr, amr, resource, authorization_details, session_id
FROM authorization_codes
WHERE EXISTS (SELECT 1 FROM users WHERE users.id = authorization_codes.user_id);

DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_with_user RENAME TO authorization_codes;

CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user ON authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_realm_expires ON authorization_codes(realm_id, expires_at);

CREATE TABLE device_authorization_grants_with_user (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    approved_at INTEGER,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_poll_at INTEGER,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 5
);

INSERT INTO device_authorization_grants_with_user (device_code_hash, user_code, client_id, realm_id, scopes, user_id, expires_at, approved_at, consumed, created_at, last_poll_at, poll_interval_seconds)
SELECT device_code_hash, user_code, client_id, realm_id, scopes, user_id, expires_at, approved_at, consumed, created_at, last_poll_at, poll_interval_seconds
FROM device_authorization_grants
WHERE user_id IS NULL OR EXISTS (SELECT 1 FROM users WHERE users.id = device_authorization_grants.user_id);

DROP TABLE device_authorization_grants;
ALTER TABLE device_authorization_grants_with_user RENAME TO device_authorization_grants;

CREATE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorization_grants(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires ON device_authorization_grants(expires_at);

CREATE TABLE backchannel_authentication_grants_with_user (
    auth_req_id_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    login_hint TEXT NOT NULL,
    binding_message TEXT,
    scopes TEXT NOT NULL DEFAULT '[]',
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    approved_at INTEGER,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_poll_at INTEGER,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 5
);

INSERT INTO backchannel_authentication_grants_with_user (auth_req_id_hash, client_id, realm_id, login_hint, binding_message, scopes, user_id, expires_at, approved_at, consumed, created_at, last_poll_at, poll_interval_seconds)
SELECT auth_req_id_hash, client_id, realm_id, login_hint, binding_message, scopes, user_id, expires_at, approved_at, consumed, created_at, last_poll_at, poll_interval_seconds
FROM backchannel_authentication_grants
WHERE user_id IS NULL OR EXISTS (SELECT 1 FROM users WHERE users.id = backchannel_authentication_grants.user_id);

DROP TABLE backchannel_authentication_grants;
ALTER TABLE backchannel_authentication_grants_with_user RENAME TO backchannel_authentication_grants;

CREATE INDEX IF NOT EXISTS idx_ciba_grants_expires ON backchannel_authentication_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_ciba_grants_client ON backchannel_authentication_grants(client_id);
