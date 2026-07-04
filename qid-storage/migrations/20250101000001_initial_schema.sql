-- Initial qid schema for Phase 0 MVP.

CREATE TABLE IF NOT EXISTS realms (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL UNIQUE,
    display_name TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    display_name TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(realm_id, email)
);

CREATE TABLE IF NOT EXISTS credentials_password (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    pepper_ref TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS credentials_webauthn (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    aaguid TEXT NOT NULL DEFAULT '',
    device_name TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    client_type TEXT NOT NULL,
    redirect_uris TEXT NOT NULL, -- JSON array
    grant_types TEXT NOT NULL, -- JSON array
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm_id, client_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time INTEGER NOT NULL,
    acr TEXT,
    amr TEXT, -- JSON array
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_realm ON sessions(realm_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    realm_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_realm_created ON audit_events(realm_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created ON audit_events(actor, created_at);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    scopes TEXT, -- JSON array
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user ON authorization_codes(user_id);

CREATE TABLE IF NOT EXISTS token_families (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    current_refresh_hash TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_token_families_user ON token_families(user_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti TEXT PRIMARY KEY,
    family_id TEXT REFERENCES token_families(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    scopes TEXT, -- JSON array
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    issued_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_family ON access_tokens(family_id);

CREATE TABLE IF NOT EXISTS service_accounts (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials_totp (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    period INTEGER NOT NULL DEFAULT 30,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    device_name TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    posture TEXT DEFAULT '[]',
    registered_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_seen_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_realm ON devices(realm_id);

CREATE TABLE IF NOT EXISTS par_requests (
    request_uri TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    params_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_par_expires ON par_requests(expires_at);

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
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorization_grants(user_code);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires ON device_authorization_grants(expires_at);

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
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciba_grants_expires ON backchannel_authentication_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_ciba_grants_client ON backchannel_authentication_grants(client_id);

CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    external_id TEXT,
    user_name TEXT NOT NULL,
    name_json TEXT NOT NULL DEFAULT '{}',
    emails_json TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(realm_id, user_name)
);

CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    members_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(realm_id, display_name)
);

CREATE TABLE IF NOT EXISTS fedcm_identities (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    given_name TEXT,
    picture_url TEXT,
    approved_clients TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS workload_identities (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    spiffe_id TEXT NOT NULL,
    description TEXT,
    trust_domain TEXT NOT NULL,
    authorities_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS policy_bundles (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    compiled_json TEXT NOT NULL,
    version INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(realm_id, name)
);
