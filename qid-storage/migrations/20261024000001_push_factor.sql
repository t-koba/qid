-- Push state is immutable except for attempts, decisions, redemption and revocation.
-- JSON payloads contain public keys and SHA-256 verifiers, not private keys/nonces.
-- `issued_at` is trusted server time sampled inside the atomic owner/purpose
-- admission lock, independent of JSON lifecycle creation. It must lie within
-- the pending challenge's [created_at, expires_at) interval. Registration
-- issuance is preserved on activation; expiry mirrors JSON and pending expiry
-- is cleared atomically on activation. Reads fail closed on metadata disagreement.
CREATE TABLE push_authenticators (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    pending_expires_at BIGINT,
    record_json TEXT NOT NULL
);
CREATE INDEX push_authenticators_owner ON push_authenticators(realm_id, user_id);
CREATE INDEX push_authenticators_quota ON push_authenticators(realm_id, user_id, purpose, issued_at);
CREATE TABLE push_login_challenges (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    authenticator_id TEXT NOT NULL REFERENCES push_authenticators(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE INDEX push_login_owner ON push_login_challenges(realm_id, user_id);
CREATE INDEX push_login_quota ON push_login_challenges(realm_id, user_id, purpose, issued_at);
-- NULL pending expiry means enrolled (including revoked), never cleanup eligible.
CREATE INDEX push_authenticators_cleanup ON push_authenticators(pending_expires_at, issued_at, id) WHERE pending_expires_at IS NOT NULL;
CREATE INDEX push_login_cleanup ON push_login_challenges(expires_at, issued_at, id);
