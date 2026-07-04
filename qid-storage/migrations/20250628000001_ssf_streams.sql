CREATE TABLE IF NOT EXISTS ssf_streams (
    realm_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    delivery_json TEXT NOT NULL,
    events_requested_json TEXT NOT NULL,
    transmitter_issuer TEXT NOT NULL,
    transmitter_jwks_json TEXT NOT NULL,
    transmitter_alg TEXT NOT NULL,
    audience TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (realm_id, stream_id)
);

CREATE TABLE IF NOT EXISTS ssf_set_replay (
    realm_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (realm_id, issuer, stream_id, jti)
);

CREATE INDEX IF NOT EXISTS idx_ssf_set_replay_expires_at
    ON ssf_set_replay (expires_at);
