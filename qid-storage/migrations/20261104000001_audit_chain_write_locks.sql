CREATE TABLE IF NOT EXISTS audit_chain_locks (
    stream_id TEXT PRIMARY KEY,
    lock_version INTEGER NOT NULL DEFAULT 0
);
