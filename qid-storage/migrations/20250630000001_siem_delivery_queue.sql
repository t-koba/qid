CREATE TABLE IF NOT EXISTS siem_delivery_queue (
    id TEXT PRIMARY KEY,
    realm_id TEXT,
    endpoint_url TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER,
    status TEXT NOT NULL,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_siem_delivery_queue_status_retry
    ON siem_delivery_queue (status, next_retry_at, created_at);

CREATE INDEX IF NOT EXISTS idx_siem_delivery_queue_realm_status_retry
    ON siem_delivery_queue (realm_id, status, next_retry_at, created_at);
