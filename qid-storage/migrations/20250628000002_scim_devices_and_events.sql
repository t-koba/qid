CREATE TABLE IF NOT EXISTS scim_devices (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    display_name TEXT,
    manufacturer TEXT,
    model TEXT,
    os TEXT,
    os_version TEXT,
    last_seen INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scim_devices_realm
    ON scim_devices (realm_id);

CREATE TABLE IF NOT EXISTS scim_event_subscriptions (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    callback_url TEXT NOT NULL,
    event_types_json TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scim_event_subscriptions_realm
    ON scim_event_subscriptions (realm_id);
