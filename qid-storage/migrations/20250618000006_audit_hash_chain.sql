ALTER TABLE audit_events ADD COLUMN previous_hash TEXT;
ALTER TABLE audit_events ADD COLUMN event_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_events_realm_hash ON audit_events(realm_id, event_hash);
