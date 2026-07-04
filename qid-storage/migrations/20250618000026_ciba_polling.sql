ALTER TABLE backchannel_authentication_grants ADD COLUMN last_poll_at INTEGER;
ALTER TABLE backchannel_authentication_grants ADD COLUMN poll_interval_seconds INTEGER NOT NULL DEFAULT 5;
