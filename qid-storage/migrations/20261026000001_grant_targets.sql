-- Legacy grants have no selected target. Configured target policy will reject
-- these at issuance; unconfigured deployments retain their client fallback.
ALTER TABLE device_authorization_grants ADD COLUMN resource TEXT NOT NULL DEFAULT '[]';
ALTER TABLE device_authorization_grants ADD COLUMN audience TEXT NOT NULL DEFAULT '[]';
ALTER TABLE backchannel_authentication_grants ADD COLUMN resource TEXT NOT NULL DEFAULT '[]';
ALTER TABLE backchannel_authentication_grants ADD COLUMN audience TEXT NOT NULL DEFAULT '[]';
