ALTER TABLE custom_domains ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE custom_domains ADD COLUMN dns_challenge_name TEXT;
ALTER TABLE custom_domains ADD COLUMN dns_challenge_value TEXT;
ALTER TABLE custom_domains ADD COLUMN certificate_expires_at INTEGER;
ALTER TABLE custom_domains ADD COLUMN certificate_renew_after INTEGER;
ALTER TABLE custom_domains ADD COLUMN last_verified_at INTEGER;

UPDATE custom_domains
SET verification_status = CASE WHEN verified = 1 THEN 'active' ELSE 'pending' END
WHERE verification_status = 'active' OR verification_status = 'pending';
