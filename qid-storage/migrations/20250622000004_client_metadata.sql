ALTER TABLE clients ADD COLUMN client_name TEXT;
ALTER TABLE clients ADD COLUMN client_uri TEXT;
ALTER TABLE clients ADD COLUMN logo_uri TEXT;
ALTER TABLE clients ADD COLUMN contacts TEXT;
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT;
ALTER TABLE clients ADD COLUMN default_max_age INTEGER;
ALTER TABLE clients ADD COLUMN require_auth_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE clients ADD COLUMN subject_type TEXT;
