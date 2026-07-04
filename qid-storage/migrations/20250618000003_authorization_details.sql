ALTER TABLE authorization_codes ADD COLUMN authorization_details TEXT;
ALTER TABLE access_tokens ADD COLUMN authorization_details TEXT;
