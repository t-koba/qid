ALTER TABLE authorization_codes ADD COLUMN state TEXT;
ALTER TABLE authorization_codes ADD COLUMN nonce TEXT;
ALTER TABLE authorization_codes ADD COLUMN auth_time INTEGER;
ALTER TABLE authorization_codes ADD COLUMN acr TEXT;
ALTER TABLE authorization_codes ADD COLUMN amr TEXT;
ALTER TABLE authorization_codes ADD COLUMN resource TEXT;
