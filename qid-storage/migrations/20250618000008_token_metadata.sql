ALTER TABLE token_families ADD COLUMN sender_constraint TEXT;

ALTER TABLE access_tokens ADD COLUMN audience TEXT;
ALTER TABLE access_tokens ADD COLUMN resource TEXT;
ALTER TABLE access_tokens ADD COLUMN auth_time INTEGER;
ALTER TABLE access_tokens ADD COLUMN acr TEXT;
ALTER TABLE access_tokens ADD COLUMN amr TEXT;
ALTER TABLE access_tokens ADD COLUMN nonce TEXT;
ALTER TABLE access_tokens ADD COLUMN sender_constraint TEXT;
ALTER TABLE access_tokens ADD COLUMN token_format TEXT DEFAULT 'jwt';
