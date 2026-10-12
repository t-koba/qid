ALTER TABLE token_families ADD COLUMN auth_time INTEGER;
ALTER TABLE token_families ADD COLUMN acr TEXT;
ALTER TABLE token_families ADD COLUMN amr TEXT DEFAULT '[]';
