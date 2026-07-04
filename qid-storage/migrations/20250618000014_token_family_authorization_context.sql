ALTER TABLE token_families ADD COLUMN audience TEXT DEFAULT '[]';
ALTER TABLE token_families ADD COLUMN resource TEXT DEFAULT '[]';
ALTER TABLE token_families ADD COLUMN authorization_details TEXT;
