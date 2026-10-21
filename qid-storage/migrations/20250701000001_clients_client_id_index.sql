-- The authorization path resolves a client id across the configured realms.
-- The index keeps that resolution one cheap read.
CREATE INDEX IF NOT EXISTS idx_clients_client_id
    ON clients (client_id, realm_id);
