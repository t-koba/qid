-- Derive identity from the stored realm, not the old ambiguous sentinel key.
-- Stage first: a new key may equal another row's old key. The migrator's
-- transaction preserves all rows if duplicate stream identities are found.
CREATE TEMPORARY TABLE audit_retention_rekey AS
SELECT CASE WHEN realm_id IS NULL THEN 'global' ELSE 'realm:' || realm_id END AS stream_id,
       realm_id, retention_days, legal_hold, updated_by, reason, updated_at
FROM audit_retention_configs;

DELETE FROM audit_retention_configs;
INSERT INTO audit_retention_configs (stream_id, realm_id, retention_days, legal_hold, updated_by, reason, updated_at)
SELECT stream_id, realm_id, retention_days, legal_hold, updated_by, reason, updated_at
FROM audit_retention_rekey;
DROP TABLE audit_retention_rekey;
