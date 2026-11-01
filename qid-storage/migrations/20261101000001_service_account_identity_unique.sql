-- Never select or delete a principal to make an identity unique.
-- If the guard fails, inspect the ambiguous identities with:
-- SELECT realm_id, client_id, COUNT(*) FROM service_accounts
-- GROUP BY realm_id, client_id HAVING COUNT(*) > 1;
-- An operator must explicitly repair the identity bindings externally, then
-- retry migration. The transaction leaves every legacy row unchanged on failure.
CREATE TEMPORARY TABLE service_account_identity_guard (
    duplicates INTEGER CONSTRAINT "duplicate service_accounts realm_id/client_id; repair externally and retry migration"
        CHECK (duplicates = 0)
);
INSERT INTO service_account_identity_guard (duplicates)
SELECT COUNT(*) FROM (
    SELECT realm_id, client_id FROM service_accounts
    GROUP BY realm_id, client_id HAVING COUNT(*) > 1
) AS ambiguous_identities;
DROP TABLE service_account_identity_guard;

CREATE UNIQUE INDEX idx_service_accounts_realm_client_unique
    ON service_accounts (realm_id, client_id);
