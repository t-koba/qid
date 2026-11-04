-- Raw authenticator credential IDs must not identify multiple qid records.
-- If the guard fails, inspect collisions with:
-- SELECT credential_id, COUNT(*) FROM credentials_webauthn
-- GROUP BY credential_id HAVING COUNT(*) > 1;
-- Inspect matching rows (including id and user_id), explicitly repair the
-- credential bindings externally, then retry migration. Never choose an owner
-- automatically. Failure rolls back without changing rows or the ledger.
CREATE TEMPORARY TABLE webauthn_credential_id_guard (
    duplicates INTEGER CONSTRAINT "duplicate credential_id; inspect/repair externally; retry"
        CHECK (duplicates = 0)
);
INSERT INTO webauthn_credential_id_guard (duplicates)
SELECT COUNT(*) FROM (
    SELECT credential_id FROM credentials_webauthn
    GROUP BY credential_id HAVING COUNT(*) > 1
) AS ambiguous_credentials;
DROP TABLE webauthn_credential_id_guard;

CREATE UNIQUE INDEX idx_credentials_webauthn_credential_id_unique
    ON credentials_webauthn (credential_id);
