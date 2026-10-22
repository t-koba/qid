-- One SPIFFE ID names one workload identity in a realm.
-- A database that already holds two identities with the same SPIFFE ID in one
-- realm fails this migration; remove the redundant identity before migrating.
CREATE UNIQUE INDEX IF NOT EXISTS idx_workload_identities_realm_spiffe
    ON workload_identities (realm_id, spiffe_id);
