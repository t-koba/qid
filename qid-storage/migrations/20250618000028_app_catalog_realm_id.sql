ALTER TABLE app_catalog_entries
    ADD COLUMN realm_id TEXT NOT NULL DEFAULT '';

UPDATE app_catalog_entries
SET realm_id = COALESCE(
    (
        SELECT realms.id
        FROM realms
        WHERE realms.tenant_id = app_catalog_entries.tenant_id
          AND (
              SELECT COUNT(*)
              FROM realms AS realm_count
              WHERE realm_count.tenant_id = app_catalog_entries.tenant_id
          ) = 1
        LIMIT 1
    ),
    realm_id
)
WHERE realm_id = '';

CREATE INDEX IF NOT EXISTS idx_app_catalog_entries_realm_id
    ON app_catalog_entries (realm_id);
