CREATE TABLE IF NOT EXISTS ciam_brands (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    primary_color TEXT NOT NULL,
    logo_uri TEXT,
    privacy_policy_uri TEXT,
    support_uri TEXT,
    terms_version TEXT,
    active INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciam_brands_tenant_id
    ON ciam_brands (tenant_id);

CREATE INDEX IF NOT EXISTS idx_ciam_brands_realm_id
    ON ciam_brands (realm_id);
