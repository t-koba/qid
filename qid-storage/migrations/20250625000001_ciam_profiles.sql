CREATE TABLE IF NOT EXISTS ciam_profiles (
    id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_json TEXT NOT NULL DEFAULT '{}',
    passwordless_migrated_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ciam_profiles_realm_user
    ON ciam_profiles (realm_id, user_id);

CREATE INDEX IF NOT EXISTS idx_ciam_profiles_passwordless_migrated
    ON ciam_profiles (realm_id, passwordless_migrated_at)
    WHERE passwordless_migrated_at IS NOT NULL;
