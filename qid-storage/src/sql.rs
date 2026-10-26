use base64::Engine;
use qid_core::{
    error::{QidError, QidResult},
    models::*,
    tenant::{RealmId, TenantId},
};
use sqlx::AnyPool;
use std::collections::BTreeMap;

use crate::{
    AdminRepository, AuditRepository, CiamRepository, ClientRepository, CredentialRepository,
    DeviceRepository, FedCmRepository, IgaRepository, PolicyRepository, RealmRepository,
    RebacRepository, SaasRepository, ScimDeviceRecord, ScimEventSubscriptionRecord, ScimRepository,
    ServiceAccountRepository, SessionRepository, SiemDeliveryRecord, SiemDeliveryRepository,
    SiemDeliveryStatus, SsfRepository, SsfStreamRecord, TokenRepository, UserRepository,
    VcRepository, WorkloadRepository,
};

mod admin;
mod audit;
mod ciam;
mod client;
mod credential;
mod device;
mod fedcm;
mod hr;
mod iga;
#[cfg(test)]
mod iga_tests;
mod oidc_continuation;
mod policy;
mod push;
mod realm;
#[cfg(test)]
mod realm_tests;
mod rebac;
mod row;
mod saas;
mod scim;
mod service_account;
mod session;
mod siem;
mod ssf;
#[cfg(test)]
pub(crate) mod test_support;
mod token;
mod user;
mod vc;
mod workload;

use row::*;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
const POSTGRES_EPOCH_DEFAULT: &str = "FLOOR(EXTRACT(EPOCH FROM NOW()))::BIGINT";

fn page_bound(value: usize) -> i64 {
    value.min(i64::MAX as usize) as i64
}

/// SQL-backed repository implementation.
#[derive(Debug, Clone)]
pub struct SqlRepository {
    pool: AnyPool,
    database_kind: SqlDatabaseKind,
}

impl SqlRepository {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        sqlx::any::install_default_drivers();
        ensure_sqlite_file_exists(url);
        let database_kind = SqlDatabaseKind::from_url(url);
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await?;
        Ok(Self {
            pool,
            database_kind,
        })
    }

    /// Close the connection pool, wait for active connections, and release this handle.
    pub async fn close(self) {
        self.pool.close().await;
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        match self.database_kind {
            SqlDatabaseKind::Sqlite => MIGRATOR.run(&self.pool).await,
            SqlDatabaseKind::Postgres => postgres_migrator().run(&self.pool).await,
        }
    }

    pub async fn migration_plan(&self) -> QidResult<MigrationPlan> {
        migration_plan_for_pool(&self.pool, self.database_kind).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDatabaseKind {
    Sqlite,
    Postgres,
}

impl SqlDatabaseKind {
    fn from_url(url: &str) -> Self {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("postgres:") || lower.starts_with("postgresql:") {
            Self::Postgres
        } else {
            Self::Sqlite
        }
    }
}

// The historical migration set contains SQLite-only PRAGMAs, time types and defaults.
// Adapt them for PostgreSQL while retaining the canonical source checksums and shared schema.
fn postgres_migrator() -> sqlx::migrate::Migrator {
    let migrations = MIGRATOR
        .iter()
        .cloned()
        .map(|mut migration| {
            migration.sql = std::borrow::Cow::Owned(
                migration
                    .sql
                    .replace("PRAGMA foreign_keys = off;", "")
                    .replace("PRAGMA foreign_keys = on;", "")
                    .replace("DATETIME", "BIGINT")
                    .replace("CURRENT_TIMESTAMP", POSTGRES_EPOCH_DEFAULT)
                    .replace("strftime('%s', 'now')", POSTGRES_EPOCH_DEFAULT),
            );
            migration
        })
        .collect::<Vec<_>>();
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(migrations),
        ignore_missing: MIGRATOR.ignore_missing,
        locking: MIGRATOR.locking,
        no_tx: MIGRATOR.no_tx,
    }
}

#[cfg(test)]
mod postgres_migration_tests {
    use super::*;

    #[test]
    fn postgres_migrations_adapt_sqlite_expressions_and_keep_source_checksums() {
        let postgres = postgres_migrator();
        assert_eq!(postgres.iter().count(), MIGRATOR.iter().count());
        for (original, adapted) in MIGRATOR.iter().zip(postgres.iter()) {
            let expected_sql = original
                .sql
                .replace("PRAGMA foreign_keys = off;", "")
                .replace("PRAGMA foreign_keys = on;", "")
                .replace("DATETIME", "BIGINT")
                .replace("CURRENT_TIMESTAMP", POSTGRES_EPOCH_DEFAULT)
                .replace("strftime('%s', 'now')", POSTGRES_EPOCH_DEFAULT);
            assert_eq!(adapted.version, original.version);
            assert_eq!(adapted.sql, expected_sql);
            assert_eq!(adapted.checksum, original.checksum);
        }
        assert_eq!(
            POSTGRES_EPOCH_DEFAULT,
            "FLOOR(EXTRACT(EPOCH FROM NOW()))::BIGINT"
        );
        assert!(
            postgres
                .iter()
                .any(|migration| { migration.sql.contains(POSTGRES_EPOCH_DEFAULT) })
        );
        assert!(
            postgres
                .iter()
                .all(|migration| !migration.sql.contains("PRAGMA"))
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationPlan {
    pub current_version: Option<i64>,
    pub target_version: Option<i64>,
    pub applied: Vec<MigrationPlanItem>,
    pub pending: Vec<MigrationPlanItem>,
    pub divergent: Vec<MigrationPlanItem>,
    pub unknown_applied: Vec<MigrationPlanItem>,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationPlanItem {
    pub version: i64,
    pub description: String,
    pub checksum_hex: Option<String>,
    pub expected_checksum_hex: Option<String>,
}

async fn migration_plan_for_pool(
    pool: &AnyPool,
    database_kind: SqlDatabaseKind,
) -> QidResult<MigrationPlan> {
    let embedded = MIGRATOR
        .migrations
        .iter()
        .map(|migration| {
            (
                migration.version,
                (
                    migration.description.to_string(),
                    qid_core::util::hex_encode_lower(&migration.checksum),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let applied = load_applied_migrations(pool, database_kind).await?;

    let mut applied_items = Vec::new();
    let mut pending = Vec::new();
    let mut divergent = Vec::new();
    let mut unknown_applied = Vec::new();

    for (version, (description, expected_checksum_hex)) in &embedded {
        match applied.get(version) {
            Some((_, checksum_hex)) if checksum_hex == expected_checksum_hex => {
                applied_items.push(MigrationPlanItem {
                    version: *version,
                    description: description.clone(),
                    checksum_hex: Some(checksum_hex.clone()),
                    expected_checksum_hex: Some(expected_checksum_hex.clone()),
                });
            }
            Some((applied_description, checksum_hex)) => {
                divergent.push(MigrationPlanItem {
                    version: *version,
                    description: applied_description.clone(),
                    checksum_hex: Some(checksum_hex.clone()),
                    expected_checksum_hex: Some(expected_checksum_hex.clone()),
                });
            }
            None => pending.push(MigrationPlanItem {
                version: *version,
                description: description.clone(),
                checksum_hex: None,
                expected_checksum_hex: Some(expected_checksum_hex.clone()),
            }),
        }
    }

    for (version, (description, checksum_hex)) in &applied {
        if !embedded.contains_key(version) {
            unknown_applied.push(MigrationPlanItem {
                version: *version,
                description: description.clone(),
                checksum_hex: Some(checksum_hex.clone()),
                expected_checksum_hex: None,
            });
        }
    }

    Ok(MigrationPlan {
        current_version: applied.keys().next_back().copied(),
        target_version: embedded.keys().next_back().copied(),
        ready: divergent.is_empty() && unknown_applied.is_empty(),
        applied: applied_items,
        pending,
        divergent,
        unknown_applied,
    })
}

async fn load_applied_migrations(
    pool: &AnyPool,
    database_kind: SqlDatabaseKind,
) -> QidResult<BTreeMap<i64, (String, String)>> {
    let exists: Option<(i64,)> = match database_kind {
        SqlDatabaseKind::Sqlite => sqlx::query_as(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_optional(pool)
        .await,
        SqlDatabaseKind::Postgres => sqlx::query_as(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '_sqlx_migrations'",
        )
        .fetch_optional(pool)
        .await,
    }
    .map_err(storage_to_qid_error)?;
    if exists.is_none() {
        return Ok(BTreeMap::new());
    }

    let rows: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(storage_to_qid_error)?;
    Ok(rows
        .into_iter()
        .map(|(version, description, checksum)| {
            (
                version,
                (description, qid_core::util::hex_encode_lower(&checksum)),
            )
        })
        .collect())
}

fn ensure_sqlite_file_exists(url: &str) {
    let Some(path) = sqlite_path_from_url(url) else {
        return;
    };
    if std::path::Path::new(&path).exists() {
        return;
    }
    if let Some(parent) = std::path::Path::new(&path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::File::create(&path);
}

fn sqlite_path_from_url(url: &str) -> Option<String> {
    let lower = url.to_lowercase();
    if !lower.starts_with("sqlite:") {
        return None;
    }
    let after = &url["sqlite:".len()..];
    // sqlite:relative, sqlite://relative, sqlite:///absolute
    let path = after.trim_start_matches("//");
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    Some(path.to_string())
}
