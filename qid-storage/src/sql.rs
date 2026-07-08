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
mod iga;
mod policy;
mod realm;
mod rebac;
mod row;
mod saas;
mod scim;
mod service_account;
mod session;
mod siem;
mod ssf;
mod token;
mod user;
mod vc;
mod workload;

use row::*;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
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
                    bytes_to_hex(&migration.checksum),
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
        .map(|(version, description, checksum)| (version, (description, bytes_to_hex(&checksum))))
        .collect())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
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
