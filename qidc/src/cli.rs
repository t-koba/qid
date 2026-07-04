use super::*;

#[derive(Parser)]
#[command(name = "qidc")]
#[command(about = "qid control CLI")]
pub(crate) struct CliArgs {
    #[arg(short, long, global = true, default_value = "/etc/qid/qid.yaml")]
    pub(crate) config: Vec<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Validate the configuration file.
    Check,
    /// Show the compiled runtime plan.
    Plan,
    /// Realm management.
    Realm {
        #[command(subcommand)]
        command: RealmCommand,
    },
    /// Client management.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// User management.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Session management.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// TOTP credential management.
    Totp {
        #[command(subcommand)]
        command: TotpCommand,
    },
    /// Explain a policy decision.
    Explain {
        #[arg(long, default_value = "corp")]
        realm: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        resource_host: Option<String>,
        #[arg(long, default_value = "connect")]
        action: String,
        #[arg(long)]
        pep_registration: Option<String>,
        #[arg(long)]
        destination_category: Option<String>,
        #[arg(long, value_enum, default_value = "unknown")]
        destination_reputation: CliDestinationReputation,
        #[arg(long, value_enum, default_value = "unknown")]
        device_trust: CliDeviceTrust,
        #[arg(long)]
        anonymous_network: bool,
        #[arg(long)]
        high_risk_asn: bool,
        #[arg(long)]
        phishing_resistant_mfa: bool,
        #[arg(long)]
        sender_constrained_token: bool,
        #[arg(long)]
        token_age_seconds: Option<u64>,
        #[arg(long)]
        auth_age_seconds: Option<u64>,
        #[arg(long)]
        acr: Option<String>,
        #[arg(long, value_delimiter = ',')]
        amr: Vec<String>,
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Operational readiness and recovery helpers.
    Ops {
        #[command(subcommand)]
        command: OpsCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum OpsCommand {
    /// Check Ops configuration readiness.
    #[command(name = "check")]
    Check,
    /// Build a backup manifest for one or more exported objects.
    #[command(name = "backup-manifest")]
    BackupManifest(BackupManifestArgs),
    /// Plan a restore from a backup manifest.
    #[command(name = "restore-plan")]
    RestorePlan(RestorePlanArgs),
    /// Execute a restore from local backup objects.
    #[command(name = "restore-execute")]
    RestoreExecute(RestoreExecuteArgs),
    /// Render the non-PII cache key for a material string.
    #[command(name = "cache-key")]
    CacheKey(CacheKeyArgs),
    /// Plan realm and purpose scoped key rotation actions.
    #[command(name = "key-rotation-plan")]
    KeyRotationPlan(KeyRotationPlanArgs),
    /// Check key rotation status from local state directory (cron-friendly).
    #[command(name = "key-rotation-check")]
    KeyRotationCheck,
}

#[derive(Args)]
pub(crate) struct BackupManifestArgs {
    #[arg(long)]
    pub(crate) source_cluster_id: Option<String>,
    #[arg(long)]
    pub(crate) migration_version: Option<String>,
    #[arg(long, required = true)]
    pub(crate) object: Vec<String>,
}

#[derive(Args)]
pub(crate) struct RestorePlanArgs {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) target_cluster_id: String,
    #[arg(long)]
    pub(crate) current_migration_version: Option<String>,
    #[arg(long)]
    pub(crate) read_only: bool,
}

#[derive(Args)]
pub(crate) struct RestoreExecuteArgs {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) target_cluster_id: String,
    #[arg(long)]
    pub(crate) current_migration_version: Option<String>,
    #[arg(long)]
    pub(crate) read_only: bool,
    #[arg(long)]
    pub(crate) source_dir: PathBuf,
    #[arg(long)]
    pub(crate) target_dir: PathBuf,
    #[arg(long)]
    pub(crate) allow_overwrite: bool,
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub(crate) struct CacheKeyArgs {
    #[arg(long)]
    pub(crate) namespace: String,
    #[arg(long)]
    pub(crate) material: String,
}

#[derive(Args)]
pub(crate) struct KeyRotationPlanArgs {
    /// Inventory record: realm,keyring,kid,purpose,signer_type,created,not_before,retire_after\[,revoked\].
    #[arg(long = "inventory", required = true)]
    pub(crate) inventory: Vec<String>,
    /// Requirement: realm,purpose,max_age_days,overlap_days,require_remote,require_dedicated.
    #[arg(long = "requirement", required = true)]
    pub(crate) requirement: Vec<String>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
}

// --- Realm ---

#[derive(Args)]
pub(crate) struct CreateRealm {
    #[arg(long)]
    pub(crate) id: String,
    #[arg(long)]
    pub(crate) issuer: String,
    #[arg(long)]
    pub(crate) display_name: Option<String>,
}

#[derive(Args)]
pub(crate) struct GetRealm {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Args)]
pub(crate) struct DeleteRealm {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Subcommand)]
pub(crate) enum RealmCommand {
    #[command(name = "create")]
    Create(CreateRealm),
    /// List all realms.
    #[command(name = "list")]
    List,
    /// Get a realm by ID.
    #[command(name = "get")]
    Get(GetRealm),
    /// Delete a realm.
    #[command(name = "delete")]
    Delete(DeleteRealm),
}

// --- Client ---

#[derive(Args)]
pub(crate) struct CreateClient {
    #[arg(long)]
    pub(crate) realm: String,
    #[arg(long)]
    pub(crate) client_id: String,
    #[arg(long)]
    pub(crate) secret: Option<String>,
    #[arg(long)]
    pub(crate) redirect_uri: String,
    #[arg(long, value_enum, default_value = "confidential")]
    pub(crate) client_type: CliClientType,
}

#[derive(Args)]
pub(crate) struct ListClients {
    #[arg(long)]
    pub(crate) realm: String,
}

#[derive(Args)]
pub(crate) struct DeleteClient {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Subcommand)]
pub(crate) enum ClientCommand {
    #[command(name = "create")]
    Create(CreateClient),
    /// List clients in a realm.
    #[command(name = "list")]
    List(ListClients),
    /// Delete a client.
    #[command(name = "delete")]
    Delete(DeleteClient),
}

// --- User ---

#[derive(Args)]
pub(crate) struct CreateUser {
    #[arg(long)]
    pub(crate) realm: String,
    #[arg(long)]
    pub(crate) email: String,
    #[arg(long)]
    pub(crate) password: String,
    #[arg(long)]
    pub(crate) display_name: Option<String>,
}

#[derive(Args)]
pub(crate) struct ListUsers {
    #[arg(long)]
    pub(crate) realm: String,
}

#[derive(Args)]
pub(crate) struct GetUser {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Args)]
pub(crate) struct DeleteUser {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Subcommand)]
pub(crate) enum UserCommand {
    #[command(name = "create")]
    Create(CreateUser),
    /// List users in a realm.
    #[command(name = "list")]
    List(ListUsers),
    /// Get a user by ID.
    #[command(name = "get")]
    Get(GetUser),
    /// Delete a user.
    #[command(name = "delete")]
    Delete(DeleteUser),
}

// --- Session ---

#[derive(Args)]
pub(crate) struct CreateSession {
    #[arg(long)]
    pub(crate) realm: String,
    #[arg(long)]
    pub(crate) user_id: String,
    #[arg(long, default_value = "12")]
    pub(crate) absolute_hours: u64,
    #[arg(long, default_value = "30")]
    pub(crate) idle_minutes: u64,
}

#[derive(Args)]
pub(crate) struct RevokeSession {
    #[arg(long)]
    pub(crate) session_id: String,
}

#[derive(Subcommand)]
pub(crate) enum SessionCommand {
    #[command(name = "create")]
    Create(CreateSession),
    /// Revoke a session.
    #[command(name = "revoke")]
    Revoke(RevokeSession),
}

// --- TOTP ---

#[derive(Args)]
pub(crate) struct TotpEnroll {
    #[arg(long)]
    pub(crate) user_id: String,
}

#[derive(Subcommand)]
pub(crate) enum TotpCommand {
    /// Enroll a TOTP credential for a user.
    #[command(name = "enroll")]
    Enroll(TotpEnroll),
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum CliClientType {
    #[default]
    Confidential,
    Public,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum CliDeviceTrust {
    Managed,
    Registered,
    #[default]
    Unknown,
    Unmanaged,
    Compromised,
}

impl From<CliDeviceTrust> for DeviceTrustState {
    fn from(value: CliDeviceTrust) -> Self {
        match value {
            CliDeviceTrust::Managed => DeviceTrustState::Managed,
            CliDeviceTrust::Registered => DeviceTrustState::Registered,
            CliDeviceTrust::Unknown => DeviceTrustState::Unknown,
            CliDeviceTrust::Unmanaged => DeviceTrustState::Unmanaged,
            CliDeviceTrust::Compromised => DeviceTrustState::Compromised,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub(crate) enum CliDestinationReputation {
    KnownGood,
    #[default]
    Unknown,
    Suspicious,
    Malicious,
}

impl From<CliDestinationReputation> for DestinationReputation {
    fn from(value: CliDestinationReputation) -> Self {
        match value {
            CliDestinationReputation::KnownGood => DestinationReputation::KnownGood,
            CliDestinationReputation::Unknown => DestinationReputation::Unknown,
            CliDestinationReputation::Suspicious => DestinationReputation::Suspicious,
            CliDestinationReputation::Malicious => DestinationReputation::Malicious,
        }
    }
}
