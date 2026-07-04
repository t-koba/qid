use clap::Parser;
use qid_storage::SqlRepository;

#[derive(Parser)]
#[command(name = "qid-migrate")]
#[command(about = "qid database migration tool")]
struct Args {
    /// Database URL.
    #[arg(short, long, env = "QID_DATABASE_URL")]
    database_url: String,

    /// Print the migration plan without applying migrations.
    #[arg(long)]
    dry_run: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let repo = SqlRepository::connect(&args.database_url).await?;
    if args.dry_run {
        let plan = repo.migration_plan().await?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            println!(
                "migration plan: current={:?} target={:?} applied={} pending={} divergent={} unknown_applied={} ready={}",
                plan.current_version,
                plan.target_version,
                plan.applied.len(),
                plan.pending.len(),
                plan.divergent.len(),
                plan.unknown_applied.len(),
                plan.ready,
            );
            for migration in &plan.pending {
                println!("pending {} {}", migration.version, migration.description);
            }
            for migration in &plan.divergent {
                println!("divergent {} {}", migration.version, migration.description);
            }
            for migration in &plan.unknown_applied {
                println!(
                    "unknown_applied {} {}",
                    migration.version, migration.description
                );
            }
        }
        return Ok(());
    }

    println!("running migrations on: {}", args.database_url);
    repo.migrate().await?;
    println!("migrations complete");
    Ok(())
}
