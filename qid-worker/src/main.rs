use clap::Parser;

mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let result = cli::run(args).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
