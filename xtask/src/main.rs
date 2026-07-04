use clap::{Parser, ValueEnum};
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as Shell;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "qid repository tasks")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Verify crate structure constraints.
    Structure,
    /// Verify line-count budget.
    Budget,
    /// Run CI quality and conformance gates.
    Gate {
        /// Gate suite to run.
        #[arg(value_enum, default_value_t = GateSuite::Baseline)]
        suite: GateSuite,
        /// Print the command plan without executing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Measure code coverage with cargo-llvm-cov.
    Coverage {
        /// Minimum line coverage threshold (default 50.0).
        #[arg(long, default_value_t = 50.0)]
        min_pct: f64,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Structure => cmd_structure()?,
        Command::Budget => cmd_budget()?,
        Command::Gate { suite, dry_run } => cmd_gate(suite, dry_run)?,
        Command::Coverage { min_pct } => cmd_coverage(min_pct)?,
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GateSuite {
    /// fmt, clippy, tests, docs, structure, and budget.
    Baseline,
    /// OAuth/OIDC, FAPI, SAML, SCIM, WebAuthn, and qpx e2e checks.
    Conformance,
    /// Parser hardening, security properties, migration rollback, and chaos checks.
    Assurance,
    /// Sanitizer, performance, and final release preflight checks.
    Preflight,
    /// Baseline, conformance, and assurance checks.
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateCommand {
    name: &'static str,
    program: &'static str,
    args: Vec<&'static str>,
    env: Vec<(&'static str, &'static str)>,
}

impl GateCommand {
    fn new(name: &'static str, program: &'static str, args: &[&'static str]) -> Self {
        Self {
            name,
            program,
            args: args.to_vec(),
            env: Vec::new(),
        }
    }

    fn with_env(mut self, key: &'static str, value: &'static str) -> Self {
        self.env.push((key, value));
        self
    }

    fn display(&self) -> String {
        let env = self
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        let command = std::iter::once(self.program)
            .chain(self.args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        if env.is_empty() {
            command
        } else {
            format!("{env} {command}")
        }
    }
}

fn cmd_gate(suite: GateSuite, dry_run: bool) -> anyhow::Result<()> {
    let root = workspace_root()?;
    let plan = gate_plan(suite);
    for command in &plan {
        println!("GATE: {} -> {}", command.name, command.display());
        if dry_run {
            continue;
        }
        let mut child = Shell::new(command.program);
        child.args(&command.args).current_dir(&root);
        for (key, value) in &command.env {
            child.env(key, value);
        }
        let status = child.status()?;
        if !status.success() {
            anyhow::bail!("gate '{}' failed with status {status}", command.name);
        }
    }
    println!("\ngate suite '{suite:?}' passed");
    Ok(())
}

fn gate_plan(suite: GateSuite) -> Vec<GateCommand> {
    match suite {
        GateSuite::Baseline => baseline_gates(),
        GateSuite::Conformance => conformance_gates(),
        GateSuite::Assurance => assurance_gates(),
        GateSuite::Preflight => preflight_gates(),
        GateSuite::Release => {
            let mut gates = baseline_gates();
            gates.extend(conformance_gates());
            gates.extend(assurance_gates());
            gates.extend(preflight_gates());
            gates
        }
    }
}

fn baseline_gates() -> Vec<GateCommand> {
    vec![
        GateCommand::new("fmt", "cargo", &["fmt", "--all", "--", "--check"]),
        GateCommand::new(
            "clippy",
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "workspace-tests",
            "cargo",
            &["test", "--workspace", "--locked", "--", "--test-threads=1"],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "docs",
            "cargo",
            &["doc", "--workspace", "--locked", "--no-deps"],
        )
        .with_env("RUSTDOCFLAGS", "-D warnings"),
        GateCommand::new("cargo-deny", "cargo", &["deny", "check"]),
        GateCommand::new("cargo-audit", "cargo", &["audit"]),
        GateCommand::new(
            "structure",
            "cargo",
            &["run", "-p", "xtask", "--", "structure"],
        ),
        GateCommand::new("budget", "cargo", &["run", "-p", "xtask", "--", "budget"]),
    ]
}

fn conformance_gates() -> Vec<GateCommand> {
    vec![
        GateCommand::new(
            "oauth-oidc-conformance",
            "cargo",
            &[
                "test",
                "-p",
                "qid-oidc",
                "--test",
                "authorize_par",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "fapi-token-conformance",
            "cargo",
            &[
                "test",
                "-p",
                "qid-oauth",
                "--test",
                "token_flows",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "saml-interop",
            "cargo",
            &[
                "test",
                "-p",
                "qid-saml",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "scim-protocol",
            "cargo",
            &[
                "test",
                "-p",
                "qid-scim",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "webauthn-ceremony",
            "cargo",
            &[
                "test",
                "-p",
                "qid-session",
                "--locked",
                "webauthn",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new("qpx-e2e", "bash", &["examples/qpx-e2e/run.sh"]),
    ]
}

fn assurance_gates() -> Vec<GateCommand> {
    vec![
        GateCommand::new(
            "jwt-jwk-parser-hardening",
            "cargo",
            &[
                "test",
                "-p",
                "qid-crypto",
                "--locked",
                "jwt::tests",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "saml-xml-hardening",
            "cargo",
            &[
                "test",
                "-p",
                "qid-saml",
                "--locked",
                "wrapping",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "scim-filter-hardening",
            "cargo",
            &[
                "test",
                "-p",
                "qid-scim",
                "--locked",
                "filter",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "policy-property-checks",
            "cargo",
            &[
                "test",
                "-p",
                "qid-policy",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "token-rotation-property",
            "cargo",
            &[
                "test",
                "-p",
                "qid-oauth",
                "--test",
                "token_flows",
                "--locked",
                "refresh",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "tenant-isolation-property",
            "cargo",
            &[
                "test",
                "-p",
                "qid-storage",
                "--test",
                "sql_repository",
                "--locked",
                "test_sql_saas_repository_round_trip",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "migration-rollback",
            "cargo",
            &[
                "test",
                "-p",
                "qid-ops",
                "--locked",
                "restore_failure_reports_partial_objects_for_rollback_plan",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "chaos-cache-down",
            "cargo",
            &[
                "test",
                "-p",
                "qid-ops",
                "--locked",
                "redis_like_cache_health_reports_backend_failure",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "chaos-kms-latency",
            "cargo",
            &[
                "test",
                "-p",
                "qid-crypto",
                "--locked",
                "remote_signer_readiness_fails_closed_on_latency",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "chaos-pep-decision-timeout",
            "cargo",
            &[
                "test",
                "-p",
                "qid-proxy",
                "--locked",
                "timeout",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
    ]
}

fn preflight_gates() -> Vec<GateCommand> {
    vec![
        GateCommand::new(
            "fuzz-smoke-jwt-jwk-jws",
            "cargo",
            &[
                "test",
                "-p",
                "qid-crypto",
                "--locked",
                "jwt",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "fuzz-smoke-saml-xml",
            "cargo",
            &[
                "test",
                "-p",
                "qid-saml",
                "--locked",
                "xml",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "fuzz-smoke-scim-filter",
            "cargo",
            &[
                "test",
                "-p",
                "qid-scim",
                "--locked",
                "filter",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "fuzz-smoke-policy-parser",
            "cargo",
            &[
                "test",
                "-p",
                "qid-policy",
                "--locked",
                "policy",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "sanitizer-address-smoke",
            "cargo",
            &[
                "+nightly",
                "test",
                "-p",
                "qid-policy",
                "--locked",
                "--target",
                sanitizer_target(),
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-Z sanitizer=address"),
        GateCommand::new(
            "perf-pep-decision-regression",
            "cargo",
            &[
                "test",
                "-p",
                "qid-proxy",
                "--locked",
                "pep_decision",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
        GateCommand::new(
            "release-preflight",
            "cargo",
            &[
                "test",
                "--workspace",
                "--all-features",
                "--locked",
                "--",
                "--test-threads=1",
            ],
        )
        .with_env("RUSTFLAGS", "-D warnings"),
    ]
}

fn sanitizer_target() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

fn cargo_metadata() -> anyhow::Result<serde_json::Value> {
    let output = Shell::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let meta = cargo_metadata()?;
    let root = meta["workspace_root"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("workspace_root not found in metadata"))?;
    Ok(PathBuf::from(root))
}

fn packages_in_workspace() -> anyhow::Result<Vec<(String, PathBuf)>> {
    let meta = cargo_metadata()?;
    let root = workspace_root()?;
    let packages = meta["packages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("packages not found in metadata"))?;

    let result = packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg["name"].as_str()?;
            let manifest = pkg["manifest_path"].as_str()?;
            let manifest_path = PathBuf::from(manifest);
            // Only include packages under the workspace root
            if manifest_path.starts_with(&root) {
                Some((name.to_string(), manifest_path))
            } else {
                None
            }
        })
        .collect();
    Ok(result)
}

fn cmd_structure() -> anyhow::Result<()> {
    let packages = packages_in_workspace()?;
    let mut all_pass = true;

    for (name, manifest_path) in &packages {
        let crate_dir = manifest_path
            .parent()
            .expect("manifest_path should have a parent");

        // Check 1: directory exists
        if !crate_dir.exists() {
            println!("FAIL: {name} — directory not found at {:?}", crate_dir);
            all_pass = false;
            continue;
        }
        println!("PASS: {name} — directory exists");

        // Check 2: Cargo.toml exists
        if !manifest_path.exists() {
            println!("FAIL: {name} — Cargo.toml not found");
            all_pass = false;
            continue;
        }
        println!("PASS: {name} — Cargo.toml exists");

        // Check 3: src/ with lib.rs or main.rs
        let src_dir = crate_dir.join("src");
        if !src_dir.exists() {
            println!("FAIL: {name} — src/ directory not found");
            all_pass = false;
            continue;
        }
        let has_lib = src_dir.join("lib.rs").exists();
        let has_main = src_dir.join("main.rs").exists();
        let kind = match (has_lib, has_main) {
            (true, true) => "library + binary",
            (true, false) => "library",
            (false, true) => "binary",
            (false, false) => {
                println!("FAIL: {name} — src/ contains neither lib.rs nor main.rs");
                all_pass = false;
                continue;
            }
        };
        println!("PASS: {name} — src/ contains {kind} entry point");
    }

    if !all_pass {
        anyhow::bail!("structure check failed");
    }

    println!("\nstructure check passed");
    Ok(())
}

fn count_rs_lines(dir: &Path) -> io::Result<usize> {
    let mut total = 0;
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            let content = fs::read_to_string(entry.path())?;
            total += content.lines().count();
        }
    }
    Ok(total)
}

fn cmd_budget() -> anyhow::Result<()> {
    let packages = packages_in_workspace()?;

    let default_crate_budget: usize = 3500;
    let total_budget: usize = 55000;

    let mut grand_total = 0;
    let mut failures = 0;

    println!("Line counts per crate:");
    println!("{:-<60}", "");

    for (name, manifest_path) in &packages {
        let crate_dir = manifest_path
            .parent()
            .expect("manifest_path should have a parent");
        match count_rs_lines(crate_dir) {
            Ok(count) => {
                grand_total += count;
                let crate_budget = budget_for_crate(name, default_crate_budget);
                if count > crate_budget {
                    println!("  {name:30} {count:>6} lines  FAIL (exceeds {crate_budget})");
                    failures += 1;
                } else {
                    println!("  {name:30} {count:>6} lines  PASS");
                }
            }
            Err(e) => {
                println!("  {name:30} ERROR: {e}");
                failures += 1;
            }
        }
    }

    println!("{:-<60}", "");
    println!("  {:<30} {:>6} lines", "Total", grand_total);

    if grand_total > total_budget {
        println!("FAIL: total exceeds budget of {total_budget} lines");
        failures += 1;
    } else {
        println!("PASS: within total budget of {total_budget} lines");
    }

    if failures > 0 {
        anyhow::bail!("budget check failed with {failures} failure(s)");
    }

    println!("\nbudget check passed");
    Ok(())
}

fn budget_for_crate(name: &str, default_budget: usize) -> usize {
    match name {
        "qid-core" => 6000,
        "qid-storage" => 7600,
        "qid-oauth" => 7600,
        "qid-admin" => 2800,
        "qid-iga" => 3600,
        "qid-scim" => 3200,
        "qid-saml" => 3000,
        "qid-oidc" => 2600,
        _ => default_budget,
    }
}

fn cmd_coverage(min_pct: f64) -> anyhow::Result<()> {
    let root = workspace_root()?;
    println!("=== coverage gate ===");
    println!("Minimum line coverage: {min_pct}%");
    let status = Shell::new("bash")
        .args(["scripts/coverage.sh"])
        .current_dir(&root)
        .env("MIN_LINE_COVERAGE", min_pct.to_string())
        .status()?;
    if !status.success() {
        anyhow::bail!("coverage gate failed");
    }
    println!("\ncoverage gate passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(plan: &[GateCommand]) -> Vec<&'static str> {
        plan.iter().map(|command| command.name).collect()
    }

    #[test]
    fn baseline_gate_plan_covers_repository_quality_gates() {
        let plan = gate_plan(GateSuite::Baseline);
        let names = names(&plan);

        assert_eq!(
            names,
            vec![
                "fmt",
                "clippy",
                "workspace-tests",
                "docs",
                "cargo-deny",
                "cargo-audit",
                "structure",
                "budget"
            ]
        );
        assert!(
            plan.iter()
                .find(|command| command.name == "clippy")
                .unwrap()
                .env
                .contains(&("RUSTFLAGS", "-D warnings"))
        );
    }

    #[test]
    fn conformance_gate_plan_covers_protocol_suites() {
        let names = names(&gate_plan(GateSuite::Conformance));

        assert!(names.contains(&"oauth-oidc-conformance"));
        assert!(names.contains(&"fapi-token-conformance"));
        assert!(names.contains(&"saml-interop"));
        assert!(names.contains(&"scim-protocol"));
        assert!(names.contains(&"webauthn-ceremony"));
        assert!(names.contains(&"qpx-e2e"));
    }

    #[test]
    fn assurance_gate_plan_covers_security_and_resilience_suites() {
        let names = names(&gate_plan(GateSuite::Assurance));

        assert!(names.contains(&"jwt-jwk-parser-hardening"));
        assert!(names.contains(&"saml-xml-hardening"));
        assert!(names.contains(&"scim-filter-hardening"));
        assert!(names.contains(&"policy-property-checks"));
        assert!(names.contains(&"token-rotation-property"));
        assert!(names.contains(&"tenant-isolation-property"));
        assert!(names.contains(&"migration-rollback"));
        assert!(names.contains(&"chaos-cache-down"));
        assert!(names.contains(&"chaos-kms-latency"));
        assert!(names.contains(&"chaos-pep-decision-timeout"));
    }

    #[test]
    fn preflight_gate_plan_covers_fuzz_sanitizer_perf_and_release_preflight() {
        let names = names(&gate_plan(GateSuite::Preflight));

        assert!(names.contains(&"fuzz-smoke-jwt-jwk-jws"));
        assert!(names.contains(&"fuzz-smoke-saml-xml"));
        assert!(names.contains(&"fuzz-smoke-scim-filter"));
        assert!(names.contains(&"fuzz-smoke-policy-parser"));
        assert!(names.contains(&"sanitizer-address-smoke"));
        assert!(names.contains(&"perf-pep-decision-regression"));
        assert!(names.contains(&"release-preflight"));
    }

    #[test]
    fn release_gate_plan_includes_all_suites_in_order() {
        let release = gate_plan(GateSuite::Release);
        let baseline_len = gate_plan(GateSuite::Baseline).len();
        let conformance_len = gate_plan(GateSuite::Conformance).len();
        let assurance_len = gate_plan(GateSuite::Assurance).len();
        let preflight_len = gate_plan(GateSuite::Preflight).len();

        assert_eq!(
            release.len(),
            baseline_len + conformance_len + assurance_len + preflight_len
        );
        assert_eq!(release.first().unwrap().name, "fmt");
        assert_eq!(release.last().unwrap().name, "release-preflight");
    }

    #[test]
    fn gate_command_display_includes_environment_assignments() {
        let command =
            GateCommand::new("docs", "cargo", &["doc"]).with_env("RUSTDOCFLAGS", "-D warnings");

        assert_eq!(command.display(), "RUSTDOCFLAGS=-D warnings cargo doc");
    }

    #[test]
    fn sanitizer_gate_uses_supported_rust_target() {
        let target = sanitizer_target();

        assert!(target.ends_with("-darwin") || target.ends_with("-gnu"));
    }

    #[test]
    fn budget_uses_explicit_limits_for_large_protocol_crates() {
        assert_eq!(budget_for_crate("qid-core", 3500), 6000);
        assert_eq!(budget_for_crate("qid-storage", 3500), 7600);
        assert_eq!(budget_for_crate("qid-oauth", 3500), 7600);
        assert_eq!(budget_for_crate("qid-policy", 3500), 3500);
    }
}
