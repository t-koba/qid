use clap::{Parser, ValueEnum};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as Shell;
use walkdir::WalkDir;

mod vendor_sync;

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
    /// Verify documented HTTP routes match Axum route literals and shared path constants.
    DocsRoutes,
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
    /// Synchronize vendor/rustls with an upstream release.
    VendorSync {
        /// Target upstream version (must stay on the vendored 0.x line).
        #[arg(long)]
        to: String,
        /// Merge without touching the vendor tree.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Run the vendored crate lib tests after synchronizing.
        #[arg(long, default_value_t = false)]
        run_vendor_tests: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Structure => cmd_structure()?,
        Command::Budget => cmd_budget()?,
        Command::DocsRoutes => cmd_docs_routes()?,
        Command::Gate { suite, dry_run } => cmd_gate(suite, dry_run)?,
        Command::Coverage { min_pct } => cmd_coverage(min_pct)?,
        Command::VendorSync {
            to,
            dry_run,
            run_vendor_tests,
        } => vendor_sync::cmd_vendor_sync(&to, dry_run, run_vendor_tests)?,
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
    /// Documentation route drift check only.
    DocsRoutes,
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
        GateSuite::DocsRoutes => vec![docs_routes_gate()],
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
        docs_routes_gate(),
    ]
}

fn docs_routes_gate() -> GateCommand {
    GateCommand::new(
        "docs-routes",
        "cargo",
        &["run", "-p", "xtask", "--", "docs-routes"],
    )
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

pub(crate) fn workspace_root() -> anyhow::Result<PathBuf> {
    let meta = cargo_metadata()?;
    let root = meta["workspace_root"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("workspace_root not found in metadata"))?;
    Ok(PathBuf::from(root))
}

fn cmd_docs_routes() -> anyhow::Result<()> {
    let root = workspace_root()?;
    let docs_path = root.join("docs/http-api.md");
    let docs = fs::read_to_string(&docs_path)?;
    let routes = collect_axum_route_literals(&root)?;
    let missing = routes
        .iter()
        .filter(|route| !docs.contains(route.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        for route in &missing {
            println!("FAIL: route literal missing from docs/http-api.md: {route}");
        }
        anyhow::bail!("docs/http-api.md is missing {} route(s)", missing.len());
    }
    println!(
        "PASS: docs/http-api.md covers {} literal/shared Axum route(s)",
        routes.len()
    );
    Ok(())
}

fn collect_axum_route_literals(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut sources = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        if path.components().any(|component| {
            let text = component.as_os_str().to_string_lossy();
            text == "target" || text == "fuzz"
        }) {
            continue;
        }
        let Some(first_component) = path
            .strip_prefix(root)
            .ok()
            .and_then(|relative| relative.components().next())
        else {
            continue;
        };
        let first_component = first_component.as_os_str().to_string_lossy();
        if first_component != "qidd" && !first_component.starts_with("qid-") {
            continue;
        }
        if is_test_rs_file(&first_component, path) {
            continue;
        }
        sources.push(fs::read_to_string(path)?);
    }
    let path_constants = sources
        .iter()
        .flat_map(|source| extract_path_constants(source))
        .collect::<BTreeMap<_, _>>();
    Ok(sources
        .iter()
        .flat_map(|source| extract_route_literals_from_source(source, &path_constants))
        .collect())
}

fn extract_path_constants(source: &str) -> BTreeMap<String, String> {
    source
        .lines()
        .filter_map(|line| {
            let declaration = line.trim().strip_prefix("pub const ")?;
            let (name_and_type, value) = declaration.split_once('=')?;
            let name = name_and_type.split(':').next()?.trim();
            if !name.ends_with("_PATH") {
                return None;
            }
            let value = value.trim().strip_suffix(';')?.trim();
            let value = value.strip_prefix('"')?.strip_suffix('"')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

fn extract_route_literals_from_source(
    source: &str,
    path_constants: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut routes = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains(".route(") {
            continue;
        }
        let fragment = lines[idx..std::cmp::min(idx + 8, lines.len())].join("\n");
        let Some(route_call) = fragment.find(".route(") else {
            continue;
        };
        let after_route = fragment[route_call + ".route(".len()..].trim_start();
        let route = if let Some(after_quote) = after_route.strip_prefix('"') {
            let Some(quote_end) = after_quote.find('"') else {
                continue;
            };
            after_quote[..quote_end].to_string()
        } else {
            let name = after_route
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or_default();
            if let Some(route) = path_constants.get(name) {
                route.clone()
            } else {
                let Some(quote_start) = after_route.find('"') else {
                    continue;
                };
                let after_quote = &after_route[quote_start + 1..];
                let Some(quote_end) = after_quote.find('"') else {
                    continue;
                };
                after_quote[..quote_end].to_string()
            }
        };
        if route.starts_with('/') {
            routes.insert(route);
        }
    }
    routes
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RsLineCounts {
    product: usize,
    tests: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct BudgetConfig {
    total: usize,
    default_per_crate: usize,
    per_crate: BTreeMap<String, usize>,
}

impl BudgetConfig {
    fn from_metadata(metadata: &serde_json::Value) -> anyhow::Result<Self> {
        let config = metadata
            .get("metadata")
            .and_then(|value| value.get("budget"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("workspace.metadata.budget is missing or invalid"))?;
        if config.len() != 3
            || !config.contains_key("total")
            || !config.contains_key("default_per_crate")
            || !config.contains_key("per_crate")
        {
            anyhow::bail!(
                "workspace.metadata.budget must define only total, default_per_crate, and per_crate"
            );
        }
        let total = positive_budget(config.get("total"), "total")?;
        let default_per_crate =
            positive_budget(config.get("default_per_crate"), "default_per_crate")?;
        let overrides = config
            .get("per_crate")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                anyhow::anyhow!("workspace.metadata.budget.per_crate must be a table")
            })?;
        let mut per_crate = BTreeMap::new();
        for (name, value) in overrides {
            if name.trim().is_empty() {
                anyhow::bail!("workspace.metadata.budget.per_crate contains an empty crate name");
            }
            per_crate.insert(
                name.clone(),
                positive_budget(Some(value), &format!("per_crate.{name}"))?,
            );
        }
        Ok(Self {
            total,
            default_per_crate,
            per_crate,
        })
    }

    fn crate_limit(&self, name: &str) -> usize {
        self.per_crate
            .get(name)
            .copied()
            .unwrap_or(self.default_per_crate)
    }
}

fn positive_budget(value: Option<&serde_json::Value>, name: &str) -> anyhow::Result<usize> {
    let amount = value
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("workspace.metadata.budget.{name} must be a positive integer")
        })?;
    Ok(amount)
}

fn is_test_rs_file(package_name: &str, path: &Path) -> bool {
    if package_name.ends_with("-tests")
        || path
            .components()
            .any(|component| component.as_os_str() == "tests")
    {
        return true;
    }

    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    stem == "test"
        || stem == "tests"
        || stem.starts_with("test_")
        || stem.ends_with("_test")
        || stem.ends_with("_tests")
}

fn count_rs_lines(dir: &Path, package_name: &str) -> io::Result<RsLineCounts> {
    let mut counts = RsLineCounts::default();
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        let path = entry.path();
        if path
            .components()
            .any(|component| component.as_os_str() == "target")
        {
            continue;
        }
        if entry.file_type().is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            let content = fs::read_to_string(path)?;
            let lines = content.lines().count();
            if is_test_rs_file(package_name, path) {
                counts.tests += lines;
            } else {
                counts.product += lines;
            }
        }
    }
    Ok(counts)
}

fn cmd_budget() -> anyhow::Result<()> {
    let metadata = cargo_metadata()?;
    let config = BudgetConfig::from_metadata(&metadata)?;
    let packages = packages_in_workspace()?;

    let mut product_total = 0;
    let mut test_total = 0;
    let mut failures = 0;

    println!("Product source line counts per crate (tests are reported, not capped):");
    println!("{:-<88}", "");

    for (name, manifest_path) in &packages {
        let crate_dir = manifest_path
            .parent()
            .expect("manifest_path should have a parent");
        match count_rs_lines(crate_dir, name) {
            Ok(counts) => {
                product_total += counts.product;
                test_total += counts.tests;
                let crate_budget = config.crate_limit(name);
                if counts.product > crate_budget {
                    println!(
                        "  {name:30} {:>6} source lines  FAIL (exceeds {crate_budget}); {:>6} test lines (uncapped)",
                        counts.product, counts.tests
                    );
                    failures += 1;
                } else {
                    println!(
                        "  {name:30} {:>6} source lines  PASS (limit {crate_budget}); {:>6} test lines (uncapped)",
                        counts.product, counts.tests
                    );
                }
            }
            Err(e) => {
                println!("  {name:30} ERROR: {e}");
                failures += 1;
            }
        }
    }

    println!("{:-<88}", "");
    println!(
        "  {:<30} {:>6} product source lines (limit {})",
        "Total", product_total, config.total
    );
    println!("  {:<30} {:>6} test lines (uncapped)", "Tests", test_total);

    if product_total > config.total {
        println!(
            "FAIL: product source exceeds total budget of {} lines",
            config.total
        );
        failures += 1;
    } else {
        println!(
            "PASS: product source is within total budget of {} lines",
            config.total
        );
    }

    if failures > 0 {
        anyhow::bail!("budget check failed with {failures} failure(s)");
    }

    println!("\nbudget check passed");
    Ok(())
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
mod budget_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn names(plan: &[GateCommand]) -> Vec<&'static str> {
        plan.iter().map(|command| command.name).collect()
    }

    #[test]
    fn docs_routes_resolve_shared_path_constants() {
        let constants = extract_path_constants(
            r#"pub const CAPPORT_BIND_PATH: &str = "/api/v1/:realm/captive-portal/bind";"#,
        );
        let routes = extract_route_literals_from_source(
            "Router::new().route(CAPPORT_BIND_PATH, post(handler))",
            &constants,
        );
        assert!(routes.contains("/api/v1/:realm/captive-portal/bind"));
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
                "budget",
                "docs-routes"
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
    fn budget_config_reads_workspace_metadata_and_falls_back_to_default() {
        let metadata = serde_json::json!({
            "metadata": {
                "budget": {
                    "total": 103000,
                    "default_per_crate": 4000,
                    "per_crate": {"qid-core": 14000}
                }
            }
        });
        let config = BudgetConfig::from_metadata(&metadata).unwrap();
        assert_eq!(config.total, 103000);
        assert_eq!(config.crate_limit("qid-core"), 14000);
        assert_eq!(config.crate_limit("qid-policy"), 4000);
    }

    #[test]
    fn budget_config_rejects_missing_or_nonpositive_limits() {
        let metadata = serde_json::json!({"metadata": {"budget": {
            "total": 0,
            "default_per_crate": 4000,
            "per_crate": {}
        }}});
        assert!(BudgetConfig::from_metadata(&metadata).is_err());
        assert!(BudgetConfig::from_metadata(&serde_json::json!({})).is_err());
    }

    #[test]
    fn budget_reports_test_paths_and_standalone_test_files_separately() {
        assert!(is_test_rs_file("qid-core", Path::new("tests/property.rs")));
        assert!(is_test_rs_file(
            "qid-core",
            Path::new("src/config/tests.rs")
        ));
        assert!(is_test_rs_file(
            "qid-core",
            Path::new("src/property_tests.rs")
        ));
        assert!(!is_test_rs_file(
            "qid-core",
            Path::new("src/foo_test_bar.rs")
        ));
        assert!(!is_test_rs_file(
            "qid-core",
            Path::new("src/my_test_helper.rs")
        ));
        assert!(is_test_rs_file(
            "qid-oauth-token-tests",
            Path::new("src/lib.rs")
        ));
        assert!(!is_test_rs_file("qid-core", Path::new("src/config.rs")));
    }
}
