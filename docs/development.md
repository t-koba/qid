# Development

Development should follow the product model documented in [README.md](README.md) and [architecture.md](architecture.md): qid is an identity and control plane with protocol, lifecycle, policy, governance, and operations domains.

## Workspace Ownership

- Put shared config, runtime plan, domain models, and cross-field validation in `qid-core`.
- Put PEP decision, signed assertion, and captive portal bridge behavior in `qid-proxy`.
- Put protocol-specific behavior in the corresponding protocol crate, such as `qid-oauth`, `qid-oidc`, `qid-saml`, `qid-scim`, or `qid-federation`.
- Put lifecycle, governance, risk, resource, and operations behavior in their domain crates.
- Treat PEP request body values as assertions to validate, not as authentication truth.
- Use canonical config and API shapes. Do not add internal legacy aliases or compatibility shims for pre-stable qid forms.
- Add profile validation and diagnostics together when a profile gains a required obligation.
- Update docs and config samples when route surfaces, profile obligations, or security boundaries change.

## Prerequisites

- Rust toolchain compatible with workspace `rust-version = "1.96"`.
- Cargo.
- Optional: `cargo-deny`, `cargo-audit`, `cargo-llvm-cov`, `cargo-fuzz`.
- Optional: qpx checkout/binary for the sister-product smoke in `examples/qpx-e2e/run.sh`.

## Build

```sh
cargo build --workspace --locked
cargo build --bin qidd --locked
cargo build --bin qidc --locked
```

## Supported Build Matrix

CI follows the qpx target policy with Rust 1.96.

Build/test/clippy runs on these host runners:

| Host runner | Coverage |
| --- | --- |
| `ubuntu-latest` | Linux x86_64 |
| `ubuntu-24.04-arm` | Linux aarch64 |
| `windows-2022` | Windows x86_64 |
| `macos-14` | macOS aarch64 |

Release target preflight builds these targets:

| Rust target | Runner |
| --- | --- |
| `x86_64-unknown-linux-musl` | `ubuntu-latest` with `cross` |
| `aarch64-unknown-linux-musl` | `ubuntu-latest` with `cross` |
| `aarch64-apple-darwin` | `macos-14` |
| `x86_64-pc-windows-msvc` | `windows-2022` |

Linux musl release targets should use `cross`; local macOS cross-compilation is
not a replacement for CI because native C dependencies require the target
platform's compiler, SDK, and system headers.

## GitHub Workflows

| Workflow | Purpose |
| --- | --- |
| `ci.yml` | Fast quality gates: format, clippy, docs, config samples, structure, and budget. |
| `test.yml` | Workspace build/test matrix, all-features tests, config sample validation, sister-PEP smoke, and coverage. |
| `security.yml` | Sensitive artifact checks, cargo-deny, cargo-audit, package metadata checks, crate packaging, and SBOM. |
| `release.yml` | Release preflight, qpx-aligned release target builds, binary archives, crate tarballs, SBOM, and tag-based GitHub Releases. |

`release.yml` creates GitHub Releases only for `v*` tags. Manual dispatch runs
the same release checks and uploads artifacts without publishing a GitHub
Release.

## Test

```sh
cargo test --workspace --locked -- --test-threads=1
```

Targeted examples:

```sh
cargo test -p qid-oauth --test token_flows --locked -- --test-threads=1
cargo test -p qid-scim --locked -- --test-threads=1
cargo test -p qid-saml --locked -- --test-threads=1
cargo test -p qid-storage --test sql_repository --locked -- --test-threads=1
```

## Formatting, Linting, Docs

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --locked --no-deps
```

## Repository Gates

`xtask` defines several gate suites.

```sh
cargo run -p xtask -- gate baseline --dry-run
cargo run -p xtask -- gate baseline
cargo run -p xtask -- gate conformance
cargo run -p xtask -- gate assurance
cargo run -p xtask -- gate preflight
cargo run -p xtask -- gate release
```

Gate coverage:

| Suite | Includes |
| --- | --- |
| `baseline` | fmt, clippy, workspace tests, docs, cargo-deny, cargo-audit, structure, budget. |
| `conformance` | OAuth/OIDC, FAPI token flow, SAML, SCIM, WebAuthn, generic PEP decision, and sister-product PEP smoke. |
| `assurance` | JWT/JWK hardening, SAML XML hardening, SCIM filter hardening, policy property checks, token rotation, tenant isolation, migration rollback, chaos checks. |
| `preflight` | fuzz smoke tests, sanitizer smoke, PEP decision regression, all-features workspace tests. |
| `release` | baseline + conformance + assurance + preflight. |

Structure and budget can be run separately:

```sh
cargo run -p xtask -- structure
cargo run -p xtask -- budget
```

## Coverage

Install prerequisites:

```sh
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
```

Run coverage:

```sh
scripts/coverage.sh
cargo run -p xtask -- coverage --min-pct 50.0
```

`scripts/coverage.sh` currently treats `cargo-llvm-cov` failure as non-blocking and exits successfully after printing a warning. Keep that behavior in mind when using it as a release gate.

## Fuzzing

See [../fuzz/README.md](../fuzz/README.md).

Install:

```sh
cargo install cargo-fuzz
```

Examples:

```sh
cargo fuzz list
cargo fuzz run jwt -- -max_total=60000
cargo fuzz run scim_filter -- -max_total=60000
cargo fuzz run saml_xml -- -max_total=60000
cargo fuzz run policy -- -max_total=60000
cargo fuzz run radius -- -max_total=60000
cargo fuzz run eap -- -max_total=60000
```

## Config Samples

Validate the representative config and every use-case sample:

```sh
scripts/check-config-samples.sh
```

Use-case docs:

- [../config/README.md](../config/README.md)
- [../config/qid.example.yaml](../config/qid.example.yaml)
- `config/usecases/01-getting-started/local-dev.yaml`
- `config/usecases/99-test-fixtures/minimal-e2e.yaml`

## Local Development Flow

Generate local fixtures:

```sh
cargo run --bin qid-dev -- dev-init --output target/qid-dev --force
```

Validate:

```sh
cargo run --bin qidc -- --config target/qid-dev/qid.yaml check
```

Seed users:

```sh
cargo run --bin qid-dev -- seed-users --config target/qid-dev/qid.yaml --input target/qid-dev/users.seed.json
```

Run daemon:

```sh
cargo run --bin qidd -- --config target/qid-dev/qid.yaml
```

Inspect:

```sh
curl -fsS http://127.0.0.1:8443/health
curl -fsS http://127.0.0.1:8443/jwks
curl -fsS http://127.0.0.1:8443/realms/dev/.well-known/openid-configuration
```

## Sister-Product Smoke

```sh
bash examples/qpx-e2e/run.sh
```

The script starts `qidd`, creates a user/session through `qidc`, requests a client credentials token, fetches a PEP assertion, and optionally starts `qpxd`. It exercises one concrete PEP registration flow.

Environment variables:

- `QID_QPX_E2E_TMP_DIR`
- `QID_QPX_E2E_KEEP_TMP`
- `QPXD_BIN`
- `QPX_STATE_DIR`

## Adding a Crate or Route

When adding a new crate:

1. Add it to workspace `members`.
2. Add a `src/lib.rs` or `src/main.rs`.
3. Prefer `qid-core` models/config and `qid-storage` traits over duplicating domain state.
4. Keep integration examples in `examples/` or `config/usecases/`.
5. Run `cargo run -p xtask -- structure`.
6. Run `cargo run -p xtask -- budget`.

When adding a new HTTP route:

1. Put domain routes in the relevant protocol crate.
2. Merge routes in `qidd` only when profile/config says the surface should exist.
3. Add tests around authz, config gating, fail-closed behavior, and diagnostics.
4. Update [http-api.md](http-api.md).
5. Update config samples if the route requires new config.

## Generated Artifacts

Do not treat `target/`, `mutants.out/`, local `qid-state/`, generated databases, or logs as source documentation. They can be large, environment-specific, and sensitive.
