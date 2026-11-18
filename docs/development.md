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
| `ci.yml` | Fast quality gates: format, clippy, docs, structure, report-only source-size measurements, and a lint that rejects blocking reqwest clients. |
| `test.yml` | Workspace build/test matrix, all-features tests, config sample validation, sister-PEP smoke, fuzz smoke on pushes and pull requests, and coverage. |
| `ci-job-timings.yml` | Completed same-repository CI/Test run-attempt job durations, Markdown summary, and CSV artifact. |
| `security.yml` | Sensitive artifact checks, cargo-deny, cargo-audit, package metadata checks, crate packaging, and SBOM. |
| `release.yml` | Release preflight, qpx-aligned release target builds, binary archives, crate tarballs, SBOM, and tag-based GitHub Releases. |

`release.yml` creates GitHub Releases only for `v*` tags. Manual dispatch runs
the same release checks and uploads artifacts without publishing a GitHub
Release.

`ci-job-timings.yml` reports observed runner-wall seconds and job-minutes from
Jobs API start/end timestamps, not billing or workflow elapsed time. Its report
job has a configurable five-minute timeout. It shows
timestamp coverage and excludes unavailable durations from the sum. CSV artifacts
use the repository's default retention. The read-only reporter never checks out
upstream code: it anonymously downloads its script from its own trusted workflow
SHA, so this workflow requires a public repository and deployment on the default
branch. Fork-headed runs are excluded. API failures or incomplete pagination fail
the report rather than presenting a complete total; there is no automatic retry.

Each native `test.yml` matrix job uploads a run-attempt-unique `test-binary-timings-<OS/architecture>-<run-id>-<attempt>`
with a compact CSV from that job's existing test run (no rerun). Rows contain the
executable basename, libtest duration in seconds, result and aggregate counts;
no raw logs, source paths or test names are uploaded. These are binary test times,
not compilation, process startup, doc-test or job durations. Failed libtest
summaries are included; missing/malformed summaries (including an aborted binary)
fail the reporter instead of producing incomplete evidence. Capture and reporting
run in the same test step; Cargo failures remain failures, and its captured output is
removed after reporting. CSV artifacts use the repository's default retention.

Reporter tests (stdlib only):

```sh
python3 -m unittest discover -s scripts -p 'test_report_*timings.py'
```

## Test

```sh
cargo test --workspace --locked -- --test-threads=1
```

Targeted examples:

```sh
cargo test -p qid-oauth --test token_flows --locked -- --test-threads=1
cargo test -p qid-oauth-token-tests --locked -- --test-threads=1
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
| `baseline` | fmt, clippy, workspace tests, docs, cargo-deny, cargo-audit, structure, source-size (report only), docs-routes. |
| `conformance` | OAuth/OIDC, FAPI token flow, SAML interop, SCIM protocol, WebAuthn ceremony, qpx end-to-end. |
| `assurance` | JWT/JWK parser, SAML XML and SCIM filter hardening, policy property, token rotation and tenant isolation properties, migration rollback, chaos checks. |
| `preflight` | JWT/JWK, SAML XML, SCIM filter and policy parser fuzz smokes, sanitizer smoke, PEP decision performance regression, release preflight. |
| `release` | baseline + conformance + assurance + preflight. |

Structure validation and source-size measurement can be run separately:

```sh
cargo run -p xtask -- structure
cargo run -p xtask -- source-size
```

`source-size` reports per-crate and total Rust source and test line counts as
evidence, without thresholds or PASS/FAIL status. Line counts never fail a change,
test, or CI run, and no cap metadata is required. Measurement, I/O, or metadata
errors still exit nonzero.

Rust files under `tests/`, standalone test files (named `test.rs`, `tests.rs`,
`test_*.rs`, `*_test.rs`, or `*_tests.rs`), and source in workspace packages whose
name ends in `-tests` are reported as test lines. Other Rust files are counted as
product source, including mixed files containing inline `#[cfg(test)]` modules;
the measurement does not parse Rust syntax to split them. Counts include blank
and comment lines. Non-Rust files and files under `target/` are excluded.

## Coverage

Install prerequisites:

```sh
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
# python3 is also required: scripts/coverage.sh parses and validates the report with it.
```

Run coverage:

```sh
scripts/coverage.sh
cargo run -p xtask -- coverage --min-pct 50.0
```

`scripts/coverage.sh` is a blocking gate: a `cargo-llvm-cov` failure, an invalid `MIN_LINE_COVERAGE` threshold, a malformed coverage report, or line coverage below the threshold all exit nonzero with a `FAIL` message. `MIN_LINE_COVERAGE` must be a finite decimal in `[0, 100]`; the report must contain nonnegative integer line `count`/`covered` values with `covered <= count`. The gate compares the unrounded coverage ratio against the threshold and displays the percentage rounded to two decimals.

## Fuzzing

See [../fuzz/README.md](../fuzz/README.md).

Install:

```sh
cargo install cargo-fuzz
```

Examples (each runs for a bounded 60 seconds):

```sh
cargo fuzz list
cargo fuzz run jwt -- -max_total_time=60
cargo fuzz run scim_filter -- -max_total_time=60
cargo fuzz run saml_xml -- -max_total_time=60
cargo fuzz run policy -- -max_total_time=60
cargo fuzz run radius -- -max_total_time=60
cargo fuzz run tacacs -- -max_total_time=60
cargo fuzz run eap -- -max_total_time=60
cargo fuzz run tls13_record -- -max_total_time=60
cargo fuzz run tls12_client_hello -- -max_total_time=60
cargo fuzz run tls12_record_protection -- -max_total_time=60
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

The script requires a compatible `qpxd`, starts `qidd`, creates a user/session through `qidc`, requests a client credentials token, fetches a PEP assertion, and exercises fail-closed JWT validation, AuthZEN authorization, and RFC 7662 introspection through qpx. By default it uses `../qpx/target/debug/qpxd`; set `QPXD_BIN` when the binary is elsewhere.

Environment variables:

- `QID_QPX_E2E_TMP_DIR`
- `QID_QPX_E2E_KEEP_TMP`
- `QPXD_BIN`

## Adding a Crate or Route

When adding a new crate:

1. Add it to workspace `members`.
2. Add a `src/lib.rs` or `src/main.rs`.
3. Prefer `qid-core` models/config and `qid-storage` traits over duplicating domain state.
4. Keep integration examples in `examples/` or `config/usecases/`.
5. Run `cargo run -p xtask -- structure`.
6. Run `cargo run -p xtask -- source-size`.

When adding a new HTTP route:

1. Put domain routes in the relevant protocol crate.
2. Merge routes in `qidd` only when profile/config says the surface should exist.
3. Add tests around authz, config gating, fail-closed behavior, and diagnostics.
4. Update [http-api.md](http-api.md).
5. Update config samples if the route requires new config.

## Independent Bouncy Castle TLS Client

`qid-tls/tests/bctls_v2_interop.rs` drives `ci/bctls/V2Client.java` through
`ServerHandshake` over line-oriented hex records on stdin/stdout; no socket or
listener is involved. The Java client uses Bouncy Castle's low-level TLS API
(`bctls`, `bcprov`, `bcutil`) under its permissive Bouncy Castle licence.
The `all-features` CI job pins jar version 1.84, compiles the client, and runs
the ignored test with `QID_BCTLS_JARS` and `QID_BCTLS_CLASSES`; `JAVA` may
override the runtime command. The ignored test fails rather than skips when
those variables are absent, so a green CI run is real evidence. This is the
independent-client evidence for RFC 6961 multi-response stapling; local
`cargo test` only compiles it.

## Generated Artifacts

Do not treat `target/`, `mutants.out/`, local `qid-state/`, generated databases, or logs as source documentation. They can be large, environment-specific, and sensitive.
