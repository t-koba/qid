# qid

`qid` is an identity and control-plane workspace. It is designed to stand alone as an IdP, OAuth/OIDC authorization server, SAML IdP, SCIM lifecycle service, PDP, and operations surface, while also integrating with external proxies, gateways, service meshes, and PEPs.

The sister-product relationship with qpx is important. qid owns users, sessions, tokens, MFA, SCIM lifecycle, risk, policy, audit, and decisions. A PEP owns traffic observation, protocol handling, routing, TLS behavior, local responses, header control, rate limits, and enforcement. qpx is the deepest reference PEP integration; the canonical qid surfaces remain generic.

The repository contains the HTTP identity daemon, a control CLI, asynchronous workers, synchronization helpers, an endpoint/workload agent, a development bootstrapper, a migration tool, and repository quality gates.

## Components

| Component | Role |
| --- | --- |
| `qidd` | The qid identity daemon. Runs the IdP, AS, PDP, lifecycle, admin, and optional network AAA surfaces. |
| `qidc` | Control CLI for config validation, runtime plans, realm/client/user/session/TOTP operations, policy explanation, and ops helpers. |
| `qid-dev` | Generates local development config, policy, seed users, and optional sister-product smoke assets. |
| `qid-worker` | Runs audit retention, WORM archive, SIEM delivery, notification, directory sync, and key rotation planning jobs. |
| `qid-sync` | Runs lifecycle synchronization helpers for HR, LDAP/AD, dynamic groups, nested groups, and manager chains. |
| `qid-agent` | Registers endpoint device posture and workload identities. |
| `qid-migrate` | Plans and applies SQL database migrations. |
| `cargo xtask` | Runs repository structure, budget, coverage, and quality gate tasks. |

## Quick Start

Generate local development files:

```sh
cargo run --bin qid-dev -- dev-init --output target/qid-dev --force
```

Validate the generated configuration:

```sh
cargo run --bin qidc -- --config target/qid-dev/qid.yaml check
```

Seed test users:

```sh
cargo run --bin qid-dev -- seed-users --config target/qid-dev/qid.yaml --input target/qid-dev/users.seed.json
```

Start the daemon:

```sh
cargo run --bin qidd -- --config target/qid-dev/qid.yaml
```

From another terminal, check health and discovery:

```sh
curl -fsS http://127.0.0.1:8443/health
curl -fsS http://127.0.0.1:8443/realms/dev/.well-known/openid-configuration
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/README.md](docs/README.md) | Documentation index. |
| [docs/architecture.md](docs/architecture.md) | Product boundary, runtime planes, workspace structure, startup flow, and protocol surfaces. |
| [docs/configuration.md](docs/configuration.md) | Canonical `QidConfig`, deployment profiles, validation rules, and PEP registration model. |
| [docs/cli.md](docs/cli.md) | `qidd`, `qidc`, and companion binary reference. |
| [docs/http-api.md](docs/http-api.md) | Implemented HTTP route index. |
| [docs/operations.md](docs/operations.md) | Startup, migrations, key material, audit, metrics, backup/restore, and workers. |
| [docs/security.md](docs/security.md) | Security boundaries, fail-closed behavior, credentials, keys, admin controls, SCIM, PEP trust, and metrics. |
| [docs/development.md](docs/development.md) | Build, test, gates, fuzzing, and sample validation workflow. |
| [config/README.md](config/README.md) | Use-case-oriented configuration samples. |
| [fuzz/README.md](fuzz/README.md) | Fuzz target instructions. |

## Configuration Samples

`config/usecases/` contains YAML samples organized by deployment goal. Each sample is intended to be a standalone `QidConfig` document that can be validated with `qidc --config <file> check`.

```sh
scripts/check-config-samples.sh
```

Start with `config/usecases/01-getting-started/`. For immediate local inspection, use `config/usecases/01-getting-started/local-dev.yaml`.

## Development Commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo doc --workspace --locked --no-deps
cargo run -p xtask -- gate baseline
```

See [docs/development.md](docs/development.md) for the full development workflow.

## Storage

`qid-storage` switches between a file-backed JSON store and SQL backends through `AnyRepository`.

- URLs starting with `sqlite:` or `postgres:` use SQL.
- Any other value is treated as a file-backed JSON store path.
- `qidd` runs SQL migrations when it connects to a SQL backend.

## License

The workspace package license is `MIT`.
