# CLI Reference

Examples are run from the repository root. Replace `cargo run --bin <name> --` with an installed binary in packaged deployments.

The CLI surfaces operate the qid control plane: config validation, identity data, sessions, policy explanation, lifecycle helpers, operations, and development fixtures. They do not operate a proxy data plane.

## qidd

`qidd` is the identity/control daemon.

```sh
cargo run --bin qidd -- --config /etc/qid/qid.yaml
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-c, --config <path>` | `/etc/qid/qid.yaml` | Config file. May be repeated; later files override earlier files. |

At startup, `qidd` validates config, builds diagnostics, opens storage, seeds configured realms/clients/policy bundles, initializes signing material, installs enabled control-plane routes, and binds `server.listen`.

## qidc

`qidc` is the control CLI.

Global option:

| Option | Default | Meaning |
| --- | --- | --- |
| `-c, --config <path>` | `/etc/qid/qid.yaml` | Config file. May be repeated. |

Top-level commands:

| Command | Purpose |
| --- | --- |
| `check` | Validate config, runtime plan, diagnostics, and storage SaaS checks. Emits JSON. |
| `plan` | Print the compiled `RuntimePlan`. |
| `realm` | Create/list/get/delete realms. |
| `client` | Create/list/delete clients. |
| `user` | Create/list/get/delete users and password credentials. |
| `session` | Create/revoke browser sessions. |
| `totp` | Enroll TOTP credentials. |
| `explain` | Explain a policy/risk decision from CLI inputs. |
| `ops` | Operational readiness, backup/restore, cache key, key rotation helpers. |

Examples:

```sh
cargo run --bin qidc -- --config target/qid-dev/qid.yaml check
cargo run --bin qidc -- --config target/qid-dev/qid.yaml plan

cargo run --bin qidc -- --config target/qid-dev/qid.yaml user create \
  --realm dev \
  --email alice@example.com \
  --password qid-dev-alice-password \
  --display-name Alice

cargo run --bin qidc -- --config target/qid-dev/qid.yaml session create \
  --realm dev \
  --user-id <user-id>
```

### qidc realm

| Subcommand | Key options |
| --- | --- |
| `create` | `--id`, `--issuer`, `--display-name` |
| `list` | none |
| `get` | `--id` |
| `delete` | `--id` |

### qidc client

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--client-id`, `--secret`, `--redirect-uri`, `--client-type confidential|public` |
| `list` | `--realm` |
| `delete` | `--id` |

### qidc user

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--email`, `--password`, `--display-name` |
| `list` | `--realm` |
| `get` | `--id` |
| `delete` | `--id` |

### qidc session

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--user-id`, `--absolute-hours`, `--idle-minutes` |
| `revoke` | `--session-id` |

### qidc totp

| Subcommand | Key options |
| --- | --- |
| `enroll` | `--user-id` |

### qidc explain

`explain` builds a policy/risk input from flags. For PEP scenarios, it explains the qid-owned decision context and PEP registration.

Common flags:

- `--realm`
- `--subject`
- `--resource-host`
- `--action`
- `--pep-registration`
- `--destination-category`
- `--destination-reputation known-good|unknown|suspicious|malicious`
- `--device-trust managed|registered|unknown|unmanaged|compromised`
- `--anonymous-network`
- `--high-risk-asn`
- `--phishing-resistant-mfa`
- `--sender-constrained-token`
- `--token-age-seconds`
- `--auth-age-seconds`
- `--acr`
- `--amr`
- `--format`

### qidc ops

| Subcommand | Purpose |
| --- | --- |
| `check` | Print cache/cluster/backup/emergency readiness JSON. |
| `backup-manifest` | Build a manifest for exported objects. |
| `restore-plan` | Plan restore from a manifest. |
| `restore-execute` | Execute local restore with optional dry-run. |
| `cache-key` | Render a non-PII cache key for a namespace/material pair. |
| `key-rotation-plan` | Plan key rotation from inventory and requirements. |
| `key-rotation-check` | Inspect local state directory and keyring rotation requirements. |

Example:

```sh
cargo run --bin qidc -- --config config/qid.example.yaml ops check
```

## qid-dev

`qid-dev` creates local development fixtures and seeds users.

| Command | Purpose |
| --- | --- |
| `dev-init` | Generate `qid.yaml`, `policy.json`, `users.seed.json`, optional sister-product smoke assets, and a README under an output directory. |
| `seed-users` | Seed test users from JSON into configured storage. |
| `qpx-smoke` | Run the qpx sister-product integration smoke script. |

Examples:

```sh
cargo run --bin qid-dev -- dev-init --output target/qid-dev --force
cargo run --bin qid-dev -- seed-users --config target/qid-dev/qid.yaml --input target/qid-dev/users.seed.json
cargo run --bin qid-dev -- qpx-smoke
```

## qid-worker

`qid-worker` runs operational jobs and emits JSON.

| Command | Purpose |
| --- | --- |
| `audit-retention-evaluate` | Evaluate retention and optionally record an audit event. |
| `audit-retention-execute` | Archive when required and report purge-ready IDs. |
| `audit-worm-archive` | Export recent audit events to a local append-only archive directory. |
| `audit-siem-deliver` | Build and deliver a SIEM webhook payload through deterministic local transport. |
| `notification-deliver` | Deliver email or push notification through deterministic local transport. |
| `directory-sync` | Synchronize a configured directory provider. |
| `key-rotation-plan` | Plan key rotation and optionally record an audit event. |

Example:

```sh
cargo run --bin qid-worker -- --config target/qid-dev/qid.yaml audit-retention-evaluate \
  --realm dev \
  --actor qid-worker \
  --reason "scheduled retention evaluation"
```

## qid-sync

`qid-sync` is a lifecycle synchronization helper.

| Command | Purpose |
| --- | --- |
| `hr-import` | Import HR joiner/mover/leaver records from JSON. |
| `ldap-sync` | Synchronize LDAP/AD directory entries from JSON. |
| `deprovision-sla` | Audit leaver deprovisioning SLA from JSON events. |
| `dynamic-group-sync` | Synchronize a dynamic group from a JSON rule. |
| `expand-group` | Expand nested SCIM group membership. |
| `manager-chain` | Resolve a user's manager chain. |

## qid-agent

`qid-agent` writes endpoint and workload identity records to the configured repository.

| Command | Purpose |
| --- | --- |
| `device-register` | Register/update endpoint posture for a user device. |
| `device-heartbeat` | Update last-seen timestamp for a device. |
| `devices` | List devices for a user. |
| `workload-register` | Register a SPIFFE-aware workload identity. |
| `workloads` | List workload identities for a realm. |
| `workload-delete` | Delete workload identity by ID. |

Example:

```sh
cargo run --bin qid-agent -- --config target/qid-dev/qid.yaml device-register \
  --realm dev \
  --user-id <user-id> \
  --device-name laptop \
  --posture disk_encrypted \
  --posture os_updated
```

## qid-migrate

`qid-migrate` handles SQL migrations.

| Option | Meaning |
| --- | --- |
| `-d, --database-url <url>` | Database URL. Can also come from `QID_DATABASE_URL`. |
| `--dry-run` | Print migration plan without applying migrations. |
| `--json` | Emit a JSON plan. |

Examples:

```sh
cargo run --bin qid-migrate -- --database-url sqlite:target/qid.db --dry-run --json
cargo run --bin qid-migrate -- --database-url sqlite:target/qid.db
```

## cargo xtask

The `xtask` package exposes repository maintenance commands through the `cargo-xtask` binary.

| Command | Purpose |
| --- | --- |
| `structure` | Verify workspace package layout. |
| `budget` | Enforce per-crate and total Rust line-count budgets. |
| `gate <suite>` | Run quality/conformance/assurance/preflight/release gates. |
| `coverage` | Run the coverage gate through `scripts/coverage.sh`. |

Gate suites:

- `baseline`
- `conformance`
- `assurance`
- `preflight`
- `release`

Examples:

```sh
cargo run -p xtask -- gate baseline --dry-run
cargo run -p xtask -- gate baseline
cargo run -p xtask -- structure
cargo run -p xtask -- budget
```
