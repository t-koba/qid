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
| `keys` | Local signing key encryption, status, and successor generation helpers. |

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

`create` writes the realm to the repository. The product serves the realms the configuration declares, so the command reports a realm that the configuration does not declare: declare it in the configuration file to serve it and to create users in it.

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

`create` writes the user and its password credential to the repository. The credential is hashed with the Argon2id calibration of the realm, so `--realm` must name a realm the configuration declares; a realm the configuration does not declare is refused by name rather than hashed with a cost the product chose on the operator's behalf.

### qidc session

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--user-id`, `--absolute-hours`, `--idle-minutes` |
| `revoke` | `--session-id` |

### qidc totp

| Subcommand | Key options |
| --- | --- |
| `enroll` | `--user-id` |

`enroll` writes a TOTP credential for an existing user of a realm that offers the TOTP factor (`authentication.mfa.totp.enabled`). A realm that does not enable TOTP refuses the enrolment, and so does an unknown user.

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
| `siem-dlq-list` | List persistent SIEM delivery queue entries. |
| `siem-dlq-redrive` | Move a SIEM delivery back to pending for redrive. |

Example:

```sh
cargo run --bin qidc -- --config config/qid.example.yaml ops check
cargo run --bin qidc -- --config config/qid.example.yaml ops siem-dlq-list --status dead
cargo run --bin qidc -- --config config/qid.example.yaml ops siem-dlq-redrive --id <delivery-id>
```

### qidc keys

Use `QID_KEY_PASSPHRASE` or `--passphrase-file` for commands that write encrypted private keys.

| Subcommand | Purpose |
| --- | --- |
| `encrypt` | Encrypt a plaintext PEM private key to `.pem.enc`. |
| `status` | Inspect whether a key file is encrypted and print metadata. |
| `rotate` | Generate an encrypted successor key plus public PEM and public JWK files. |

Examples:

```sh
cargo run --bin qidc -- keys encrypt \
  --input qid-state/signing-key.pem \
  --kid default \
  --alg ES256 \
  --passphrase-file /etc/qid/key.passphrase

cargo run --bin qidc -- keys status --key qid-state/signing-key.pem.enc

cargo run --bin qidc -- keys rotate \
  --output-dir qid-state/rotation \
  --keyring default \
  --alg ES256 \
  --passphrase-file /etc/qid/key.passphrase
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
| `audit-retention-execute` | Archive when required and report purge-ready IDs; optionally attach a verified RFC 3161 timestamp. |
| `audit-worm-archive` | Export recent audit events to a local append-only archive directory; optionally attach a verified RFC 3161 timestamp. |
| `audit-siem-deliver` | Build and deliver a SIEM webhook payload through deterministic local transport. |
| `audit-siem-redrive` | Redrive a persistent SIEM delivery queue entry. |
| `notification-deliver` | Deliver email or push notification through deterministic local transport. |
| `directory-sync` | Synchronize a configured directory provider. |
| `key-rotation-plan` | Plan key rotation and optionally record an audit event. |
| `key-rotation-execute` | Execute supported key rotation actions from a plan JSON file. |

Example:

```sh
cargo run --bin qid-worker -- --config target/qid-dev/qid.yaml audit-retention-evaluate \
  --realm dev \
  --actor qid-worker \
  --reason "scheduled retention evaluation"

cargo run --bin qid-worker -- --config target/qid-dev/qid.yaml key-rotation-execute \
  --plan-json target/qid-dev/key-rotation-plan.json \
  --output-dir target/qid-dev/rotation \
  --passphrase-file /etc/qid/key.passphrase
```

## qid-sync

`qid-sync` is a lifecycle synchronization helper.

| Command | Purpose |
| --- | --- |
| `hr-import` | Import HR joiner/mover/leaver records from JSON; duplicate or ambiguous identities conflict. |
| `ldap-sync` | Synchronize LDAP/AD directory entries from JSON (requires `--provider-id`; IDs must stay stable, `externalId` remains the raw DN). |
| `deprovision-sla` | Audit leaver deprovisioning SLA from JSON events (optional `provider_id` disambiguates shared DNs; ambiguous legacy events conflict). |
| `dynamic-group-sync` | Synchronize a dynamic group from a JSON rule. |
| `expand-group` | Expand nested SCIM group membership. |
| `manager-chain` | Resolve a user's manager chain. |

`hr-import` accepts a JSON array of lifecycle records. An `external_id` may
appear only once per batch; repeated keys and identities matching multiple
realm users fail during preflight before writes. Missing leaver targets are
also rejected before the first write. For mover records, an omitted or `null`
`department` or `manager_external_id` clears the stored organizational
attribute; non-null values set it. On joiner/leaver records, omitted or `null`
values preserve the stored attribute. Preflight prevents deterministic input
errors from causing prefix writes, but storage failures after preflight are not
transactional and may leave earlier writes applied.

Each `deprovision-sla` input element is a JSON object such as:

```json
{ "external_id": "uid=leaver,ou=people,dc=example,dc=com", "occurred_at": 1710000000, "provider_id": "ad-main" }
```

`provider_id` is optional for backward compatibility: old event files without
it still parse and audit uniquely-owned identities unchanged. When several
realm users share one raw `external_id` across directory providers, a legacy
event without `provider_id` fails with a conflict telling the caller to repeat
the audit with an explicit `provider_id`; scoped events match only the
server-owned `directory_provider_id` plus `external_id` (blank IDs are
rejected).

## qid-agent

`qid-agent` writes endpoint and workload identity records to the configured repository.

| Command | Purpose |
| --- | --- |
| `device-register` | Register/update endpoint posture for a user device. |
| `device-heartbeat` | Update last-seen timestamp for a device. |
| `devices` | List devices for a user. |
| `workload-register` | Register a SPIFFE-aware workload identity. |
| `workloads` | List workload identities for a realm. |
| `workload-delete` | Delete a workload identity of a realm by ID. |

`workload-delete` takes the owning realm as well as the identity ID; deleting
an identity that belongs to another realm, or an unknown ID, reports that the
identity was not found.

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
| `budget` | Enforce configured per-crate and total product-source line budgets; report test lines separately without capping them. |
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

`budget` reads the documented defaults and per-crate overrides from
`[workspace.metadata.budget]` in the workspace `Cargo.toml`. It applies limits to
product source and reports recognized test files separately as uncapped; mixed source
files with inline `#[cfg(test)]` modules remain in the source count. See
[development budget policy](development.md#repository-gates) for the counting
rules and change process.
