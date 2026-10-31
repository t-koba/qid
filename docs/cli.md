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
| `admin` | Deployment-local Admin membership grants (no session or elevation). |
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

A realm the configuration declares belongs to the configuration: the daemon serves it with the issuer the configuration names and refuses to start when the stored issuer differs. The command therefore refuses an `--issuer` the configuration does not name, and it does not change the issuer of a realm that is already in the repository.

### qidc client

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--client-id`, `--secret`, `--redirect-uri`, `--client-type confidential|public` |
| `list` | `--realm` |
| `delete` | `--realm`, `--id` |

`create` writes the client to the repository. The realm must be in the repository, and a client id the configuration declares belongs to the configuration - the daemon serves that client from the configuration and refuses to start when the stored record differs - so the command refuses such a client id, and it refuses a client id the realm already holds.

`delete` requires both `--realm` and the internal client `--id`. Storage deletes only when both match; a missing ID or a client in another realm remains a no-op.

### qidc user

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--email`, `--password`, `--display-name` |
| `list` | `--realm` |
| `get` | `--id` |
| `delete` | `--id` |

`create` writes the user and its password credential to the repository. The credential is hashed with the Argon2id calibration of the realm, so `--realm` must name a realm the configuration declares; a realm the configuration does not declare is refused by name rather than hashed with a cost the product chose on the operator's behalf. The realm is written to the repository when it is not there yet, with the issuer the configuration names, so the user belongs to a realm the daemon serves.

### qidc admin

Run this only with deployment-local operator access to the configured repository:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml admin grant \
  --realm corp \
  --subject '<existing-user-id>' \
  --roles realm.admin,auditor \
  --reason 'Approved initial Admin provisioning'
```

All four options are required. `--subject` is an existing qid user ID in the explicit
configured realm, not an email address. The realm must already be stored with its
configured issuer and a persisted tenant binding. An explicit configured `tenant_id`
must match storage; absent `tenant_id` preserves the stored binding. This command
never seeds or reassigns a realm, creates a user, or automatically promotes anyone.

`--roles` accepts a comma-separated list or repeated options and **replaces** membership
roles, without implicitly adding any. The existing Admin vocabulary is `tenant.owner`,
`realm.admin`, `app.admin`, `directory.admin`, `security.admin`, `auditor`,
`platform.admin`, `platform.security.admin`, `platform.auditor`, and `breakglass`.
Unknown/blank roles, an empty list, and a blank reason are refused. Granting a role
does not change its authorization policy (including the configured breakglass gate).
Same-owner updates preserve the Admin ID and creation timestamp. Successful output
is the stored Admin as JSON, not an authentication credential.

The command stores a required `admin.grant.intent` audit with actor
`qidc:local-operator` (a local-access label, not an authenticated end-user identity),
the reason, realm, tenant, subject, target Admin ID, and exact requested roles **before**
calling `upsert_admin`. If the audit append fails, no Admin upsert is attempted.
These are separate repository writes, not a transaction: if the later upsert fails,
the intent audit remains and does not prove a successful grant. A File persistence
error may also leave the failing write's in-memory mutation; an audit failure still
prevents reaching the Admin write. Inspect the stored membership after an error;
there is no rollback or fabricated success audit.

This is provisioning only: it creates no browser session or `AdminElevation`, accepts
no ACR/AMR/session proof, and supplies no authentication evidence. The user must still
sign in and meet the existing Admin step-up/authorization policy through the normal
server flow. No server/Admin API is changed.

### qidc session

| Subcommand | Key options |
| --- | --- |
| `create` | `--realm`, `--user-id`, `--absolute-hours`, `--idle-minutes` |
| `revoke` | `--session-id` |

### qidc totp

| Subcommand | Key options |
| --- | --- |
| `enroll` | `--user-id` |

`enroll` writes a TOTP credential for an existing user whose realm is declared in the loaded configuration and offers the TOTP factor (`authentication.mfa.totp.enabled`). An unknown user, a realm absent from the configuration, or a realm that does not enable TOTP refuses the enrolment. A repository realm record alone does not configure the realm or its authentication policy; declare it in the configuration selected by `--config` before enrolling.

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

SIEM and notification delivery send HTTPS requests by default. Add `--dry-run` to record a prepared request without sending; dry runs report `skipped_dry_run`, and SIEM entries remain pending. `--request-output` writes a local copy of the request; protect that file because notification payloads may contain personal data. The default network timeout is 10 seconds (`--timeout-seconds`), and redirects are not followed. For `notification-deliver`, `--provider` is the HTTPS endpoint URL accepting the JSON request, unless it selects SMTP delivery (see below).

| Command | Purpose |
| --- | --- |
| `audit-retention-evaluate` | Evaluate retention and optionally record an audit event. |
| `audit-retention-execute` | Archive when required and report purge-ready IDs; optionally attach a verified RFC 3161 timestamp. |
| `audit-worm-archive` | Export recent audit events to a local append-only archive directory; optionally attach a verified RFC 3161 timestamp. |
| `audit-siem-deliver` | Send a SIEM webhook to an HTTPS endpoint; `--dry-run` records without sending. |
| `audit-siem-redrive` | Redrive a persistent SIEM delivery queue entry. |
| `notification-deliver` | Send email or push notification to an HTTPS endpoint, or send email via SMTP when `--provider` is `smtp(s)://`; `--dry-run` records without sending. |
| `push-cleanup` | Delete a bounded batch of expired push records and OIDC authorization continuations; schedule repeated invocations externally. |
| `directory-sync` | Synchronize a configured directory provider. |
| `key-rotation-plan` | Plan key rotation and optionally record an audit event. |
| `key-rotation-execute` | Execute supported key rotation actions from a plan JSON file. |

`notification-deliver` sends email through SMTP when `--provider` is an `smtp://host[:port]`
(STARTTLS, default port 587) or `smtps://host[:port]` (implicit TLS, default port 465)
URL. Only `email` notifications are accepted over SMTP, and TLS is always required:
there is no plaintext mode, and credentials, query strings, fragments and paths are
rejected in the provider URL. The sender and credentials come only from the runtime
environment: `QID_SMTP_FROM` (required sender address) and `QID_SMTP_USERNAME` plus
`QID_SMTP_PASSWORD` (both set for authenticated relay, or both unset). SMTP delivery
requires the `smtp-transport` build (`cargo run --features smtp-transport ...`); without
it, an `smtp(s)://` provider fails with a clear error instead of attempting HTTPS.
`--request-output` is echoed but no request body is written for SMTP sends.

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

cargo run --bin qid-worker -- --config /etc/qid/qid.yaml push-cleanup --limit 100
```

`push-cleanup` is a one-shot command. The external scheduler must run it
repeatedly; qid does not schedule cleanup itself. `--limit` bounds each of the
push-record and OIDC-continuation cleanup batches independently (default `100`,
allowed `1..=1000`).

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
| `workload-register` | Register a SPIFFE-aware workload identity; registering the same SPIFFE ID again updates it and keeps every field the command does not state. |
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
