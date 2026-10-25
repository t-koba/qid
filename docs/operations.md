# Operations

This guide focuses on running `qidd` and companion tools safely. Operationally, qid is the identity and control plane: it owns identity data, sessions, tokens, lifecycle, policy decisions, audit, and profile gates. Proxies, gateways, service meshes, and PEPs remain separate data planes.

OAuth authorization codes and pushed authorization requests default to 300 seconds. Device authorization codes default to 1800 seconds. Operators upgrading from older configurations that relied on longer implicit lifetimes should set the realm `protocols.oauth.tokens.*_ttl_seconds` values explicitly.

## Startup Checklist

Before starting `qidd`:

1. Validate the config with `qidc check`.
2. Confirm `server.listen` and `server.public_base_url`.
3. Confirm `observability.metrics.listen` is loopback.
4. Confirm storage URL and migration readiness.
5. Confirm `qid-state/` parent directory is writable and protected.
6. Confirm profile-specific requirements, especially PEP, SCIM, SAML, FAPI, workload, network AAA, VC, or high assurance.
7. Confirm PEP registrations are enabled only for realms that should expose PEP routes.

Commands:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml check
cargo run --bin qidc -- --config /etc/qid/qid.yaml plan
cargo run --bin qidd -- --config /etc/qid/qid.yaml
```

## Declarative Seed Behavior

`qidd` seeds configured realms, static clients, and local policy bundles into storage.

Behavior:

- Missing configured realm: created.
- Existing realm with same issuer: accepted.
- Existing realm with different issuer: startup fails.
- Missing configured static client: created.
- Existing static client matching config: accepted.
- Existing static client differing from config: startup fails.
- Missing configured policy bundle: created.
- Existing policy bundle with matching JSON/hash: accepted.
- Existing policy bundle differing from config: startup fails.

This is deliberate. qid will not silently overwrite persisted identity objects from config drift.

## Storage and Migration

Backend selection:

- `sqlite:*` or `postgres:*`: SQL backend.
- Any other path: file-backed JSON backend.

`qidd` runs SQL migrations during repository connect. For explicit migration planning:

```sh
cargo run --bin qid-migrate -- --database-url sqlite:target/qid.db --dry-run --json
cargo run --bin qid-migrate -- --database-url sqlite:target/qid.db
```

For Postgres, set `QID_DATABASE_URL` or pass `--database-url`.

PostgreSQL applies the shared versioned migrations with SQLite-only foreign-key `PRAGMA` directives omitted and SQLite epoch-time defaults translated to PostgreSQL expressions; the schema changes and recorded source checksums remain unchanged.

Storage diagnostics are a startup safety gate. A storage audit error means qid may not have verified realm, tenant, connector, SAML, OIDC, or SaaS object references; daemon preflight treats that as an error.

One SPIFFE ID names one workload identity in a realm. A database that already holds two workload identities with the same SPIFFE ID in one realm fails the migration that adds the unique index; remove the redundant identity before migrating.

A workload identity belongs to its realm: registration binds it to that realm, and listing and deletion are scoped to that realm, so one realm's identity cannot be read or removed by another realm's request. The SPIFFE ID names the identity inside its realm, so registering that SPIFFE ID again updates the identity rather than adding a second one.

## Shared Cache

Set `ops.cache.kind` to `redis` or `valkey` for every multi-instance deployment. The shared cache backs DPoP and JWT assertion replay guards, PEP decision cache entries, and browser session cache entries. `kind: disabled` is only appropriate for single-process deployments.

Operational behavior:

- Replay guards fail closed if the shared cache cannot atomically record a JTI or assertion replay key.
- PEP decision and browser session caches degrade to cache misses when the shared cache is unavailable.
- Browser sessions keep a short process-local L1 cache and write through to the shared cache; revocation deletes both layers on qid-managed revoke paths.
- File storage with Redis or Valkey cache is not multi-process safe; `qidd` warns at startup and SQL storage should be used for multi-instance deployments.

## Key Material

`qidd` stores generated local key material in `qid-state/` next to the primary config file.

Protect this directory as secret material:

- private signing keys are written here for local keyrings.
- workload CA private key is written here when generated.
- public keys are used for JWKS and PEP assertion verification.

Configured local keyrings produce deterministic filenames based on keyring name and algorithm. The default ES256 key uses `signing-key.pem` and `signing-key.pub.pem`.

Set `QID_KEY_PASSPHRASE` or `crypto.key_passphrase_file` to enable encrypted local signing key storage. With a passphrase configured, new local keys are written as `.pem.enc` files, and existing plaintext PEM files are migrated to `.pem.enc` with the original moved to `.bak`.

Before deleting a `.bak` plaintext key, verify daemon startup and JWKS publication with the encrypted key and make sure the encrypted file is included in backup/restore procedures. A lost passphrase makes the encrypted signing key unrecoverable.

Current daemon startup supports local signer transport. Remote signer config is validated, but `qidd` fails startup for `kms`, `hsm`, or `pkcs11` signer types until a transport is wired in.

## PEP Operations

PEP integration is a control-plane contract, not a proxy runtime embedded inside qid.

Operational rules:

- Keep `decision.fail_policy: deny` unless a registration explicitly owns fail-open for post-auth internal/storage errors; `edge-pep` always keeps `deny`.
- Keep assertion TTL short.
- Register each PEP audience explicitly.
- Enable replay protection for PEP credentials and assertions.
- Treat body-provided edge, route, realm, audience, and capability values as declarations to verify against the authenticated registration.
- Do not send raw request bodies to qid for ordinary policy decisions.
- Transfer selected headers only through explicit allowlists and redaction.
- Expect the PEP to revalidate mapped effects against local policy before enforcement.

When a PEP cannot reach qid, cannot authenticate, receives an invalid response, or maps an unsupported effect, the safe operational behavior is fail closed.

## Metrics and Logs

The daemon writes its logs in the format the configuration selects, `json` by default. It does not redact personally identifiable information from them. Configure:

```yaml
observability:
  logs:
    format: json
  metrics:
    listen: "127.0.0.1:9464"
```

### Optional OTLP tracing

Build the daemon with `cargo build -p qidd --features otel-otlp --locked` to
export spans using OTLP/gRPC (protobuf, not OTLP/HTTP). Export is **disabled by
default**, even in that build. Enable it only with an explicit collector URL:

```yaml
observability:
  tracing:
    endpoint: "http://127.0.0.1:4317"
    service_name: qidd
    scheduled_delay_ms: 5000
    export_timeout_ms: 3000
    max_queue_size: 2048
    max_export_batch_size: 512
```

All values other than `endpoint` above are their defaults. Omit `endpoint` (or
set it to null) to disable export. Setting it on a binary without `otel-otlp`
is a startup error, not a silently ignored option. The endpoint must be an
absolute `http` or `https` URL with a host and no credentials, query or fragment.
Use HTTP for a trusted local collector; HTTPS validates the server name and
certificate chain using the platform's normal certificate roots. There is no
insecure TLS mode. qidd selects the same AWS-LC crypto provider as its native
TLS server before initializing tracing, avoiding ambiguous dependency backend
selection. gRPC supplies its own service path; a URL path is not an
OTLP/HTTP ingestion path. Errors do not echo the endpoint or collector response.

`QID_OBSERVABILITY__TRACING__ENDPOINT` can supply the endpoint through the normal
qid configuration environment overlay. The validated qid endpoint and timeouts
are not overridden by `OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or the SDK's timeout variables. Other
exporter-level environment settings (such as OTLP headers/compression) retain
the upstream exporter's behavior; no authentication/propagation integration is
added by qid. Service name, batching, resource and sampling are owned by the qid
configuration/initializer, not the SDK environment defaults.

One subscriber writes existing JSON/text logs and exports spans, including the
HTTP middleware's `http_request` span and its child spans. `RUST_LOG` filters both
surfaces, defaulting to `info` when absent or invalid. In-process parent/child
trace linkage is preserved; roots are sampled and children respect their parent.
Arbitrary tracing log events (including error events) are **not** exported as
span events. Logs themselves are unchanged and are not redacted. No additional
request headers, query strings or bodies are attached to spans. Existing span
fields, including request IDs and paths, still need an appropriate collector
access/retention policy. Prometheus configuration and behavior are unchanged.

Export is best-effort, not an audit delivery guarantee: an unreachable collector
does not prevent startup or request handling. The SDK queues completed spans in
memory, exports on the delay or batch threshold, drops on queue overflow, and
discards failed/timed-out batches rather than persisting/retrying them. The queue
and batch sizes must be positive with batch <= queue; both durations must be
positive. One batch is exported at a time, with `export_timeout_ms` bounding both
transport and SDK export work. Tune these configuration values for the desired
memory/latency/loss tradeoff; periodic failures need collector-side monitoring.

On normal shutdown, and on returned startup/serve errors after initialization,
qidd explicitly flushes completed spans and shuts down the retained SDK provider
in `spawn_blocking` while Tokio is still running. This avoids blocking a
current-thread runtime and does not wait for the normal batch delay. Shutdown can
still take multiple export timeouts when draining a full queue; it is bounded by
the configured finite queue/batch work and per-export timeout. Flush/shutdown
failure returns a sanitized error if the daemon was otherwise successful; an
existing daemon error remains the primary error. Abrupt process termination or
spans still open at shutdown can lose spans.

HTTP request metrics include:

- `qid_http_requests_total`
- `qid_http_request_duration_seconds`

Hot-path control-plane metrics include:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `qid_token_issued_total` | `grant_type`, `realm` | Successful OAuth token responses. |
| `qid_token_issue_duration_seconds` | `grant_type`, `realm` | Token endpoint issuance latency. |
| `qid_login_failures_total` | `realm`, `reason` | Failed password login attempts by stable error code. |
| `qid_policy_decision_duration_seconds` | `realm` | Policy decision latency for PEP-facing checks. |
| `qid_audit_append_failures_total` | none | Admin audit append failures. |
| `qid_proxy_pep_decision_cache_hits_total` | none | PEP decision cache hits. |
| `qid_proxy_pep_decision_cache_misses_total` | none | PEP decision cache misses. |
| `qid_proxy_pep_decision_fail_open_total` | none | PEP decisions answered fail-open (`fail-open` allow, post-auth system error only). |

Metrics bind addresses must not be unspecified addresses such as `0.0.0.0:9464`. Metrics labels should remain low-cardinality and should not contain user IDs, email addresses, tokens, selected header values, or raw unbounded paths.

## Audit

Audit is represented in storage and can be exported or verified through admin routes and worker jobs.

Useful API groups:

- `/admin/api/v1/audit`
- `/admin/api/v1/:realm/audit`
- `/admin/api/v1/audit/export`
- `/admin/api/v1/:realm/audit/export`
- `/admin/api/v1/audit/verify`
- `/admin/api/v1/:realm/audit/verify`
- `/admin/api/v1/audit/retention`
- `/admin/api/v1/:realm/audit/retention`

Worker jobs:

```sh
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-retention-evaluate --realm corp
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-retention-execute --realm corp --archive-dir /var/lib/qid/audit-archive
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-worm-archive --realm corp --archive-dir /var/lib/qid/worm
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-siem-deliver --realm corp --endpoint-url https://siem.example.com/audit
```

For audit evidence that requires an independently trusted time, configure an RFC 3161 TSA and one or more PEM trust-anchor bundles:

```sh
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-worm-archive \
  --realm corp \
  --archive-dir /var/lib/qid/worm \
  --tsa-url https://tsa.example.com/timestamp \
  --tsa-ca /etc/qid/tsa/root-ca.pem
```

The worker hashes the JSONL audit body with SHA-256, sends a nonce-bearing RFC 3161 request, verifies the response imprint, nonce, CMS signature, time-stamping EKU, and certificate path, then archives the `.timestamp.tsr` response beside the body and version 2 manifest. TSA acquisition or verification failure aborts the archive job before any object is written. The current verifier accepts ECDSA TSA signing keys on P-256/P-384; configure a compatible TSA. The same TSA options are available on `audit-retention-execute`.

SIEM delivery posts to the configured HTTPS endpoint by default, with a 10-second timeout and redirects disabled. Use `--dry-run` only to capture a request without sending; it reports `skipped_dry_run` and leaves the queue entry pending. Notification `--provider` is likewise an HTTPS JSON endpoint URL.

SIEM delivery failures are persisted in `siem_delivery_queue`. Retryable failures stay `pending` with `next_retry_at`; exhausted failures become `dead` and can be inspected or redriven:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml ops siem-dlq-list --status dead
cargo run --bin qidc -- --config /etc/qid/qid.yaml ops siem-dlq-redrive --id <delivery-id>
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml audit-siem-redrive --id <delivery-id>
```

## Backup and Restore Helpers

Configure backups under `ops.backup`. Backup enabled requires:

- `object_store_uri`
- `migration_version`

Generate a manifest:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml ops backup-manifest \
  --object users:/backups/users.json \
  --object clients:/backups/clients.json
```

Plan restore:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml ops restore-plan \
  --manifest manifest.json \
  --target-cluster-id prod-a
```

Dry-run restore execution:

```sh
cargo run --bin qidc -- --config /etc/qid/qid.yaml ops restore-execute \
  --manifest manifest.json \
  --target-cluster-id prod-a \
  --source-dir /backups \
  --target-dir /restore \
  --dry-run
```

## Emergency Read-Only

`ops.emergency.read_only` is used by restore planning and execution. Set it when the cluster should refuse operational writes at the orchestration layer.

```yaml
ops:
  emergency:
    read_only: true
```

## Push Challenge and OIDC Continuation Cleanup

`qid-worker push-cleanup` is a one-shot, bounded cleanup operation. Configure an
external scheduler to invoke it repeatedly with the current QID configuration;
QID does not schedule the command. Each invocation deletes at most `--limit`
expired push records and at most `--limit` expired OIDC authorization
continuations (default `100`, range `1..=1000`). Pending push records remain
available through the maximum quota-retention horizon: login rows are retained
until immutable expiry is strictly older than 86400 seconds, so resent sends
cannot disappear from a rolling quota early. Pending registrations retain the
original-issuance horizon and must also be expired. Enrolled and revoked
authenticator records are retained. Expired OIDC continuations, including
consumed records, are deleted in bounded batches. Without the external schedule,
expired OIDC request context remains stored until cleanup is run.

```sh
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml push-cleanup --limit 100
```

## Directory Synchronization

`sync_interval_minutes` is a requested per-provider cadence for an operator-owned
scheduler, not a QID timer. List providers with the authenticated
`GET /directory/v1/providers?realm=<realm>` route and read each enabled,
syncable pull provider's cadence from
`GET /directory/v1/providers/<id>?realm=<realm>`. The scheduler must
periodically re-read provider details and reconcile timers after configuration
changes; schedule each provider at its returned interval, and do not schedule
a provider whose interval is `null`. A hard-coded cron interval cannot honor
per-provider changes. QID does not enqueue, track, or lock periodic jobs; HTTP
`/sync` and `/sync/status` remain unsupported. The external scheduler must
enforce single-flight per `(realm, provider_id)`, including across scheduler
instances.

For LDAP/Active Directory, sequential replay of the same provider snapshot
updates matching provider-owned users and reports unchanged rows; this does not
make overlapping runs safe. A CSV provider rereads the whole configured HR
file on every invocation and has no persisted file cursor or cross-run receipt.
The scheduler/operator must supply fresh, unconsumed lifecycle rows or rotate
its input; replayed CSV rows can apply lifecycle actions again. Duplicate
`external_id` values within one CSV batch are rejected before any write.

For a one-shot sync, use `qid-worker directory-sync` with the configured
provider. The worker reads provider settings from its `--config` file, so use
the current QID configuration for the same realm. A non-mutating directory
sync plan is not supported; `--dry-run` is refused before provider lookup or
storage writes rather than risking a mutating preview:

```sh
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml directory-sync \
  --realm corp \
  --provider-id ad-main
```

A normal JSON report has status `completed`, `skipped_disabled`, or `failed`;
`failed` exits nonzero, while a disabled provider or directory reports
`skipped_disabled` and exits zero. Configuration, connector, or storage errors
can abort with a nonzero exit before a JSON report exists. Audit append errors
are included in `report.errors` even when the sync itself completed, so capture
the report and inspect both exit status and errors. The HTTP status route does
not provide job state; the external scheduler owns its run history.

For JSON-based lifecycle testing or one-off sync, `--provider-id` must remain stable for the directory provider. LDAP rows retain the raw DN as SCIM `externalId` and record ownership in the internal server-owned `directory_provider_id` (never in `enterprise_json`, which SCIM clients can forge). Existing rows without an owner need explicit internal migration; ownership is never inferred from `enterprise_json`, even with a single provider. SCIM clients cannot change or remove `externalId` on provider-owned users. An unowned row whose `externalId` collides with an incoming DN fails the sync with a conflict before any write; unrelated ownerless rows do not block sync.

```sh
cargo run --bin qid-sync -- --config /etc/qid/qid.yaml hr-import --realm corp --input hr.json
cargo run --bin qid-sync -- --config /etc/qid/qid.yaml ldap-sync --realm corp --provider-id ad-main --input ldap.json --deactivate-missing
```

## Network AAA

`network-aaa` profile starts UDP/TCP listeners in addition to HTTP:

- RADIUS authentication
- RADIUS accounting
- RADIUS CoA
- RADIUS/TLS

RADIUS/DTLS is not implemented. This includes RFC 7360 and DTLS 1.3 from RFC 9147; `qid-network` does not expose a UDP DTLS transport or configuration placeholder.

RFC 9966 TLS-POK is available through the `qid-network` `tls-pok` feature. `TlsPokTeapServerSession` accepts strict TEAP version 1 fragments, acknowledges incomplete inbound flights, fragments outbound TLS records, and completes a TLS 1.3 handshake using the RFC 9258 imported PSK. The TLS engine negotiates RFC 9973 `tls_cert_with_extern_psk` (which obsoletes RFC 8773), requests an RFC 7250 client Raw Public Key, and binds that key to the BSK selected by the imported identity inside the same handshake. RFC 9973 requires the peer ClientHello to include `key_share`, `supported_groups`, `psk_key_exchange_modes`, and `pre_shared_key`; the patched Rustls client path includes these extensions and offers only `psk_dhe_ke`, which qid's server requires. The TLS 1.3 key schedule uses the corrected order: `Early Secret = HKDF-Extract(0, external PSK)`, with ECDHE incorporated into the Handshake Secret later. These are audited behaviors, not a claim of full RFC 9973 conformance. Registration must supply exactly one supported compressed-point EC SubjectPublicKeyInfo for each NAI; any identity, binder, or public-key mismatch terminates the handshake.

Required configuration includes bind addresses, TLS certificate/key/client CA paths, shared secret, and enabled directory authority. The RADIUS authorizer currently accepts subjects present in the repository user list; when EAP-TLS is required, the request must include EAP evidence.

## Sister-Product Smoke

`examples/qpx-e2e/run.sh` is a development smoke for one concrete qpx sister-product PEP registration flow.

The script requires a compatible `qpxd`, starts `qidd`, creates a test subject/session, gets a client credentials token, fetches a PEP assertion, and exercises fail-closed JWT validation, AuthZEN authorization, and RFC 7662 introspection through qpx. It fails before starting services if either qpx configuration is invalid or the qpx binary is unavailable.

```sh
bash examples/qpx-e2e/run.sh
```

Useful environment variables:

- `QID_QPX_E2E_TMP_DIR`: use a fixed temp directory.
- `QID_QPX_E2E_KEEP_TMP=1`: keep temp files.
- `QPXD_BIN`: path to qpxd binary; defaults to `../qpx/target/debug/qpxd` relative to the qid repository.
