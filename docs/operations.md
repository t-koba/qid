# Operations

This guide focuses on running `qidd` and companion tools safely. Operationally, qid is the identity and control plane: it owns identity data, sessions, tokens, lifecycle, policy decisions, audit, and profile gates. Proxies, gateways, service meshes, and PEPs remain separate data planes.

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

Storage diagnostics are a startup safety gate. A storage audit error means qid may not have verified realm, tenant, connector, SAML, OIDC, or SaaS object references; daemon preflight treats that as an error.

## Key Material

`qidd` stores generated local key material in `qid-state/` next to the primary config file.

Protect this directory as secret material:

- private signing keys are written here for local keyrings.
- workload CA private key is written here when generated.
- public keys are used for JWKS and PEP assertion verification.

Configured local keyrings produce deterministic filenames based on keyring name and algorithm. The default ES256 key uses `signing-key.pem` and `signing-key.pub.pem`.

Current daemon startup supports local signer transport. Remote signer config is validated, but `qidd` fails startup for `kms`, `hsm`, or `pkcs11` signer types until a transport is wired in.

## PEP Operations

PEP integration is a control-plane contract, not a proxy runtime embedded inside qid.

Operational rules:

- Keep `decision.fail_policy: deny`.
- Keep assertion TTL short.
- Register each PEP audience explicitly.
- Enable replay protection for PEP credentials and assertions.
- Treat body-provided edge, route, realm, audience, and capability values as declarations to verify against the authenticated registration.
- Do not send raw request bodies to qid for ordinary policy decisions.
- Transfer selected headers only through explicit allowlists and redaction.
- Expect the PEP to revalidate mapped effects against local policy before enforcement.

When a PEP cannot reach qid, cannot authenticate, receives an invalid response, or maps an unsupported effect, the safe operational behavior is fail closed.

## Metrics and Logs

`qid_observability::init_logging(true)` initializes JSON-friendly logging. Configure:

```yaml
observability:
  logs:
    format: json
    redact_pii: true
  metrics:
    listen: "127.0.0.1:9464"
```

HTTP request metrics include:

- `qid_http_requests_total`
- `qid_http_request_duration_seconds`

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

## Directory Synchronization

For scheduled directory jobs, prefer `qid-worker directory-sync` when operating from configured providers:

```sh
cargo run --bin qid-worker -- --config /etc/qid/qid.yaml directory-sync \
  --realm corp \
  --provider-id ad-main
```

For JSON-based lifecycle testing or one-off sync:

```sh
cargo run --bin qid-sync -- --config /etc/qid/qid.yaml hr-import --realm corp --input hr.json
cargo run --bin qid-sync -- --config /etc/qid/qid.yaml ldap-sync --realm corp --input ldap.json --deactivate-missing
```

## Network AAA

`network-aaa` profile starts UDP/TCP listeners in addition to HTTP:

- RADIUS authentication
- RADIUS accounting
- RADIUS CoA
- RADIUS/TLS

Required configuration includes bind addresses, TLS certificate/key/client CA paths, shared secret, and enabled directory authority. The RADIUS authorizer currently accepts subjects present in the repository user list; when EAP-TLS is required, the request must include EAP evidence.

## Sister-Product Smoke

`examples/qpx-e2e/run.sh` is a development smoke for one concrete qpx sister-product PEP registration flow.

The script starts `qidd`, creates a test subject/session, gets a client credentials token, fetches a PEP assertion, and optionally starts `qpxd` if the binary is present.

```sh
bash examples/qpx-e2e/run.sh
```

Useful environment variables:

- `QID_QPX_E2E_TMP_DIR`: use a fixed temp directory.
- `QID_QPX_E2E_KEEP_TMP=1`: keep temp files.
- `QPXD_BIN`: path to qpxd binary.
- `QPX_STATE_DIR`: override qpx state directory.
