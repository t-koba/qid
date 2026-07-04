# Configuration

qid loads YAML or TOML into `qid_core::config::QidConfig`. Configuration is a canonical contract: unknown fields are rejected, profile obligations are explicit, and old aliases are not accepted for convenience.

The configuration model describes qid as an IdP, authorization server, lifecycle service, PDP, and provider-neutral PEP integration point.

## Loading Order

`QidConfig::from_files` accepts one or more paths.

1. Each file can declare `include`.
2. Includes are resolved relative to the including file.
3. Include cycles are rejected.
4. Earlier files and includes provide defaults.
5. Later files override earlier files.
6. Environment variables with the `QID_` prefix and `__` separators are merged through Figment.

Examples:

```sh
cargo run --bin qidc -- --config config/usecases/01-getting-started/minimal-oidc.yaml check
cargo run --bin qidc -- --config base.yaml --config prod.yaml plan
```

## Top-Level Keys

| Key | Required | Purpose |
| --- | --- | --- |
| `include` | no | Additional YAML/TOML files to merge before the current file. |
| `profile` | no | Deployment profile. Defaults to `oidc`. |
| `server` | yes | Listen address, public URL, TLS, paths, CORS, HTTP Message Signatures. |
| `admin` | no | Admin operation security policy. |
| `storage` | no | Primary repository and cache settings. |
| `crypto` | no | Default signing algorithm and keyrings. |
| `realms` | yes | Realm definitions. At least one realm is required. |
| `observability` | no | Logs, metrics, tracing, audit sink. |
| `ops` | no | Ops cache, cluster, backup, emergency read-only mode. |

## Profiles

`profile` can be one of:

- `oidc`
- `edge-pep`
- `enterprise`
- `fapi`
- `ciam`
- `workload`
- `high-assurance`
- `network-aaa`
- `vc`

Profiles are not marketing labels. They are validation bundles that make a deployment shape fail early when required security or protocol surfaces are missing.

| Profile | Required configuration |
| --- | --- |
| `oidc` | OIDC enabled, authorization code enabled, PKCE required for every realm. |
| `edge-pep` | Server HTTP Message Signatures, at least one enabled PEP registration realm, realm mTLS, required PEP capability effects, and `fail_policy=deny`. |
| `enterprise` | Passkeys, SCIM with a 32+ byte cursor secret, SCIM callback allowlist, SAML with signed assertions and signed XMLDSig metadata, at least one SAML SP, and an enabled LDAPS directory provider with bind credentials and TLS verification. |
| `ciam` | OIDC discovery/userinfo/auth code/PKCE, passkeys, FedCM, consent, progressive profile, identity proofing, privacy dashboard, and inbound federation with enabled provider, domains, account linking, and JIT provisioning. |
| `fapi` | HTTP Message Signatures, PAR, RAR, DPoP, mTLS, private_key_jwt, JARM, required PAR, signed request objects, JWT introspection, and sender-constrained or high-risk resource servers. |
| `vc` | All `fapi` requirements plus OID4VCI, OID4VP, HAIP, VC Data Model 2.0, JOSE/COSE, status list, holder binding, and issuer key reference. |
| `workload` | SPIFFE Workload API, X.509-SVID, JWT-SVID, short-lived credentials, RATS/EAT, OAuth token exchange, workload CA key reference, mTLS, and private_key_jwt. |
| `network-aaa` | RADIUS, RADIUS/TLS, EAP, EAP-TLS, CAPPORT, CoA, accounting, directory authority, mTLS, 16+ byte shared secret, bind addresses, TLS material paths, and an enabled directory provider. |
| `high-assurance` | All `fapi` requirements plus remote KMS/HSM/PKCS#11 keyrings, admin approval, admin step-up, backup enabled, passkeys, mTLS, and passwordless-only realms. |

## Server and Paths

`server.listen` must be a valid socket address. `server.public_base_url` must be a valid URL.

Important subkeys:

- `tls.cert` and `tls.key`: enable TLS in `qidd`.
- `http_message_signatures`: enables RFC 9421-style verification around signed back-channel routes.
- `cors.allowed_origins`: absolute HTTP(S) origins or `*`.
- `cors.allow_credentials`: cannot be combined with wildcard origin.
- `paths`: configurable canonical paths for health, discovery, OAuth, session auth, WebAuthn, PEP, logout, email magic link, and related endpoints.

Path values must start with `/`, must not be empty, and must be unique.

Selected default paths:

| Setting | Default |
| --- | --- |
| `health` | `/health` |
| `ready` | `/ready` |
| `jwks` | `/jwks` |
| `authorize` | `/oauth2/authorize` |
| `par` | `/oauth2/par` |
| `token` | `/oauth2/token` |
| `introspect` | `/oauth2/introspect` |
| `revoke` | `/oauth2/revoke` |
| `userinfo` | `/oidc/userinfo` |
| `assertion` | `/pep/:realm/assertion` |
| `pep_decision` | `/pep/decision/v1/evaluate` |
| `authzen_evaluation` | `/access/v1/evaluation` |

## Storage

`storage.primary` supports:

- `type`: defaults to `sqlite`.
- `url`: direct URL or file path.
- `url_env`: environment variable containing the URL.

The effective URL is `url`, then `url_env`, then the daemon default.

Backend selection:

- `sqlite:*` and `postgres:*` use SQL.
- Other values use file-backed JSON.

Redis/Valkey-style cache settings require endpoints, a non-empty key prefix, and a positive TTL when enabled.

## Crypto

`crypto.default_alg` must be `ES256`, `RS256`, or `EdDSA`. Local signer generation in `qidd` currently supports `ES256` and `EdDSA`.

`crypto.keyrings[]` fields:

- `name`: unique keyring name.
- `realm_id`: optional realm scoping.
- `purposes`: `oidc_token`, `saml_assertion`, `pep_assertion`, `audit_log`, `browser_session`, or `other:<name>`.
- `signer.type`: `local`, `kms`, `hsm`, or `pkcs11`.
- `signer.uri`: required for remote signer types.
- `signer.public_jwk`: required for remote signer types.
- `rotation.max_age_days` and `rotation.overlap_days`.

Remote signer JWKs must include `kty`, `kid`, and `alg`; `kid` must match the keyring name. RSA keys must be at least 2048 bits.

## Realms

Each realm requires:

- `id`: URL-safe path segment using `[A-Za-z0-9._~-]`.
- `issuer`: valid URL.

Optional realm fields include:

- `display_name`
- `tenant_id`
- `clients`
- `protocols`
- `authentication`
- `sessions`
- `pep_registrations`
- `policy`

When multiple realms are configured, each issuer must match:

```text
<server.public_base_url>/realms/<realm.id>
```

## Static Clients

`realms[].clients[]` supports:

- `client_id`
- `id`
- `client_type`: `public` or `confidential`
- `token_endpoint_auth_method`
- `client_secret` or `client_secret_hash`
- `mtls_certificate_thumbprints`
- `jwks`
- `redirect_uris`
- `grant_types`

Validation rules:

- `grant_types` must not be empty.
- `implicit` and `password` grants are forbidden.
- Public clients must use `token_endpoint_auth_method=none` and cannot declare secrets.
- Public clients cannot use `client_credentials`.
- Confidential clients using `client_secret_basic` or `client_secret_post` need a secret or hash.
- `private_key_jwt` clients need `jwks.keys`.
- mTLS clients need certificate thumbprints.
- Authorization code clients need redirect URIs.
- Redirect URIs cannot contain wildcards or fragments.
- Redirect URIs must use HTTPS, except localhost HTTP.

## Protocols

`realms[].protocols` contains:

| Section | Purpose |
| --- | --- |
| `oidc` | OIDC enablement, auth code, PKCE, request object policy, discovery, userinfo, logout, session management. |
| `oauth` | Introspection, revocation, PAR, RAR, DPoP, mTLS, device flow, CIBA, DCR, private_key_jwt, JARM, token TTL, resource servers. |
| `saml` | SAML IdP routes, metadata signing, assertion signing/encryption, SP registration, clock skew. |
| `scim` | SCIM base path, cursor secret, callback host allowlist, custom schemas. |
| `fedcm` | FedCM route surface. |
| `federation` | Inbound OIDC/SAML/social providers and claim mappings. |
| `directory` | LDAP/AD/SCIM/HR providers, sync filters, attribute mapping. |
| `ciam` | Consent, progressive profile, identity proofing, privacy dashboard. |
| `vc` | OID4VCI/OID4VP/HAIP/status/holder binding. |
| `workload` | SPIFFE, SVID, RATS/EAT, token exchange, CA key reference. |
| `network_aaa` | RADIUS/TLS/EAP/CAPPORT/CoA/accounting/directory authority. |

Boolean-like feature structs often accept either `true` / `false` or an object with `enabled`.

Example:

```yaml
oauth:
  dpop:
    enabled: true
    replay_cache: true
    nonce: false
```

## Authentication and Sessions

`authentication` includes:

- `passkeys.enabled`, `preferred`, `rp_id`, `rp_origin`, `rp_name`, `attestation`
- `password.enabled`, `hash`, `pepper_ref`, lockout settings, Argon2id cost
- `mfa.required_for_admins`, `allowed`, `totp`, `sms`, `client_certificate`
- `passwordless_only`

Validation rules:

- Weak OIDC implicit and ROPC flows are rejected.
- Authorization code requires PKCE.
- If `passwordless_only` is true, passkeys must be enabled.
- Otherwise, at least one of passkeys or password must be enabled.

`sessions` includes browser cookie name, SameSite, idle/absolute timeout, refresh token rotation, and reuse detection policy.

## PEP Registrations and Policy

`pep_registrations` declares external PEP identities that may receive qid assertions or call qid decision endpoints. A registration can represent qpx, Envoy, NGINX, HAProxy, a service mesh, an API gateway, a custom reverse proxy, or another enforcement component.

Important rules:

- Registration names must be unique per realm.
- Global PEP audiences must be unique.
- `decision.fail_policy` must be `deny`.
- Assertion TTL must not exceed 300 seconds.
- Enabled `edge-pep` deployments must have at least one enabled realm with registrations.
- The implemented `auth.active_method` is currently `bearer_jwt`.
- Body claims from a PEP are assertions to verify, not authentication truth.
- Credential-bound registration identity, audience, replay protection, and capability checks are the trusted basis.

Capabilities declare the qid effects a PEP says it can accept. They do not remove the PEP's responsibility to validate and enforce its own local policy. qid should return only effects within the registration capabilities; the PEP must still reject unsupported or malformed effects fail-closed.

Policy bundles are declared with:

```yaml
policy:
  default_decision: deny
  bundles:
    - name: authenticated-read
      source: policies/authenticated-read.json
      mode: enforce
```

`qidd` supports local policy bundle files at startup. Remote `http://` and `https://` bundle sources are rejected during daemon startup.

## Observability

`observability.logs.format` defaults to `json`; `redact_pii` can be enabled.

`observability.metrics.listen` defaults to `127.0.0.1:9464`. It must be a valid socket address and cannot bind to all interfaces.

`observability.audit.sink` can point to a file sink.

Metrics should stay low-cardinality. User IDs, email addresses, raw host/path values, tokens, and selected header values do not belong in labels.

## Ops

`ops` includes:

- `cache`: disabled/redis/valkey-style cache config.
- `cluster`: cluster ID, region, node ID, leader lease TTL, active-active flag.
- `backup`: enabled, object store URI, migration version.
- `emergency.read_only`: emergency mode used by restore planning/execution.

Backup enabled requires both `object_store_uri` and `migration_version`.

Active-active requires `cluster_id`, `region`, and `node_id`.

## Validation Commands

```sh
cargo run --bin qidc -- --config config/qid.example.yaml check
cargo run --bin qidc -- --config config/qid.example.yaml plan
scripts/check-config-samples.sh
```

`qidc check` prints JSON with `status`, `summary`, and individual checks. Warnings remain visible; errors fail daemon preflight.
