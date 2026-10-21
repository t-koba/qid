# Configuration

qid loads YAML or TOML into `qid_core::config::QidConfig`. Configuration is a canonical contract: unknown fields are rejected, profile obligations are explicit, and old aliases are not accepted for convenience.

The configuration model describes qid as an IdP, authorization server, lifecycle service, PDP, and provider-neutral PEP integration point.

## Placeholders

The shipped samples mark the values an operator must supply with a placeholder: either `secret://<name>` or `change-me-<name>`. Both are plain text. qid does not resolve `secret://` references, so a placeholder is sent literally to the service it configures - a directory bind password placeholder is presented to the directory as that literal string - and it must be replaced with the real value before the deployment runs. Some samples ship a literal example value instead of a marker, such as the hex string a shared secret or a cursor secret uses; every sample value is plain text that qid uses as it stands, so such an example value must be replaced with the real value before the deployment runs.

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
| `observability` | no | Log format and metrics listener. |
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
- `tls.client_ca`: enables optional native client certificate authentication. Every presented client certificate is path-validated to this PEM trust-anchor bundle; requests without a client certificate remain available for public endpoints.
- `tls.client_crls`: optional PEM or DER CRLs enforced by the client certificate path verifier. CRLs require `tls.client_ca`, and unknown revocation status fails closed.
- `tls.ocsp_responses`: optional list of DER OCSP response paths in server certificate-chain order. Use `null` for a certificate without a stored response. The list cannot be longer than the configured chain and must contain at least one non-empty response. TLS 1.2 clients that explicitly support RFC 6961 receive `ocsp_multi`; the non-empty leaf entry is also available through RFC 6066. qid never fetches or silently substitutes OCSP responses.
- `http_message_signatures`: enables RFC 9421-style verification around signed back-channel routes.
- `cors.allowed_origins`: absolute HTTP(S) origins or `*`.
- `cors.allow_credentials`: cannot be combined with wildcard origin.
- `paths`: configurable canonical paths for health, discovery, OAuth, session auth, WebAuthn, PEP, logout, email magic link, CAPPORT details, and related endpoints.
- `quic`: opt-in QUIC listener, disabled by default. When `enabled`, `bind` (default `[::]:4433`) must be a valid socket address, `certificate_path` and `private_key_path` must point at readable certificate/key material, and `max_bidi_streams` must be positive. `qidd` only serves QUIC when built with its `quic` cargo feature; otherwise enabling `server.quic` fails startup. This remains a helper-level transport: it accepts and drains bidirectional streams and makes no mdoc/OID4VP interoperability claim.

Path values must start with `/`, must not be empty, and must be unique. `paths.capport_details` must additionally contain an Axum `:realm` segment and must not reuse the fixed CAPPORT bind, unbind, or lookup path.

OAuth clients using `tls_client_auth` or `self_signed_tls_client_auth` can authenticate directly to `qidd` when `tls.client_ca` is configured. The TLS layer validates the certificate path before the OAuth layer binds the SHA-256 leaf thumbprint. Authenticated PEP-provided mTLS metadata remains available for deployments that terminate client TLS at a registered enforcement point.

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
| `capport_details` | `/api/v1/:realm/captive-portal/api/v1/details` |

The CAPPORT routes are mounted only when at least one realm sets
`network_aaa.capport: true` (default `false`), and every CAPPORT handler
re-checks the requested realm, so enabling one realm never enables another.

## Storage

`storage.primary` supports:

- `type`: defaults to `sqlite`.
- `url`: direct URL or file path.
- `url_env`: environment variable containing the URL.

`storage.file.flush_mode` controls the file-backed JSON backend:

- `immediate`: default; every mutation is flushed durably before returning.
- `interval_ms(N)`: mutations mark the store dirty and a background task flushes at the interval; `qidd` also flushes during graceful shutdown.

The effective URL is `url`, then `url_env`, then the daemon default.

Backend selection:

- `sqlite:*` and `postgres:*` use SQL.
- Other values use file-backed JSON.

Redis/Valkey-style cache settings require endpoints, a non-empty key prefix, and a positive TTL when enabled.

## Crypto

`crypto.default_alg` must be `ES256`, `RS256`, or `EdDSA`. Local signer generation in `qidd` currently supports `ES256` and `EdDSA`.

Set `QID_KEY_PASSPHRASE` or `crypto.key_passphrase_file` to store local signing keys as `.pem.enc` files. When a passphrase is configured and a plaintext local PEM already exists, `qidd` encrypts it on startup and moves the plaintext file to `.bak`.

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
| `saml` | SAML IdP routes, metadata signing, assertion signing/encryption, SP registration, clock skew. SP signing certificates accept PEM or bare standard base64 DER; encryption certificates require a compact bare standard base64 DER value. |
| `scim` | SCIM base path, cursor secret, and callback host allowlist. Only core User/Group and the Enterprise User extension are supported; `custom_schemas` entries are rejected. |
| `fedcm` | FedCM route surface. |
| `federation` | Inbound OIDC/SAML/social providers and claim mappings. |
| `directory` | LDAP and Active Directory providers, sync filters and attribute mapping. |
| `ciam` | Consent, progressive profile, identity proofing, privacy dashboard. |
| `vc` | OID4VCI/OID4VP/HAIP/status/holder binding. |
| `workload` | SPIFFE, SVID, RATS/EAT, token exchange, CA key reference. |
| `network_aaa` | RADIUS/TLS/EAP/CAPPORT/CoA/accounting/directory authority. |

An LDAP or Active Directory provider's `connection` holds:

| Field | Purpose |
| --- | --- |
| `url` | The directory endpoint. `ldaps://` and `ldap://` are accepted; another scheme is rejected when the configuration loads. |
| `bind_dn` | The bind DN, used for the directory's simple bind. |
| `bind_password` | The bind password for that DN. |
| `base_dn` | The subtree the sync reads. |
| `connect_timeout_seconds` | The timeout in seconds for the bind, the search and the unbind. Defaults to 10; the connect itself is not bounded by it. |
| `page_size` | The page size an RFC 2696 paged search requests. Between 1 and 1000; a value outside that range is rejected when the configuration loads. |
| `max_entries` | The most entries one directory search may collect. Defaults to 1,000,000; between 1 and 10,000,000, and a value outside that range is rejected when the configuration loads. |
| `tls_insecure_skip_verify` | Skip the TLS certificate verification. This disables the server name check as well as the chain check, so it applies to the whole connection. |

The provider rules apply to a realm whose directory sync is on; a realm whose directory sync is
off is not checked for them. For such a realm, every provider, enabled or not, needs a unique
id, a URL and a `type` of `ldap` or `active-directory`. An enabled provider is checked for the
URL scheme and the credential rules below as well; a disabled provider is not checked for them.
A bind DN that carries a control character is rejected with the credential rules.

An enabled provider's `bind_dn` and `bind_password` must both be set and non-blank, or the
bind DN must be absent and the bind password blank. A bind DN without a usable password is
an unauthenticated bind that RFC 4513 answers with success, and a password without a bind DN
would leave the search anonymous, so a provider with only one of them is rejected when the
configuration loads. A disabled provider is not checked for credentials, because no sync
reads it.

A provider's connection can ask for RFC 2696 paging with `page_size`. The
setting is a requirement on the directory, not a hint: with a page size the
search expects the PagedResults control on every page, so a directory that does
not implement RFC 2696 paging must be read without a page size. A directory
that ignores the request fails the sync rather than returning a partial result.

One search collects at most 1,000,000 entries. That ceiling is above the
number of objects the supported directory servers are documented to hold, so an
ordinary large directory still syncs. A provider's connection raises the
ceiling with `max_entries` when its directory holds more; the setting is
rejected when the configuration loads unless it is between 1 and 10,000,000.
The pages a search may fetch follow from the ceiling and the requested page
size, so a directory that keeps handing back a paging cookie fails the sync
with the bound in the error instead of running forever. Without `page_size` the
search is one request, so it returns what that request returned; the entry
ceiling still applies to it, so a directory that answers with more entries
than the ceiling allows fails the sync rather than filling the memory.

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
- `mfa.allowed`, `totp`, `sms`, `client_certificate`
- `passwordless_only`

Validation rules:

- Weak OIDC implicit and ROPC flows are rejected.
- Authorization code requires PKCE.
- If `passwordless_only` is true, passkeys must be enabled.
- Otherwise, at least one of passkeys or password must be enabled.

`sessions` includes browser cookie name, SameSite, idle/absolute timeout, refresh token rotation, and reuse detection. The refresh path always rotates the refresh token on every use, and a superseded or concurrently redeemed token always revokes the whole token family. `refresh_tokens.rotation` states that behaviour and cannot be turned off: a configuration that disables it is an error, because the product has no mode without rotation. `refresh_tokens.reuse_detection` names the mode the product enforces and accepts only `revoke_family`; any other mode is a configuration error.

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

When no rule matches, the bundle's own `default_decision` applies; a realm
without a configured bundle falls back to the realm `policy.default_decision`
(`deny` unless configured). Unknown decision names are rejected at startup,
and absent risk or authentication-age evidence never satisfies a rule — not
even under negation.

A bundle is read strictly: an unknown key in the bundle, in a rule, in a
condition, or in an expression is an error naming that key, and a malformed
expression is an error naming the key and its expected shape. A typo cannot
silently drop a rule's conditions and leave an allow rule matching every
request.

## Observability

`observability.logs.format` selects how the daemon writes its logs: `json` (the default) or `text`. Any other value is a configuration error naming the key.

`observability.metrics.listen` defaults to `127.0.0.1:9464`. It must be a valid socket address and cannot bind to all interfaces.

These two settings are the whole observability block. The daemon does not export traces to an OpenTelemetry collector.

Audit events are not configured here. They are stored in the audit store of the configured primary repository, scoped to their realm and chained by hash, and the admin API exports them as JSONL.

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
