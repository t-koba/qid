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
- `paths`: configurable canonical paths for health, discovery, OAuth, session auth, WebAuthn, PEP, logout, CAPPORT details, and related endpoints.
- `quic`: opt-in QUIC listener, disabled by default. When `enabled`, `bind` (default `[::]:4433`) must be a valid socket address, `certificate_path` and `private_key_path` must point at readable certificate/key material, and `max_bidi_streams` must be positive. `qidd` only serves QUIC when built with its `quic` cargo feature; otherwise enabling `server.quic` fails startup. This remains a helper-level transport: it accepts and drains bidirectional streams and makes no mdoc/OID4VP interoperability claim.

### Notification delivery

`server.notification` is optional and absent by default: no transport is composed
and email-verification issuance fails closed. Configure one delivery provider:

```yaml
server:
  notification:
    provider: https://notifications.example.com/deliver
    timeout_seconds: 10
    max_concurrent_deliveries: 16
realms:
  - id: example
    # Other required realm fields omitted.
    authentication:
      password_reset:
        ttl_seconds: 900
        max_issuances_per_window: 5
        issuance_window_seconds: 3600
      email_verification:
        ttl_seconds: 600
        max_attempts: 5
```

`provider` must be an absolute HTTPS adapter URL (no user information, query or
fragment), or an `smtp://` / `smtps://` server URL (no credentials, query, fragment
or path other than `/`). `timeout_seconds` defaults to `10` and must be positive.
The daemon composes the existing worker HTTPS/SMTP implementation; resource APIs
use only the core transport contract, not a separate provider framework. HTTPS
receives the worker notification JSON envelope (`channel`, `provider`,
`recipient`, `subject`, `body`, `template_id`, `data_json`). SMTP uses the existing
worker environment configuration (`QID_SMTP_FROM`, optional paired
`QID_SMTP_USERNAME` / `QID_SMTP_PASSWORD`); credentials must not be placed in the
provider URL. Provider configuration and request/response debug output redact
secret-bearing values. Adapter acceptance is not verification: only a correctly
confirmed, persisted challenge can verify a stored email address.

Password-reset issuance uses the realm's `authentication.password_reset` policy:
`ttl_seconds` defaults to 900 (1–1800), `max_issuances_per_window` to 5
(1–4294967295), and `issuance_window_seconds` to 3600 (1–86400). All three
may be omitted independently. Expiry is server time plus the configured TTL;
public requests accept only `user_id` and optional `device_id`, never risk, time,
TTL or budget selectors. The persisted risk context is `{}` (no trusted signal).
The budget is enforced atomically per realm/account with token insertion. All
records at or after `server_creation_time - issuance_window_seconds + 1` count,
including consumed, expired and delivery-failure records. At the exact window
boundary the old record stops counting. Newer records count conservatively for
out-of-order tasks or clock rollback. Suppression creates no token or mail.

`server.notification.max_concurrent_deliveries` defaults to 16 and must be in
1–1024. One shared, process-local semaphore bounds background password-reset
persistence, delivery and audit across all realms. A request tries to reserve a
slot before spawning; no slot means suppression, not a queued task or a budget
charge. Slots are released on every completion/error/cancellation path. This
setting does not change the synchronous email-verification flow or worker job
scheduling. Unknown/ineligible/unconfigured, over-budget, capacity-suppressed and
failed delivery cases all retain the same generic `202` password-reset response.
The per-account rolling budget is repository-backed; the task bound is per
process. Traffic/IP controls belong at qpx ingress, not in qid, and forwarded IP
headers are not trusted for these controls. See [the API contract](http-api.md#password-reset).

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
| `fedcm` | FedCM route surface. The `enabled` switch decides whether a realm serves the FedCM routes and appears in the FedCM discovery documents; it is off unless the configuration sets it. |
| `federation` | Inbound OIDC/SAML/social providers, claim mappings, and per-provider `trusted_audiences`. |
| `directory` | LDAP, Active Directory, CSV HR pulls, and inbound HR webhook bindings; sync filters and attribute mapping apply only to pulls. |
| `ciam` | Consent, progressive profile, identity proofing, privacy dashboard. |
| `vc` | OID4VCI/OID4VP/HAIP/status/holder binding. |
| `workload` | SPIFFE, SVID, RATS/EAT, token exchange, CA key reference. |
| `network_aaa` | RADIUS/TLS/EAP/CAPPORT/CoA/accounting/directory authority. |

An inbound OIDC/social provider's `trusted_audiences` lists extra ID-token
`aud` values trusted for that provider besides its `client_id`. The
`client_id` used as the expected audience at the OIDC/social callbacks is
always trusted; omitting `trusted_audiences` (or leaving it empty) trusts
only the `client_id`. After signature/issuer/expiry validation every `aud`
member must equal the expected audience or a `trusted_audiences` entry, so a
token that pairs the `client_id` with an unlisted audience is rejected.
Entries must be nonempty and unique, and malformed `aud` values fail closed.
Setting this option on SAML, LDAP/AD, or Kerberos providers is a configuration
error because those providers do not verify OIDC ID tokens.


An LDAP or Active Directory provider's `connection` holds:

| Field | Purpose |
| --- | --- |
| `url` | The LDAP/AD directory endpoint (`ldaps://` or `ldap://`), or a local CSV file path for `type: csv`. |
| `bind_dn` | The bind DN, used for the directory's simple bind. |
| `bind_password` | The bind password for that DN. |
| `base_dn` | The subtree the sync reads. |
| `connect_timeout_seconds` | The timeout in seconds for the bind, the search and the unbind. Defaults to 10; the connect itself is not bounded by it. |
| `page_size` | The page size an RFC 2696 paged search requests. Between 1 and 1000; a value outside that range is rejected when the configuration loads. |
| `max_entries` | The most entries one directory search or CSV batch may collect. Defaults to 1,000,000; between 1 and 10,000,000, and a value outside that range is rejected when the configuration loads. |
| `tls_insecure_skip_verify` | Skip the TLS certificate verification. This disables the server name check as well as the chain check, so it applies to the whole connection. |

For a realm whose directory is enabled, every provider, enabled or not, needs a
unique nonblank id and a supported `type` (`ldap`, `active-directory`, `csv`, or
`webhook`). Pull providers need a source in `connection.url`; webhooks do not.
The pull source-specific rules below apply when both directory and provider
are enabled. Webhook-specific settings are always validated, even when disabled.
An enabled LDAP/Active Directory provider is checked for the LDAP URL scheme and
the credential rules below; an enabled CSV provider follows the local-file rules
below instead. Disabled providers are not checked for these source-specific rules.
A bind DN that carries a control character is rejected with the credential rules.
A `csv` provider reads the historical HR workforce export from the local file
`connection.url` names instead of connecting to a directory: `url` must be a
local file path (surrounding whitespace is trimmed; a value with a `://` scheme
is rejected), and the LDAP-only
`bind_dn`, `bind_password`, `base_dn`, `page_size`, `tls_insecure_skip_verify`,
`user_search_filter`, and `attribute_mapping` settings are rejected when set to
anything but their defaults, because a CSV source would silently ignore them.
The LDAP-only `connect_timeout_seconds` likewise accepts only its default `10`
or unset for CSV; neither applies a timeout to local file reads.
`sync.deactivate_missing` defaults to true for LDAP/AD snapshots; CSV accepts
only false or unset and never deactivates users missing from its HR event batch.
`max_entries` stays settable as the CSV record ceiling (default 1,000,000).
The CSV keeps the historical columns `external_id`, `email`, `display_name`,
`department`, `manager_external_id`, and `event` (joiner/mover/leaver); an
optional `username` column names the user when present and non-blank, otherwise
`external_id` stays the username as before. Quoted fields follow RFC 4180
(commas and line breaks inside quotes are data, `""` is an escaped quote).
Quotes may open only at field start, and after a closing quote only a comma,
record terminator, or EOF is allowed. Input must be valid UTF-8. The source is
bounded to 8 MiB and the whole file is validated before any write, so a
rejected row writes nothing; joiner/mover/leaver lifecycle, duplicate-ID
preflight, and mover-clear semantics stay owned by the HR importer.

### Inbound HR webhook bindings

A `webhook` provider receives ordered lifecycle batches at
`POST /directory/v1/providers/:id/hr?realm=<realm>`. It is not a periodic
source: `qid-worker directory-sync` refuses it before constructing any LDAP
connector or reading CSV. Directory and provider `enabled` must both be true
(provider `enabled` defaults to false; the existing directory default stays
true), and the realm must have a nonblank `tenant_id`
matching the authenticated directory administrator's tenant. Provider IDs are
stable ordering domains: **never reuse an ID for a different source**.

```yaml
# Inside one configured realm (with tenant_id set):
protocols:
  directory:
    enabled: true
    providers:
      - id: workforce-events
        type: webhook
        enabled: true
        webhook:
          max_request_bytes: 8388608
          max_records: 1000000
```

`webhook.max_request_bytes` defaults to 8 MiB (8,388,608 bytes), the same
ceiling as CSV HR files; allowed range is 1..=8,388,608. The raw body is bounded
before JSON parsing. `webhook.max_records` defaults to
`MAX_DIRECTORY_SEARCH_ENTRIES` (1,000,000), allowed range
1..=`MAX_DIRECTORY_SEARCH_ENTRIES_LIMIT` (10,000,000), checked before preflight.
Omitting the `webhook` block uses those defaults. Unknown keys are rejected.
The block is rejected on non-webhook types. For webhooks, `connection`,
`sync`, and `attribute_mapping` must be omitted or equal their defaults;
non-default settings (including CSV paths, LDAP credentials, search filters,
intervals or snapshot-deactivation options) are rejected rather than ignored.
These rules hold even for an inert disabled webhook provider.

The route uses the existing elevated administrator session, not a new webhook
secret or signature protocol. See [HTTP API](http-api.md#inbound-hr-lifecycle-batches)
for the strict envelope, ordered retry contract, non-PII summaries, and failure
semantics. No queue or external delivery is involved.

An enabled LDAP/Active Directory provider's `bind_dn` and `bind_password` must both be set and non-blank, or the
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

`oauth.require_pushed_authorization_requests` is a realm's own requirement: a realm
that sets it refuses an authorization request that carries no pushed request. The
requirement is read from the realm of the client that made the request, so it
reaches the clients of that realm and no other. Beside it, the standard
[RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) client metadata boolean
`require_pushed_authorization_requests` (default `false`) requires a pushed
request for that client only: it is set per client through dynamic client
registration, persisted with the client record, and enforced alongside the
realm-wide setting, so a flagged client is refused without `request_uri` while
an unmarked client of the same realm is unaffected. Registration or update
with this metadata is refused when the client's realm has not enabled the PAR
endpoint. The per-client list `oauth.par.required_for` was removed: the product
never read it, so a configuration that still sets it is a configuration error
naming the key.

## Authentication and Sessions

`authentication` includes:

- `passkeys.enabled`, `rp_id`, `rp_origin`, `rp_name`, `preferred`, optional `attestation`
- `password.enabled`, `hash`, `max_failed_attempts`, `lockout_duration_seconds`, `max_failed_attempts_per_realm`, `argon2id`, `pepper`
- `email_verification.ttl_seconds` (default `600`, allowed `1..=3600`) and `email_verification.max_attempts` (default `5`, positive): persisted session-bound email challenge policy.
- `mfa.totp.enabled`, `mfa.totp.max_failed_attempts` (default `5`, allowed `1..=100`), `mfa.totp.failed_attempt_window_seconds` (default `300`, allowed `1..=86400`): per-account TOTP proof admission policy.
- `passwordless_only`

Validation rules:

- Weak OIDC implicit and ROPC flows are rejected.
- Authorization code requires PKCE.
- If `passwordless_only` is true, passkeys must be enabled.
- Otherwise, at least one of passkeys or password must be enabled.
- A realm that disables password authentication, or that is passwordless, refuses every password login: the session API and the OIDC authorization endpoint both refuse it.
- `password.hash` must be `argon2id`: it names the one algorithm the product creates.
- `password.max_failed_attempts`, `password.max_failed_attempts_per_realm` and `password.lockout_duration_seconds` must be at least 1.
- `password.argon2id` must be a usable cost: `time_cost` and `parallelism` at least 1, and `memory_kib` at least 8 KiB per lane.

`passkeys` names the realm's WebAuthn relying party. `enabled` states whether the realm offers the factor, `rp_id` and `rp_origin` override the relying-party ID and origin the ceremony uses, and `rp_name` names the relying party to the authenticator. Without `passkeys.attestation`, registration requests `none` and adds no attestation trust requirement. The optional typed policy below requests `direct` and requires trusted packed evidence; legacy string values such as `attestation: enterprise` remain configuration errors. `passkeys.preferred` defaults to `false` and requires `passkeys.enabled: true` when set to `true`. The OIDC GET authorization endpoint's `login_required` JSON challenge includes an `authentication_methods` string array for the validated client's realm: `password` then `webauthn` by default, or `webauthn` then `password` when preferred; `email_magic_link` is appended when enabled. Only enabled methods are listed, and `passwordless_only` suppresses password even if its configuration enables it. This order is advisory for API clients, not an authentication requirement or automatic browser UI; qid provides only the explicit email-link confirmation page, not a general login UI.


To execute a login choice (default paths shown; deployments may customize them):

- `password`: POST to `/oauth2/authorize` with the original authorization request parameters in the query string and an `application/x-www-form-urlencoded` body containing `email` and `password`.
- `webauthn`: POST JSON `{"email":"..."}` to `/api/v1/:realm/auth/webauthn/auth/start`, pass the returned `challenge` options to the browser's `navigator.credentials.get`, then POST `{"email":"...","response":...}` to `/api/v1/:realm/auth/webauthn/auth/finish`. For a discoverable credential, POST `{}` to `/api/v1/:realm/auth/webauthn/discoverable/start` and POST `{"ceremony_id":"...","response":...}` to `/api/v1/:realm/auth/webauthn/discoverable/finish` instead, using the `ceremony_id` returned by the start route. Replace `:realm` with the client's realm ID. Both finish routes establish a realm browser session and return its `Set-Cookie`; retain/send that cookie when repeating the original GET `/oauth2/authorize` request to resume OIDC and receive the authorization redirect. Keep the original authorization parameters (or PAR `request_uri`), not just the subset echoed in the challenge. Session reuse still respects realm, expiry, `max_age`, and essential ACR requirements; `prompt=login` forces a new login, so do not carry it into a session-resume GET.

### Required trusted packed enrollment

`passkeys.attestation` is an optional **enrollment-only** operator trust policy.
Omit it for the default `none` request and existing registration algorithms and
behavior. When present, passkeys must be enabled, registration requests `direct`,
and finish requires the policy below as well as the ordinary caden ceremony
checks. Browsers may withhold attestation; `none`, self-attestation, other formats,
and unsupported algorithms then refuse enrollment rather than silently downgrade.
Existing credentials, authentication, discoverable login and session AMR are
unchanged: an old stored AAGUID never gains retrospective trust, and this policy
does not establish a `hwk` factor or a hardware/non-exportability claim.

Example shape under a realm's `authentication.passkeys` (replace the certificate
placeholder and validity interval before use):

```yaml
enabled: true
attestation:
  metadata:
    not_before: 1767225600  # inclusive Unix seconds
    expires_at: 1893456000  # exclusive Unix seconds
    models:
      "11111111-1111-1111-1111-111111111111":
        status: allowed     # allowed | blocked
        roots: ["<standard padded base64 DER trust-anchor certificate>"]
  limits:                  # these are the defaults; every field is optional
    evidence_bytes: 16384
    client_data_bytes: 4096
    certificates: 4
    certificate_bytes: 4096
    models: 128
    roots_per_model: 4
```

The inline metadata is trusted **because the operator controls the configuration**,
not because qid verifies a FIDO Metadata Service signature. There is no network,
file-provider, MDS fetch, certificate AIA fetch or system-root fallback. Supply
curated roots only for the corresponding authenticator model; sharing a broad root
across models broadens the authority trusted to assert those models. Model IDs
must be unique canonical lower-case, hyphenated 16-byte AAGUIDs. Metadata must have
an ordered validity interval and nonempty bounded models and roots, with valid
base64 DER certificates usable by webpki's runtime trust-anchor extraction and
positive limits. `blocked` models still require roots
in configuration, but cannot enroll. At **finish**, current time must be in
`[not_before, expires_at)` and the signed AAGUID must select an `allowed` model.
Missing/unknown/blocked models, stale/not-yet-valid metadata and any trust failure
refuse enrollment without a credential write and consume the one-use ceremony.
Start is not a freshness guarantee. Update configuration and restart through the
normal deployment procedure before the metadata expires.

The intentionally narrow trusted profile supports **packed x5c with ES256/P-256**
statement and certificate-chain signatures only. The leaf must be X.509 v3, have
nonempty subject C (syntactically two uppercase ASCII letters, without ISO country
registry membership validation), O and CN, exactly one OU equal
to `Authenticator Attestation`, and explicit BasicConstraints `CA=false`.
KeyUsage, if present, must include digitalSignature on the leaf and keyCertSign
on every supplied intermediate. EKU must be absent on all supplied certificates
(including empty or malformed EKU, which is rejected); no standardized packed EKU
OID is assumed. Unlike generic packed attestation, this profile **requires** the
noncritical FIDO AAGUID certificate extension, containing exactly a DER OCTET STRING
of 16 bytes equal to the signed authenticator-data AAGUID. Otherwise valid packed
evidence lacking this extension is deliberately not trusted by this profile.

qid uses non-TLS webpki path validation to the selected model's configured pins
and independently verifies the exact `authData || SHA256(clientDataJSON)` statement
with the parsed leaf SPKI. It checks certificate validity, CA/path-length/name
constraints and unknown critical extensions in the path. A configured root is a
**trust anchor, not a path member**: its self-signature, expiration, CA flag and
path-length are not inferred to be chain constraints. The operator is responsible
for pin authorization and retirement. Send the leaf followed by intermediates in
x5c, not roots. Neither CRL/OCSP nor MDS status revocation is claimed: metadata
expiry/model blocking controls new enrollment only, not existing credentials or
sessions. Use credential/session administration for those.

Limits are independent ceilings, not truncation. The encoded attestation object
and client-data lengths are checked before base64 decode/CBOR allocation; chain
count and each DER size are checked before certificate work. Metadata model/root
counts and root DER sizes are validated at configuration load. The default bounds
leave room above the generated test fixture (about 0.5 KiB leaf, 0.4 KiB intermediate,
1.2 KiB attestation object and 138-byte client data) without an unbounded chain or
metadata set. Raise limits only for a measured deployment need. There is no
per-request filesystem work; the active service borrows the realm policy.

Enrollment uses the existing cookie-authenticated
`POST /api/v1/:realm/auth/webauthn/start` (`{"email":"..."}`) and
`POST /api/v1/:realm/auth/webauthn/finish` (`{"user_id":"...","response":...}`)
routes. Both the browser session and user must belong to the request realm;
there is no extra trusted-enrollment endpoint or hosted enrollment UI.

### Password policy

`password` is the realm's password policy, and every setting in it has an effect. `hash` names the algorithm the product creates credentials with, so any other value is a configuration error naming the key. `max_failed_attempts` and `lockout_duration_seconds` are the limits the realm's password logins enforce: the session API and the OIDC authorization endpoint both lock the account after that many failed attempts and refuse even the correct password until the lockout expires. `max_failed_attempts_per_realm` bounds the failures the realm accepts as a whole: within the lockout window the realm accepts that many failed password logins and refuses further password logins with `429 Too Many Requests` until the window passes, so a spray that tests one guess per account cannot run without bound, and one burst cannot lock every account of a realm. The budget counts failures only, so a successful login never spends it, and a refused login is refused before any credential is verified, so it costs no Argon2id work. The budget is kept in the process that enforces it, so a deployment with several instances applies the limit to each of them. Both password login paths share the budget of the realm, so they enforce the same numbers. Before the credential work, a password login is admitted by an admission count: the submitted email's admission count follows `max_failed_attempts` within `lockout_duration_seconds`, and the realm's admission count follows `max_failed_attempts_per_realm` within the same window. The admission cap counts the logins that reach the credential work, while the budget counts only the logins that failed, so the two answer different questions: the cap bounds the work a spray of guesses can cause, and the budget bounds the failures a realm accepts. A login the cap refuses answers `429 Too Many Requests` before any credential is verified, so it costs no Argon2id work, and the session API and the authorization endpoint share the cap, so both paths refuse the same logins. A successful login gives back the admission it spent on the submitted address and on the realm, so both counts follow the logins that failed and the ones still in flight: a realm whose logins succeed keeps its room, and one success never spends the room of the realm it belongs to. The admission limiter is process-local, so each qidd instance enforces its own counts and restarts clear them. `argon2id` is the cost the product hashes with whenever it creates a credential - a user the CLI creates, a user a seed writes, a password a reset consumes - and the cost every credential of the realm ends up carrying: a credential whose stored parameters differ from the realm's is rehashed with the realm's cost at the next successful login, so an imported credential and a credential created at an older cost both reach it; verification always honours the parameters stored in the hash. The obsolete `pepper_ref` is rejected; use the explicit versioned `pepper` key configuration below.

### Realm password pepper

Peppering is disabled by omission. To enable it, configure an active key ID and
all keys still needed to verify existing credentials under `authentication.password`:

```yaml
pepper:
  active: key2
  keys:
    key1: { env: PASSWORD_PEPPER_OLD }
    key2: { file: /run/secrets/password-pepper-key2 }
```

Each source is exactly one `env` name or `file` path, never an inline secret.
`QID_` is reserved for configuration overrides; use other environment names for
secret references. Relative file paths are relative to the process working
directory. Files are read as bytes **verbatim**, including trailing newlines;
environment values must be UTF-8. Provision a nonempty, independently generated
secret for each realm and key, restrict file/environment access, and distribute the
same keys to every instance that serves that realm. There is no vault adapter.
IDs must be nonempty and fit in **8 UTF-8 bytes**,
the native Argon2 `keyid` limit. The active ID must exist in `keys`.

qidd resolves **all** configured keys before storage seeding or serving and keeps
one zeroizing credential context per realm for its process lifetime. Missing,
unreadable, empty or invalid sources fail startup, including retained keys. CLI
user creation and dev seeding resolve before account writes; login rehashes and
atomic password reset use the same owner as ordinary creation. Embedded HTTP
servers must install `resolve_password_contexts` on `SharedState.password_credentials`
before serving; configured realms without an installed context fail closed. No
secret bytes are included in credential hashes, persisted configuration, audit
records or resolver errors. Treat the referenced files/environment and their
backups as secret storage independent of the identity database.

New credentials use Argon2id's native secret input and a standard PHC `keyid`
selector (base64-encoded ID), preserving the configured Argon2 costs. A tagged hash
uses **only** its selected key: unknown, missing or wrong keys fail authentication;
there is no unpeppered fallback or search through other keys. Untagged supported
Argon2id/PBKDF2 imports still verify normally and migrate on successful login to
the active key and current realm cost. A retained older key likewise migrates to
the active key. Unconfigured deployments retain ordinary unpeppered behavior.

To rotate, provision a **new ID and new bytes**, retain old keys, set the active ID
to the new one, and restart all instances together. Sources are snapshotted, **not
hot-reloaded**; changing a file or environment value does not rotate a running
process. Keep old keys until their credentials have migrated or been reset.
Never change bytes under an existing ID: old credentials then fail. Removing a
required key, or removing the entire pepper configuration, makes its tagged
credentials unusable; it never downgrades them to unpeppered verification. Restore
the required key or perform an authorized password reset to recover. Existing
backups may still need old keys even after live credentials have migrated.


### Delivered email magic-link login

`realms[].authentication.email_magic_link` enables standalone passwordless primary
email authentication. It is **disabled by default** and uses the shared
`server.notification` transport (HTTPS delivery adapter or configured SMTP). An
enabled realm is rejected at configuration validation without that provider or
without an HTTPS `server.public_base_url` with a host and no credentials, query or
fragment. Missing runtime transport still fails closed. OIDC's real login-method
listing advertises `email_magic_link` only in enabled realms. The send and verify
POSTs remain under qid's CSRF protection; browser initiation must be same-origin
with qid, or use a same-origin proxy. No cross-device or client redirect flow is
provided. This does not enable
or replace MFA, satisfy high-assurance requirements, or change password, passkey
or TOTP policy. Sessions carry ACR `urn:qid:acr:email_magic_link` and AMR `email`.

| Setting | Default | Inclusive range |
| --- | --- | --- |
| `enabled` | `false` | Boolean |
| `ttl_seconds` | `600` | 1..3600 |
| `max_attempts` | `5` | 1..20 |
| `max_issuances_per_window` | `5` | 1..100 |
| `issuance_window_seconds` | `3600` | 1..86400 |

Send accepts only an email selector; delivery uses the resolved account's exact
stored nonempty, verified email. Every eligible, unknown, disabled, suppressed or
failed-delivery send returns the same generic `202` body. Rolling issuance is
atomic per realm/account/purpose, includes failed deliveries and persists across
restarts; attempts and one-use redemption are atomic too. Notification capacity
is shared and bounded by `server.notification.max_concurrent_deliveries`. No
in-process challenge map or additional rate limiter is used.

Send sets/reuses `__Host-qid_email_magic_binding`, a random 32-byte browser cookie
with HttpOnly, Secure, SameSite=Lax, Path=/ and a renewed one-hour Max-Age. That
name is reserved when enabling this feature. Realm IDs `.` and `..` are refused
for this feature because browsers normalize URL dot segments. Outstanding links share the existing
well-formed binding; clearing/losing the cookie invalidates them. The email tells
the user to open the link in **the same browser**, then explicitly confirm. An
invalid, missing or malformed browser binding does not spend token attempts or
consume the token; reopen the email link in the initiating browser or restart
sign-in there. Links use only the configured HTTPS
`server.public_base_url` (including any path
prefix) and configured verify route (absolute path, substituting the realm), never
request Host or forwarding headers. ID and
32-byte secret are placed in `#challenge_id.token`, not a query string. The
self-contained GET landing page immediately clears the fragment from history,
uses a per-response nonce CSP with no third-party assets, no-store/no-referrer,
and sends a same-origin POST only on button click. GET never logs in, including
email scanner GETs. JavaScript is required for this confirmation page.

Only a versioned pair of domain-separated, length-prefixed SHA-256 digests is
stored in the existing challenge hash field (`ml2:<binding digest>:<token digest>`).
Each proof binds the immutable challenge identity. Storage checks binding first;
only the correct binding spends a persisted attempt on a wrong token (including a
malformed token) or on successful one-use redemption. Legacy combined hashes fail
closed; request a new link after an upgrade. Redemption requires the current
exact verified email, realm, purpose/channel, binding, server-time expiry and
remaining attempt budget. Invalid/replayed credentials fail uniformly. Only
successful atomic redemption regenerates the browser session and sets its
configured session cookie; subsequent session/cookie failure does not restore
the consumed challenge. Adapter acceptance is never authentication, and provider
errors/content and delivery secrets are not logged by these routes. Successful
delivery acceptance is audited separately from authentication; acceptance is not
verification or login. Protect mail and configure adapters not to disclose
delivery content.

`server.paths.auth_email_magic_link_send` and
`server.paths.auth_email_magic_link_verify` customize the routes. Each requires
exactly one `:realm` segment and otherwise literal URL-safe, nonempty path
segments (no wildcards, other parameters, dot segments, query or fragment); route
values must remain unique.


`mfa.totp.enabled` states whether the realm offers the TOTP factor, and every path that performs the factor honours it: a realm that does not enable TOTP refuses enrolment, confirmation and challenges on the routes and refuses the `qidc totp enroll` command, while a realm that enables it performs them. The switch is off by default, so a realm offers TOTP only when it says so. `mfa.totp.max_failed_attempts` bounds how many TOTP proof attempts one account may spend within `mfa.totp.failed_attempt_window_seconds`: enrolment confirmation and primary authentication share one account-keyed budget per realm, admit each proof for a known account before code verification, and refuse with `429` once the budget is spent, before verification, step consumption, enrolment activation or session creation. Wrong, malformed and replayed codes spend the budget; only a proof that verifies and wins the step claim gives its admission back. The budget never resets just because the 30-second code step rolls over. The limiter is process-local memory: restarting the process clears the counts, counts are not shared between processes or hosts, and there is no claim of distributed protection. A realm that spans more than one process or host must not rely on this budget to stop a coordinated guess spread across them. The preflight check requires TOTP or passkeys for high-risk audiences and reports the factors the realm can actually use. `mfa.sms.enabled` was removed: the product has no SMS factor, no SMS delivery adapter and no SMS route, so a configuration that still sets it is a configuration error naming the key. The MFA options are TOTP and passkeys (WebAuthn). Push MFA is not available. Email magic-link login is a separate passwordless primary authentication method, not MFA (see above). A TOTP credential carries its own digits and period from the moment it is enrolled. A client certificate is a client authentication method (`tls_client_auth`) and a TLS trust decision (`server.tls.client_ca`); it is not a realm MFA factor, so the realm configuration has no client-certificate switch.

`sessions` includes browser cookie name, SameSite, idle/absolute timeout, refresh token rotation, and reuse detection. The refresh path always rotates the refresh token on every use, and a superseded or concurrently redeemed token always revokes the whole token family. `refresh_tokens.rotation` states that behaviour and cannot be turned off: a configuration that disables it is an error, because the product has no mode without rotation. `refresh_tokens.reuse_detection` names the mode the product enforces and accepts only `revoke_family`; any other mode is a configuration error.

## PEP Registrations and Policy

`pep_registrations` declares external PEP identities that may receive qid assertions or call qid decision endpoints. A registration can represent qpx, Envoy, NGINX, HAProxy, a service mesh, an API gateway, a custom reverse proxy, or another enforcement component.

`pep_registrations.enabled` decides whether the realm serves its registrations at all. The switch is off unless the configuration sets it, so a realm that lists registrations without enabling them serves none of them: the decision, assertion and AuthZEN endpoints authenticate no PEP of that realm, and the PAR and OAuth mTLS paths accept no PEP metadata of that realm. The registrations stay declared, so a deployment can turn the serving off and on again without rewriting them.

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

A registration carries the audience it is identified by, the effects it accepts in `capabilities[].effect`, the lifetime of the assertions qid issues for it in `assertion.ttl_seconds`, how qid answers when it cannot decide in `decision.fail_policy`, the decision cache in `decision.cache`, and the credential the PEP authenticates with in `auth`, where `auth.active_method` names the method - only `bearer_jwt` is implemented - and `auth.replay_protection`, `auth.token_max_age_seconds` and `auth.clock_skew_seconds` bound the presented token. `auth.key_rotation` and `auth.http_message_signatures` were removed from that block: a configuration that sets either is a load-time error naming it. The endpoints are served at the server paths `server.paths.pep_decision`, `server.paths.authzen_evaluation` and `server.paths.assertion`; a registration does not name its own endpoint, and the assertion qid issues is signed with the realm's `pep_assertion` keyring and returned in the response body.

The decision cache block names how long the cache may keep a decision: `positive_ttl_seconds` for a decision the request proceeds on and `negative_ttl_seconds` for one the product refuses or defers - a quarantine is a refusal, and the decision response reports it as `deny`. A lifetime of zero keeps that class of decision out of the cache, and a registration that names no lifetime keeps the product defaults of 30 seconds for a positive decision and 5 seconds for a negative one. The `ttl_ms` of a decision response is the lifetime the registration asks for, so the PEP and qid hold the decision for the same time.

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
