# Security Notes

qid is fail-closed by default because it sits on identity, token, policy, and PEP decision boundaries. It must not become a data plane, and it must not trust a data plane's request body merely because the body names a realm, audience, route, or capability.

## Boundary Model

| Boundary | qid requirement |
| --- | --- |
| Browser/client to qid | exact issuer, redirect, state/nonce, PKCE, CSRF, secure session cookie, WebAuthn origin/RP ID validation. |
| Service/client to qid | client authentication, audience/resource validation, sender constraint where required, replay protection. |
| IdP/federation to qid | signature, issuer, audience, destination/recipient, conditions, replay, and metadata trust validation. |
| PEP to qid | credential-bound registration, audience, replay, capability, schema, and fail-closed validation. |
| qid to PEP | short-lived signed assertions or signed decision responses where configured, minimal PII, scoped audience. |

## Config Hardening

Config structs reject unknown fields. This prevents misspelled security settings from being silently ignored.

Important validation rules:

- At least one realm is required.
- Realm IDs must be URL-safe path segments.
- OIDC implicit flow and ROPC are rejected.
- Authorization code flow requires PKCE.
- Multi-realm issuer URLs must match realm-scoped discovery paths.
- Metrics cannot bind to all interfaces.
- Static redirect URIs cannot use wildcards or fragments.
- Redirect URIs must use HTTPS except localhost HTTP.
- SCIM cursor secrets must be at least 32 bytes when SCIM is enabled.
- SCIM event callback allowlists must be hostnames and reject unsafe local/non-routable hosts.
- PEP decisions must fail closed with `fail_policy=deny`.
- PEP assertion TTL cannot exceed 300 seconds.

## Authentication

Supported authentication surfaces include password, passkeys/WebAuthn, TOTP, push MFA, email magic link, browser sessions, and refresh token rotation.

Operational guidance:

- Prefer passkeys, especially for admin and high-assurance realms.
- Use `passwordless_only` only with passkeys enabled.
- Tune Argon2id cost per deployment CPU/memory budget.
- Keep lockout enabled for password-backed realms.
- Treat email magic link and push channels as recovery or step-up surfaces unless your threat model accepts them as primary.

## Admin Operations

`admin.security` defaults toward reason and step-up requirements:

- `require_reason`
- `require_step_up`
- `required_acr`
- `required_amr`
- `max_elevation_seconds`
- `require_approval`
- `max_approval_age_seconds`
- `breakglass_enabled`

For sensitive deployments, enable approval and keep elevation TTL short.

## Tokens and Clients

Static client validation enforces:

- no weak grants (`implicit`, `password`)
- no secret on public clients
- no `client_credentials` for public clients
- required secrets for confidential secret-based auth
- required JWKS for `private_key_jwt`
- required certificate thumbprints for mTLS

FAPI and high-assurance profiles require sender-constrained resource servers and stronger client authentication surfaces.

## HTTP Layers

`qidd` installs:

- request ID middleware
- request metrics
- CSRF protection
- Content Security Policy
- TLS 0-RTT rejection
- HSTS
- standard security headers
- configured CORS

HTTP Message Signatures can wrap signed OAuth and PEP-facing back-channel routes. Public front-channel and metadata routes stay outside that layer by design.

## Key Material

Local signing keys are stored in `qid-state/` next to the primary config. Protect this directory with filesystem permissions and backup policy appropriate for signing keys.

Remote signer keyrings are validated by config, but current daemon startup does not include remote signer transport. Do not set high-assurance remote signer profiles expecting runtime signing to work until the transport is implemented.

Keyring purposes are validated and should be scoped narrowly:

- `oidc_token`
- `saml_assertion`
- `pep_assertion`
- `audit_log`
- `browser_session`
- `other:<name>`

## PEP Trust

PEP registration is security-sensitive because it can influence traffic forwarding, local responses, header injection, inspection/tunnel behavior, and audit outcomes.

Keep these settings:

- `decision.fail_policy: deny`
- low assertion TTL
- unique PEP audience
- explicit capabilities
- `auth.active_method: bearer_jwt` while it is the implemented method
- HTTP Message Signatures for `edge-pep` profile
- replay protection for PEP credentials and assertions

The trusted authentication context for a PEP request comes from the verified credential and qid registration. Body fields such as edge name, realm, route, audience, capability, or provider context are declarations to compare with the authenticated registration. They are not proof by themselves.

qid should return only effects permitted by the registration capabilities. The PEP must still validate mapped effects against its own current mode, phase, local policy, and route constraints. Unsupported, malformed, or inconsistent effects should fail closed atomically.

## Sensitive Data in PEP Inputs

PEP decision requests should normally be header/metadata only:

- Do not send raw request bodies for ordinary authorization.
- Prefer derived identity context over raw tokens or session cookies.
- Header names should be normalized before allowlist checks.
- `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, and assertion-bearing headers are denied by default.
- Any opt-in selected header transfer needs redaction and audit.
- Audit can record transmitted header names, but should not record transmitted values.

If raw credential inspection is needed, model it as a token introspection or session validation contract, not as routine PEP decision input.

## Policy Bundles

For policy bundles:

- Use local files at daemon startup.
- Keep bundle paths relative to the config file where possible.
- Do not rely on remote policy bundle sources at startup; `qidd` rejects them.

## SCIM and Provisioning

SCIM routes require bearer tokens with `scim`, `scim.read`, or `scim.write`.

Write methods require `scim` or `scim.write`. Read methods require `scim` or `scim.read`.

The token must be bound to a configured OAuth resource server that allows SCIM scopes through audience or resource indicators.

For SCIM EventSubscriptions, maintain a tight callback allowlist. Wildcards must be of the form `*.example.com`.

## SAML

Enterprise profile requires:

- SAML enabled.
- signed assertions.
- signed metadata.
- XMLDSig signing key path.
- at least one SP.
- SP signing certificates.

When encrypted assertions are required, SP encryption certificates must be configured.

Inbound SAML federation must validate signatures, issuer, audience, destination/recipient, conditions, subject confirmation expiry, and replay state. Missing or unverifiable trust material is a fail-closed condition.

## Metrics and Audit Exposure

Metrics should stay on loopback:

```yaml
observability:
  metrics:
    listen: "127.0.0.1:9464"
```

Metrics labels must stay low-cardinality and non-sensitive. User IDs, email addresses, raw token values, selected header values, and unbounded raw paths do not belong in labels.

Audit export and verification endpoints are admin surfaces. Treat audit archives and WORM output as sensitive because they can contain operational and identity metadata.

## Dependency and Quality Gates

The baseline gate includes `cargo-deny` and `cargo-audit`. `deny.toml` allows common permissive licenses and currently ignores a specific advisory entry. Review advisory ignores periodically.

```sh
cargo run -p xtask -- gate baseline
```
