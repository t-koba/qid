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

When `server.tls.client_ca` is configured, rustls/webpki performs native client certificate path validation before OAuth sees the leaf thumbprint. Optional configured CRLs are checked by the same verifier. qid never trusts a caller-supplied client certificate header; the TLS peer thumbprint is passed through a process-local authenticated metadata boundary. Deployments that terminate mTLS at a PEP must use a registered PEP assertion bound to the reported thumbprint.

## Shared Cache Security

Multi-instance deployments must configure `ops.cache.kind: redis` or `valkey` with a shared endpoint. Process-local memory is not sufficient for replay detection or cross-instance revocation visibility.

Failure behavior is intentionally split by security impact:

- DPoP JTI and JWT assertion replay recording fails closed when the shared cache cannot perform atomic insert-if-absent.
- PEP decision cache and browser session cache failures are treated as cache misses so authorization and session checks fall back to storage or policy evaluation.
- Session revocation deletes the shared cache entry on qid-managed revoke paths and the process-local L1 cache is intentionally short-lived.

## HTTP Layers

`qidd` installs:

- request ID middleware
- request metrics
- CSRF protection (strict for session operations; non-cookie OAuth routes exempt)
- Content Security Policy
- TLS 0-RTT rejection
- HSTS
- standard security headers
- configured CORS

CSRF checks reject cross-site state-changing requests with an `Origin`/`Referer`/`Sec-Fetch-Site` mismatch. Non-cookie OAuth routes authenticate with client credentials, bearer tokens, DPoP/mTLS proof, or PKCE rather than the session cookie and are exempt by exact configured `server.paths` match: token, introspection, revocation, PAR, device/CIBA initiation, dynamic client registration (including the concrete `/:client_id` instance), and `/oauth2/challenge`. Device/CIBA approval sub-paths (`.../approve`) and all session, authorize, logout, and admin operations stay fail-closed. A CORS `allowed_origins` entry does not imply CSRF exemption for session routes.

HTTP Message Signatures can wrap signed OAuth and PEP-facing back-channel routes. Public front-channel and metadata routes stay outside that layer by design.

## Key Material

Local signing keys are stored in `qid-state/` next to the primary config. Protect this directory with filesystem permissions and backup policy appropriate for signing keys.

Set `QID_KEY_PASSPHRASE` or `crypto.key_passphrase_file` before first startup to store generated local signing keys as encrypted `.pem.enc` files. The file format uses Argon2id-derived AES-256-GCM and keeps `kid`, `alg`, and creation time as explicit metadata.

When a passphrase is configured and a plaintext local PEM already exists, `qidd` migrates it on startup by writing the encrypted `.pem.enc` file and moving the plaintext file to `.bak`. Treat the backup as exposed secret material and remove it only after the encrypted key has been tested and backed up.

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

Inbound `qid-saml` XMLDSig preflight rejects DOCTYPE declarations, XML comments,
duplicate IDs across `ID`/`Id`/`id`/`AssertionID` (including namespaced id aliases),
multiple XMLDSig Signature/SignedInfo/Reference elements, external references,
missing or ambiguous targets, wrong SAML target namespaces/types, wrapping forms,
and a Signature outside its referenced target. The enforced profile is exactly
RSA-SHA256 with RSA keys >=2048 bits or ECDSA-SHA256 with P-256, SHA-256
digest, exclusive C14N SignedInfo, and one local `#ID` reference with
enveloped-signature then exclusive C14N.
SHA-1, HMAC, unknown algorithms and unsupported transforms fail before crypto.

Verification uses bergshamra-dsig 0.9.2 with `trusted_keys_only`,
`strict_verification`, and `require_reference_digests` explicitly enabled. It
loads only the key selected by qid's existing trust/profile logic, with no URL
maps, external resolution or network configuration. Embedded KeyInfo cannot
override that key. The caller-selected RSA SubjectPublicKeyInfo key is parsed
and its modulus size checked before candidate verification; keys below 2048 bits
are rejected. AuthnRequest/LogoutRequest certificate pinning to SP metadata
is unchanged. OAuth SAML bearer grant assertions and token-exchange SAML subject
and actor assertions are verified only with certificates from an enabled realm
`protocols.federation.inbound_providers` entry of `kind: saml`; federation must
also be enabled, and the issuer extracted from the verified Assertion tree must
exactly equal that provider's configured issuer. Missing providers or signing
certificates fail closed. Embedded KeyInfo is never trusted or used as fallback.
Browser ACS selection and verification behavior are unchanged. This trust check
does not broaden Conditions or claim broader RFC 7522 conformance.

For OAuth SAML bearer grants and token-exchange SAML subject and actor tokens,
qid maps the realm ID, verified external issuer, and structured NameID from the
verified Assertion to an opaque deterministic `sub`: its text, effective Format,
and optional NameQualifier, SPNameQualifier, and SPProvidedID. An absent Format
uses the SAML Core §2.2.2 default corrected by [SAML 2.0 Approved Errata 05, E60](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html), `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`;
other optional attributes retain their exact parsed presence and value. The
versioned, domain-separated, fixed-order JSON tuple uses SHA-256/base64url and
does not depend on assertion IDs, issue/expiry times, signing certificates or
keys, XML serialization, or request path. This v2 mapping changes subjects
issued by the earlier text-only mapping; consumers relying on those values must
plan that change explicitly. This conservative tuple is not a NameID alias or
format-equivalence rule: changing SPProvidedID can split one external principal
into multiple OAuth subjects, and qid performs no alias resolution. The hash is
not a confidentiality guarantee for guessable identifiers. These OAuth token paths do
not invoke the interactive federation broker's account-link or just-in-time
provisioning behavior and perform no account-link/JIT writes. Token-exchange
`act` claims keep the external issuer and apply the same opaque mapping to
the actor, not raw NameID text.

JWT-bearer assertions and JWT subject tokens in token exchange are verified
against the invoking client's registered `jwks` and require signed `iss` to equal
`client_id`. Their opaque deterministic OAuth `sub` is derived from realm ID,
verified JWT `iss`, and exact JWT `sub`. A domain-separated v1 JSON tuple is
hashed with SHA-256/base64url; the mapping does not depend on JWT serialization,
`jti`, signing key, or grant path. Thus the same `(realm, iss, sub)` is stable
across both paths, while identical subject text from different issuers remains
distinct. This replaces the earlier raw-subject output and does not resolve aliases;
the hash is not a confidentiality guarantee for guessable identifiers.

### Federated subject mapping rollout

The new mapping applies when qid processes a JWT or SAML assertion; it does not
rewrite access-token records or token claims issued under the earlier raw-subject
mappings. Access-token subject and actor exchange reads the persisted `user_id`
and preserves it, so an active pre-mapping token can retain its old raw subject
in `sub` or `act.sub`; repeated exchanges can issue further tokens with that
subject. The persisted record has no reliable federation source and mapping
version for safely reconstructing all earlier identities, so qid does not
heuristically rewrite unversioned IDs.

Before relying on the new mapping, stop all old qid instances and revoke all
pre-cutover access tokens, including tokens created by earlier exchanges. If
all of them cannot be revoked, remove `token-exchange` from every client's
`grant_types` and keep it disabled until every pre-cutover access token has
expired or been revoked. Use the outstanding token expirations or the maximum
access-token lifetime that applied before cutover; `access_token_ttl_seconds` is
configurable. This pause prevents further exchanges but does not itself
invalidate old tokens for ordinary resource access. Qid's revocation state is
checked by qid exchange/introspection paths, but a resource server that validates
a JWT offline without consulting qid or its own denylist cannot see that state;
it can continue accepting a revoked token until the token's signed `exp`. For
immediate resource-level cutover, ensure every resource server honors revocation
(e.g. through introspection or a denylist); otherwise wait for all pre-cutover
JWTs to expire before relying on the new mapping at that server. This is a
one-time cutover procedure, not support for legacy subject aliases.

The verifier retains the parsed Uppsala Document and exact candidate-resolved
NodeId internally; raw DOM/node access is crate-private. `qid-saml` bearer claims
are consumed from that verified Assertion tree.
Federation uses `verify_saml_xml_signature_for` with the explicit Reference target
kind and extracts identity claims and replay IDs from the same verified tree via
`VerifiedSamlDocument::assertion_claims`. A signed Response must have exactly one
direct Assertion for claim extraction; an Assertion signature uses that exact
Assertion's issuer, never the unsigned Response issuer. A signed Response's
direct issuer is covered and may be used. Protocol checks on the separate policy
tree require matching Response/Assertion IDs and the relevant issuer. The
unit-returning compatibility verifier has been removed.
Outbound signing uses the pinned bergshamra-dsig 0.9.2 signer rather than
qid's removed custom canonicalizer. Its fixed profile uses exclusive C14N,
enveloped signatures and SHA-256 with local PKCS#8 RSA >=2048 or P-256 keys.
`sign_saml_document_with_key` returns the complete signed document, binding the
caller-selected unique unqualified `ID` to the expanded Assertion, Response or
EntityDescriptor name. Outbound IDs use the ASCII NCName subset
`[A-Za-z_][A-Za-z0-9_.-]*`; duplicate ID aliases fail closed. Only the supplied
private key is loaded; no KeyInfo is emitted or trusted. The complete parsed
document retains inherited namespaces. When both signatures are requested,
Assertion is signed first so Response covers the inner signature. In SSO, the
IdP signing key is read once: sign the plaintext Assertion, attempt configured
encryption, then sign the final plaintext-or-encrypted Response. The Response
is never signed before encryption. Required encryption failures still reject
issuance; optional encryption failures retain the signed plaintext Assertion.
When signing is not required, the encryption-only path is unchanged. Metadata's
Signature follows optional Extensions and precedes role descriptors (or is the
first element when Extensions is absent).
The inbound single-signature profile and trust controls above are unchanged.
Offline fixture and production-signer coverage is described in
`qid-saml/tests/fixtures/README.md`; no arbitrary XMLDSig, generic-SP or live-IdP
coverage is claimed.

## Metrics and Audit Exposure

Metrics should stay on loopback:

```yaml
observability:
  metrics:
    listen: "127.0.0.1:9464"
```

Metrics labels must stay low-cardinality and non-sensitive. User IDs, email addresses, raw token values, selected header values, and unbounded raw paths do not belong in labels.

Audit export and verification endpoints are admin surfaces. Treat audit archives and WORM output as sensitive because they can contain operational and identity metadata.

## TLS-POK Bootstrap Keys

RFC 9966 bootstrap public keys are authentication key material even though they are not private keys. Store their DER SubjectPublicKeyInfo bytes as sensitive configuration, restrict replacement to an authenticated provisioning path, and audit every registration or rotation. The registered DER bytes must contain exactly one supported EC SubjectPublicKeyInfo with a compressed point; trailing data, uncompressed points, unsupported curves, and ambiguous encodings are rejected.

TLS-POK key selection and the RFC 7250 client Raw Public Key comparison must occur inside the same TLS 1.3 handshake. Do not treat the RFC 9258 imported PSK as a bearer credential, log it, or export it from the TLS process. A TLS backend that cannot negotiate certificate authentication with an external PSK, require `psk_dhe_ke`, generate the `imp binder`, and expose the authenticated Raw Public Key is not sufficient for RFC 9966 deployment.

## TLS Backend Policy

qid follows the same primary backend policy as qpx: rustls is the default and security-critical TLS behavior remains in Rust. qid does not dynamically link OpenSSL and does not depend on wolfSSL or GnuTLS. NoxTLS is also excluded because its available licensing is GPL or commercial rather than the workspace's permissive dependency policy.

RFC 9966 and RFC 6961 require rustls capabilities absent from the pinned upstream base, `v/0.23.46`; see `vendor/rustls/QID-PATCHES.md`. The workspace pins a reviewed source fork through `[patch.crates-io]`; its provenance, patch boundary, and update procedure are recorded there. All ordinary rustls callers continue to use upstream behavior unless they explicitly select the imported-PSK or multi-stapling APIs. The fork must pass both upstream rustls tests and qid's protocol handshake tests before an update is accepted.

Do not introduce a native TLS backend as an implicit fallback. Any future platform-native adapter must be an explicit feature with an independently reviewed use case and must not weaken the RFC 9966, RFC 6961, certificate-path, revocation, or fail-closed guarantees.

## Dependency and Quality Gates

The baseline gate includes `cargo-deny` and `cargo-audit`. `deny.toml` allows common permissive licenses and currently ignores a specific advisory entry. Review advisory ignores periodically.

```sh
cargo run -p xtask -- gate baseline
```
