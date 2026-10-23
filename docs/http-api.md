# HTTP API Surfaces

This file lists routes wired by `qidd`. It is an operator/developer index, not a replacement for protocol specifications.

The route model follows the qid product boundary:

- OIDC/OAuth/SAML/FedCM routes expose qid as IdP, authorization server, and federation broker.
- SCIM/directory/device/workload routes expose qid as lifecycle and identity authority.
- Admin/IGA/risk routes expose qid as control plane.
- AuthZEN and `/pep/decision/v1/evaluate` expose qid as PDP for external PEPs.
- qid does not expose routing, TLS inspection, caching, mirroring, packet capture, or proxy data-plane APIs.

Many paths are configurable through `server.paths`. The table marks those as `configurable`.

Every JSON request body is a JSON object. A JSON body that is an array, or any
other shape, is rejected with HTTP 400 instead of being mapped positionally onto
the request fields. The form-encoded endpoints - the token, revocation,
introspection, CIBA, device authorization, SAML and OIDC logout endpoints - take
form bodies.

## Health, readiness, keys

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | configurable `health`, default `/health` | Returns `ok`. |
| `GET` | configurable `ready`, default `/ready` | Returns `ready`. |
| `GET` | configurable `jwks`, default `/jwks` | Returns active JWKS. |

## OIDC discovery and browser-facing OIDC

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | configurable `well_known_openid_configuration`, default `/.well-known/openid-configuration` | Default realm OIDC discovery. |
| `GET` | `/realms/:realm/.well-known/openid-configuration` | Realm-scoped OIDC discovery. |
| `GET` | configurable `well_known_oauth_authorization_server`, default `/.well-known/oauth-authorization-server` | OAuth AS metadata. |
| `GET` | `/.well-known/oauth-authorization-server/realms/:realm` | Realm-scoped OAuth AS metadata. |
| `GET` | configurable `well_known_oauth_protected_resource`, default `/.well-known/oauth-protected-resource` | Protected resource metadata. |
| `GET, POST` | configurable `authorize`, default `/oauth2/authorize` | Authorization endpoint. Password login is subject to the shared account and realm admission caps; exhaustion returns `temporarily_unavailable` and issues no code. |
| `GET` | configurable `userinfo`, default `/oidc/userinfo` | UserInfo endpoint. |
| `POST` | configurable `logout`, default `/oidc/logout` | Logout. |
| `POST` | configurable `backchannel_logout`, default `/oidc/logout/backchannel` | Back-channel logout. |
| `GET` | configurable `frontchannel_logout`, default `/oidc/logout/frontchannel` | Front-channel logout. |
| `GET` | `/session/check` | Session check iframe. |
| `GET` | `/realms/:realm/session/check` | Realm-scoped session check. |
| `GET` | `/.well-known/webfinger` | WebFinger discovery. |

## OAuth

Routes below are installed for OAuth. When `server.http_message_signatures.enabled` is true, token/introspection/revocation/DCR routes are placed behind HTTP Message Signature verification; public browser and approval routes remain unsigned.

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | configurable `token`, default `/oauth2/token` | Token endpoint. |
| `POST` | configurable `introspect`, default `/oauth2/introspect` | Token introspection (RFC 7662). Requires confidential-client authentication before the token is examined; fails closed with 401 when no OAuth resource server authorizes the caller. |
| `POST` | configurable `revoke`, default `/oauth2/revoke` | Token revocation. |
| `POST` | configurable `dynamic_client_registration`, default `/oauth2/register` | Dynamic client registration. A client id the realm already holds is refused, and so is a client id another realm the deployment serves holds, because such an id names no single client. |
| `GET, PUT, DELETE` | configurable `dynamic_client_registration_management`, default `/oauth2/register/:client_id` | DCR management. |
| `POST` | configurable `device_authorization`, default `/oauth2/device_authorization` | Device authorization. |
| `POST` | `<device_authorization>/approve` | Device flow approval. |
| `GET` | configurable `device_verification`, default `/oauth2/device` | Device verification interaction page. |
| `POST` | configurable `backchannel_authentication`, default `/oauth2/backchannel-authentication` | CIBA back-channel authentication. |
| `POST` | `<backchannel_authentication>/approve` | CIBA approval. |
| `POST` | `/oauth2/challenge` | OAuth challenge helper. |
| `POST` | configurable `par`, default `/oauth2/par` | Pushed Authorization Request, installed when PAR is enabled. |

## Session, WebAuthn, TOTP

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | configurable `auth_password`, default `/api/v1/:realm/auth/password` | Password authentication. A login is admitted before any credential is verified: the submitted email's admission count follows the realm's `password.max_failed_attempts` within `password.lockout_duration_seconds`, and the realm's admission count follows the realm's `password.max_failed_attempts_per_realm` within the same window; a successful login gives back the admission it spent on the address and on the realm. A refused admission, a locked account, and a realm that has spent its budget of failed password logins answer `429 Too Many Requests`. |
| `POST` | configurable `auth_session_refresh`, default `/api/v1/:realm/auth/session/refresh` | Refresh browser session. |
| `POST` | configurable `auth_session_revoke`, default `/api/v1/:realm/auth/session/revoke` | Revoke browser session. |
| `POST` | configurable `auth_webauthn_start`, default `/api/v1/:realm/auth/webauthn/start` | WebAuthn registration start. |
| `POST` | configurable `auth_webauthn_finish`, default `/api/v1/:realm/auth/webauthn/finish` | WebAuthn registration finish. |
| `POST` | configurable `auth_webauthn_auth_start`, default `/api/v1/:realm/auth/webauthn/auth/start` | WebAuthn auth start. |
| `POST` | configurable `auth_webauthn_auth_finish`, default `/api/v1/:realm/auth/webauthn/auth/finish` | WebAuthn auth finish. |
| `POST` | configurable `auth_webauthn_discoverable_start`, default `/api/v1/:realm/auth/webauthn/discoverable/start` | Discoverable credential auth start. |
| `POST` | configurable `auth_webauthn_discoverable_finish`, default `/api/v1/:realm/auth/webauthn/discoverable/finish` | Discoverable credential auth finish. |
| `POST` | `/api/v1/:realm/auth/totp/enroll` | Enroll TOTP. |
| `POST` | `/api/v1/:realm/auth/totp/verify` | Verify enrolled TOTP. |
| `POST` | `/api/v1/:realm/auth/totp/authenticate` | TOTP authentication. |

WebAuthn ceremonies are single-use and live for five minutes, the timeout the
ceremony options advertise. A realm holds at most 4096 live ceremonies per
ceremony kind, so an unauthenticated caller of the discoverable start route
cannot grow the ceremony state without limit. The discoverable finish route
consumes the ceremony before it reads the realm's user table, so a finish
without a live ceremony is refused without reading the realm.

## Admin API

Admin mutations require admin authorization checks and, depending on config, reason, step-up, approval, or break-glass controls.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/admin/ui` | Basic admin UI. |
| `GET` | `/admin/api/v1/ui/dashboard` | Dashboard data. |
| `POST` | `/admin/api/v1/breakglass/sessions/:session_id/revoke` | Revoke break-glass session. |
| `POST` | `/admin/api/v1/key-rotation/plan` | Admin key rotation planning. |
| `POST` | `/admin/api/v1/:realm/policy/simulate` | Simulate policy. |
| `GET, POST` | `/admin/api/v1/realms` | List/create realms. |
| `GET, DELETE` | `/admin/api/v1/realms/:realm` | Get/delete realm. |
| `GET, POST` | `/admin/api/v1/:realm/users` | List/create users. A user id the deployment already holds is refused, and so is an email the realm already holds for another user. |
| `GET, PUT, DELETE` | `/admin/api/v1/:realm/users/:user_id` | Get/update/delete user. An update that gives the user an email another user of the realm already holds is refused. |
| `GET` | `/admin/api/v1/:realm/sessions` | List sessions. |
| `POST` | `/admin/api/v1/:realm/sessions/:session_id/revoke` | Revoke session. |
| `GET` | `/admin/api/v1/:realm/token-families` | List token families. |
| `POST` | `/admin/api/v1/:realm/token-families/:family_id/revoke` | Revoke token family. |
| `GET` | `/admin/api/v1/:realm/pep-decisions` | List PEP decisions. |
| `GET` | `/admin/api/v1/:realm/risk-events` | List risk events. |
| `GET, POST` | `/admin/api/v1/:realm/clients` | List/create clients. A client id the realm already holds is refused, and so is a client id another realm the deployment serves holds. |
| `DELETE` | `/admin/api/v1/:realm/clients/:client_id` | Delete client. |
| `GET, POST` | `/admin/api/v1/:realm/service-accounts` | List/create service accounts. |
| `DELETE` | `/admin/api/v1/:realm/service-accounts/:sa_id` | Delete service account. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/custom-domains` | List/create or update same-tenant domains. IDs are global; reuse by another tenant returns `409 Conflict` without changing the incumbent. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id` | Delete custom domain. |
| `POST` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/activate` | Activate custom domain. |
| `POST` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/renew-certificate` | Renew custom domain certificate. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/app-catalog` | List/create app catalog entries. IDs are globally unique; duplicate POST IDs return `409 Conflict` without replacing the incumbent. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/app-catalog/:entry_id` | Delete app catalog entry. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/ciam-brands` | List/create or update same-tenant CIAM brands. IDs are global; reuse by another tenant returns `409 Conflict` without changing the incumbent. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/ciam-brands/:brand_id` | Delete CIAM brand. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/marketplace-connectors` | List/create marketplace connectors; duplicate connector IDs return `409 Conflict`. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/marketplace-connectors/:connector_id` | Delete marketplace connector. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/usage-billing-events` | List/create usage billing events; duplicate IDs return `409 Conflict`, and idempotency keys are tenant-scoped. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/compliance-evidence-packs` | List/create compliance evidence packs; duplicate pack IDs return `409 Conflict`. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/delegated-admins` | List/create or update same-tenant delegated admins. IDs are global; reuse by another tenant returns `409 Conflict` without changing the incumbent. |
| `POST` | `/admin/api/v1/tenants/:tenant/delegated-admins/:admin_id/revoke` | Revoke delegated admin. |
| `GET` | `/admin/api/v1/audit/export` | Export global audit. |
| `GET` | `/admin/api/v1/:realm/audit/export` | Export realm audit. |
| `GET` | `/admin/api/v1/audit/verify` | Verify global audit chain. |
| `GET` | `/admin/api/v1/:realm/audit/verify` | Verify realm audit chain. |
| `GET, PUT` | `/admin/api/v1/audit/retention` | Get/update global retention. |
| `GET` | `/admin/api/v1/audit/retention/plan` | Plan global retention. |
| `GET, PUT` | `/admin/api/v1/:realm/audit/retention` | Get/update realm retention. |
| `GET` | `/admin/api/v1/:realm/audit/retention/plan` | Plan realm retention. |
| `GET` | `/admin/api/v1/audit` | List global audit events. |
| `GET` | `/admin/api/v1/:realm/audit` | List realm audit events. |

## PEP, AuthZEN, Captive Portal

AuthZEN-style evaluation is the generic subject/resource/action access surface. The PEP decision API is the richer low-latency PDP surface for proxies, gateways, service meshes, resource servers, and qpx-like edges that need decision metadata and qid-owned obligations.

qid only authenticates the PEP through credential-bound registration. Request body fields are verified against that registration and policy; they are not trusted identity by themselves. qid response semantics remain qid-owned. A PEP maps the response to its own enforceable effect schema and must validate capabilities fail-closed before enforcement.

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | configurable `authzen_evaluation`, default `/access/v1/evaluation` | AuthZEN-style evaluation. |
| `POST` | configurable `pep_decision`, default `/pep/decision/v1/evaluate` | Generic PEP decision API. |
| `GET` | configurable `assertion`, default `/pep/:realm/assertion` | Issue short-lived PEP assertion. |
| `POST` | `/api/v1/:realm/captive-portal/bind` | Bind captive portal session. |
| `POST` | `/api/v1/:realm/captive-portal/unbind` | Unbind captive portal session. |
| `GET` | `/api/v1/:realm/captive-portal/lookup` | Lookup captive portal binding. |
| `GET` | configurable `capport_details`, default `/api/v1/:realm/captive-portal/api/v1/details` | CAPPORT details. |

CAPPORT routes are mounted only when at least one realm enables
`network_aaa.capport` (default `false`), and every CAPPORT handler rejects
realms without the flag, so enabling one realm never enables another.

## SCIM

SCIM base path defaults to `/scim/v2` and can be configured per realm.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `<base>/ServiceProviderConfig` | SCIM service provider config. |
| `GET` | `<base>/Schemas` | Schemas. |
| `GET` | `<base>/ResourceTypes` | Resource types. |
| `GET, POST` | `<base>/Users` | List/create users. |
| `GET, PUT, PATCH, DELETE` | `<base>/Users/:id` | User resource. |
| `GET, POST` | `<base>/Groups` | List/create groups. |
| `GET, PUT, PATCH, DELETE` | `<base>/Groups/:id` | Group resource. |
| `POST` | `<base>/Bulk` | Bulk operation. |
| `GET, POST` | `<base>/Devices` | SCIM Device resource. |
| `GET, DELETE` | `<base>/Devices/:id` | Device resource. |
| `GET, POST` | `<base>/EventSubscriptions` | SCIM EventSubscriptions. |
| `GET, DELETE` | `<base>/EventSubscriptions/:id` | EventSubscription resource. |

SCIM routes are protected by bearer token checks. Accepted scopes are `scim`, `scim.read`, and `scim.write`; write methods require `scim` or `scim.write`.

User schema discovery lists only core User and the Enterprise User extension. Custom User extensions are unsupported: non-empty `protocols.scim.custom_schemas` fails configuration validation, and writes carrying another User schema ID or top-level extension URN return HTTP 400 (including PATCH and Bulk) instead of silently discarding values. Every SCIM write body must be a JSON object: a JSON sequence is rejected with HTTP 400 instead of being mapped positionally onto the payload, and the same holds for the complex containers. The advertised complex containers are validated before they are stored: `name` must be an object whose advertised subattributes are strings, `emails` an array of objects whose `primary` subattribute is a boolean and whose other advertised subattributes are strings, `members` an array of member objects, and the Enterprise User extension an object. The schema discovery owns that vocabulary, so a subattribute it does not advertise is rejected rather than stored unchecked; the Enterprise User extension is the one exception, because its server-owned `deprovisioned_at` marker is accepted and stripped. A malformed container is a client error (HTTP 400) on create, replace, patch and Bulk, and the stored record is left unchanged.

Device IDs and EventSubscription IDs are global within each resource type. POST inserts a new ID or deliberately upserts an existing ID in the authenticated realm (both return `201`). The authenticated context, not a supplied body realm, determines ownership. Reusing another realm's ID returns `409 Conflict` and leaves the incumbent record unchanged; ownership is enforced atomically by storage.

Device and EventSubscription writes accept only the implemented attribute names; any other name is rejected with `400` instead of being dropped. `POST <base>/Devices` takes `id` (optional; the server assigns one when it is omitted), `displayName`, the `realm` scoping attribute the User and Group writes share, and the device extension container `urn:ietf:params:scim:schemas:extension:device:2.0:Device` with `manufacturer`, `model`, `os`, `osVersion` and `lastSeen`. `POST <base>/EventSubscriptions` takes `id` (optional), `callback`, `eventTypes`, `enabled` (default `true`), the same `realm` scoping attribute, and `createdAt`, which is server-owned, so a supplied value is accepted and ignored. A `schemas` entry outside the implemented schemas is rejected the same way. Responses carry the advertised attributes only: the realm is not echoed, because ownership follows the authenticated token.

Inbound SCIM is an isolated provisioning registry: setting `active` to false or deleting a user affects only the SCIM record (plain DELETE is a soft delete that deactivates but retains the record; hard delete needs `hard_delete=true`). There is no binding from a SCIM user to a login identity, so SCIM mutations do not revoke sessions or tokens — suspension policy must define that binding explicitly before it can act on login state.

Lifecycle deprovision timestamp (`deprovisioned_at`) is server-owned: directory and HR sync are the only writers, SCIM create never sets it, PUT/PATCH preserve it, and the SCIM `enterprise` extension only projects the trusted value (a client-supplied or legacy `enterprise.deprovisioned_at` marker is stripped on write and never rendered when the authority is `None`). Legacy `enterprise_json` markers from before the server-owned column existed are not trusted and are never backfilled; old rows read as `None` until a lifecycle transition stamps them. Preserve historical evidence only through an explicit reviewed migration. LDAP disabled snapshots stamp the first transition and preserve it across repeated snapshots; reactivation (LDAP enabled snapshot or HR joiner/mover that sets `active`) clears the timestamp and stale marker so a later disable gets a fresh timestamp.

## SAML

Installed when any realm enables SAML; each endpoint also checks that the requested realm enables SAML.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/saml/:realm/metadata` | IdP metadata. |
| `POST` | `/saml/:realm/sso` | SSO endpoint. |
| `POST` | `/saml/:realm/slo` | SLO endpoint. |
| `GET` | `/saml/:realm/slo/initiate` | Initiate SLO. |
| `POST` | `/saml/:realm/artifact` | Artifact resolution. |
| `POST` | `/saml/:realm/attribute-query` | Strict signed SOAP 1.1 AttributeQuery; configured realm-local SP certificate required. |

### AttributeQuery subset

Requires `protocols.saml.enabled` (default `false`) and an SP's
`service_providers[].signing_certificates` in the requested realm (default empty,
so no requester is trusted). The request must be a SOAP 1.1 Envelope containing
only one direct Body, containing only one direct SAML protocol AttributeQuery.
The query must have one direct assertion-namespace Issuer, one direct XMLDSig
Signature, and one direct Subject containing one NameID. SOAP headers, alternative
subjects, Extensions and attribute selectors are unsupported and rejected.

Only configured certificates are tried; unsigned Issuer and document KeyInfo do
not select or supply trust. The strict [XMLDSig subset](standards.md) verifies the
query's exact `#ID` target before Issuer, ID, NameID and Format are read from that
same verified node. The verified Issuer must equal the SP owning the verifying
configured key. Duplicate/decoy queries, ID aliases and wrapped targets fail
closed. No arbitrary XMLDSig or generic-SP interoperability is claimed.

Email-format NameIDs use realm-local email lookup; other formats (including
absent Format) use realm-local user ID lookup. Foreign-realm and missing subjects
both return `UnknownPrincipal` without attributes. The existing SP
`attribute_release_policy` applies to `email` and `displayName`: a nonempty list
releases only listed names; an empty list releases both available attributes.
This does not alter SSO attribute-release behavior. Successful SOAP Responses
contain an unsigned SAML Assertion with its own ID, Version, IssueInstant and
direct IdP Issuer. Its Subject/NameID preserves the verified query's exact value
and Format (including absent Format), and its AttributeStatement contains only
attributes permitted by that SP's release policy. The Response's InResponseTo is
the verified query ID. Both Response and Assertion remain unsigned; no response
signing, encryption, freshness/replay guarantee or full SAML conformance is claimed.

Authentication/profile failures return HTTP 403 with `RequestDenied`; unknown
principals return HTTP 200 with `UnknownPrincipal`; repository failures return
HTTP 500 with a generic `Responder` status. Failure responses do not echo request
IDs, subject values, parser/storage details or attributes. Disabled/unknown
realms return HTTP 404.

## FedCM, federation, CIAM

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/.well-known/web-identity` | FedCM web identity manifest. Lists the configured realms that enable the FedCM protocol. |
| `GET` | `/.well-known/fedcm.json` | FedCM config of the realm that enables the FedCM protocol. Absent when no realm enables it; ambiguous (`400`) when several do. |
| `GET` | `/realms/:realm/.well-known/fedcm.json` | FedCM config of one realm. Absent for a realm that does not enable the FedCM protocol. |
| `GET, POST` | `/api/v1/:realm/fedcm/accounts` | List/create FedCM accounts. Served only for a realm that enables the FedCM protocol; absent (`404`) for every other realm. |
| `POST` | `/api/v1/:realm/fedcm/token` | Generate FedCM token. Served only for a realm that enables the FedCM protocol; absent (`404`) for every other realm. |
| `GET` | `/.well-known/openid-federation` | Federation entity statement. |
| `POST` | `/federation/v1/trust-chain/validate` | Validate trust chain. |
| `POST` | `/federation/:realm/discover` | Discover inbound provider. |
| `GET` | `/federation/:realm/oidc/callback` | OIDC broker callback. |
| `POST` | `/federation/:realm/saml/acs` | SAML inbound ACS. |
| `GET` | `/federation/:realm/social/:provider/callback` | Social login callback. |
| `POST` | `/api/v1/:realm/ciam/profile/plan` | CIAM profile plan. |
| `POST` | `/api/v1/:realm/ciam/profile/submit` | Submit progressive profile. |
| `POST` | `/api/v1/:realm/ciam/passwordless/migrate` | Passwordless migration. |
| `GET` | `/api/v1/:realm/ciam/passwordless/campaign` | Passwordless campaign. |
| `POST` | `/api/v1/:realm/ciam/consent/evaluate` | Evaluate consent. |
| `POST` | `/api/v1/:realm/ciam/consent/grants` | Grant consent. Grant IDs are global and bound to `(realm, user, client)`; foreign-owner ID reuse returns `409 Conflict` without changing the incumbent. Same-owner updates remain supported. |
| `POST` | `/api/v1/:realm/ciam/identity-links` | Session authentication required; all writes return `400 Bad Request` because this surface has no provider proof. No link or create audit is persisted. |
| `POST` | `/api/v1/:realm/ciam/identity-links/lookup` | Lookup a verified identity link only. |
| `GET` | `/api/v1/:realm/ciam/users/:user_id/identity-links` | List identity links. |
| `DELETE` | `/api/v1/:realm/ciam/identity-links/:link_id` | Delete identity link. |
| `GET` | `/api/v1/:realm/ciam/privacy/:user_id` | Privacy dashboard. |
| `POST` | `/api/v1/:realm/ciam/verification/issue` | Returns `501 Not Implemented` until a delivery mechanism is implemented; no challenge is stored. |
| `POST` | `/api/v1/:realm/ciam/verification/confirm` | Returns `501 Not Implemented` until delivery and finite per-challenge attempt protection are implemented; no challenge is read or consumed. |
| `POST` | `/api/v1/:realm/ciam/password-reset/issue` | Returns `501 Not Implemented` until a delivery mechanism is implemented; no reset token is stored. |
| `POST` | `/api/v1/:realm/ciam/password-reset/consume` | Consume password reset. |
| `POST` | `/api/v1/:realm/ciam/protection/evaluate` | Protection/risk evaluation. |

Identity links are written only by trusted federation callbacks after validating provider
assertions. The session-only POST surface rejects both `verified: true` and
`verified: false` after authentication with `400 Bad Request`; a local session is
not proof of control over an external identity. List/delete and the privacy dashboard
remain available to the owning session; external-subject lookup ignores unverified
legacy rows, which cannot authenticate or reserve a subject.

At the storage boundary, identity-link IDs are global and bound to
`(realm_id, user_id, provider, external_subject)`. Reusing an ID for another owner or
identity key conflicts without changing the incumbent. Same-owner profile/contact
updates and verification promotion remain supported, but verified links cannot be
downgraded. External subjects are unique per realm/provider among verified links
only; a trusted verified mapping can coexist with unverified legacy rows.

## Device, workload, SPIFFE

| Method | Path | Notes |
| --- | --- | --- |
| `GET, POST` | `/api/v1/:realm/devices` | List/register devices. |
| `PUT` | `/api/v1/:realm/devices/:device_id/heartbeat` | Device heartbeat. |
| `POST` | `/api/v1/:realm/workload-identities` | Register a workload identity; `201 Created` for a new SPIFFE ID and `200 OK` for one the realm already holds. |
| `GET` | `/api/v1/:realm/workload-identities/:spiffe_id` | Get workload identity. |
| `GET, POST` | `/api/v1/:realm/workload-certificates` | List/issue workload certificates. |
| `POST` | `/api/v1/:realm/workload-certificates/:certificate_id/revoke` | Revoke workload certificate. |
| `GET` | `/api/v1/:realm/spiffe/workload-api/x509-svid` | Fetch X.509-SVID. |
| `GET` | `/api/v1/:realm/spiffe/workload-api/jwt-svid` | Fetch JWT-SVID. |
| `GET` | `/.well-known/spiffe-bundle` | SPIFFE bundle. |

Workload and SPIFFE routes are only merged in the `workload` profile.

One SPIFFE ID names one workload identity in a realm. Registering that SPIFFE
ID again updates the identity that carries it: the identity keeps its ID, and
every field the registration does not state keeps the stored value, so a
registration that states only a description leaves the recorded authorities
alone. An identity ID that belongs to another realm's identity is a conflict,
and the trust domain of a registration must be the
trust domain its SPIFFE ID names. A SPIFFE ID that carries whitespace, a query
or no trust domain is refused wherever it is named.

## IGA and ReBAC

| Method | Path | Notes |
| --- | --- | --- |
| `GET, POST` | `/iga/v1/entitlements` | List/upsert entitlement. |
| `DELETE` | `/iga/v1/entitlements/:id` | Delete entitlement. |
| `GET, POST` | `/iga/v1/access-packages` | List/upsert access package. |
| `DELETE` | `/iga/v1/access-packages/:id` | Delete access package. |
| `POST` | `/iga/v1/access-requests` | Create access request. |
| `POST` | `/iga/v1/access-requests/approvals/validate` | Validate approvals. |
| `GET` | `/iga/v1/access-grants` | List access grants. |
| `POST` | `/iga/v1/access-grants/:id/revoke` | Revoke grant. |
| `GET, POST` | `/iga/v1/jit-privileges` | List/issue JIT privilege. |
| `POST` | `/iga/v1/jit-privileges/:id/revoke` | Revoke JIT privilege. |
| `GET, POST` | `/iga/v1/access-reviews` | Create access review from stored grants and findings; caller evidence fields are ignored. |
| `POST` | `/iga/v1/access-reviews/:id/close` | Close access review. |
| `GET, POST` | `/iga/v1/access-reviews/:id/decisions` | List/create review decisions. |
| `GET, POST` | `/iga/v1/certifications` | List/create certifications. |
| `GET` | `/iga/v1/findings` | List findings. |
| `POST` | `/iga/v1/findings/detect` | Detect SoD-conflict findings from active grants. |
| `POST` | `/iga/v1/findings/:id/resolve` | Resolve finding. |
| `GET` | `/iga/v1/evidence` | Export IGA evidence. |
| `POST` | `/iga/v1/rebac/check` | ReBAC check. |
| `POST` | `/iga/v1/rebac/expand` | ReBAC expand. |
| `POST` | `/iga/v1/rebac/tuples` | Write tuples. |
| `POST` | `/iga/v1/rebac/tuples/delete` | Delete tuples. |
| `POST` | `/iga/v1/rebac/tuples/read` | Read tuples. |

## Directory, risk, SSF, VC

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/directory/v1/providers` | List directory providers, including disabled bindings, their `enabled`/`syncable` flags, and supported pull/inbound types. |
| `GET` | `/directory/v1/providers/:id` | Read provider configuration (`404` for unknown IDs); connection and sync settings are managed through QID configuration. |
| `PATCH` | `/directory/v1/providers/:id` | Unsupported (`501` for configured providers, `404` for unknown IDs); no provider status is asserted or changed. |
| `POST` | `/directory/v1/providers/:id/sync` | Unsupported over HTTP (`501` for configured providers, `404` for unknown IDs); no job is scheduled. Use `qid-worker directory-sync --realm <realm> --provider-id <id>` for LDAP/AD/CSV only. |
| `GET` | `/directory/v1/providers/:id/sync/status` | Unsupported (`501` for configured providers, `404` for unknown IDs); the HTTP API does not track sync-job state. |
| `POST` | `/directory/v1/providers/:id/hr` | Synchronous ordered HR batch for an enabled configured webhook binding; see below. |
| `POST` | `/risk/v1/evaluate` | Evaluate risk. |
| `GET` | `/.well-known/ssf-configuration` | SSF config. |
| `GET` | `/realms/:realm/.well-known/ssf-configuration` | Realm SSF config. |
| `GET, POST` | `/ssf/stream` | List/create SSF streams. |
| `GET, POST` | `/realms/:realm/ssf/stream` | Realm stream operations. |
| `GET, DELETE` | `/ssf/stream/:stream_id` | Get/delete SSF stream. |
| `GET, DELETE` | `/realms/:realm/ssf/stream/:stream_id` | Realm get/delete SSF stream. |
| `POST` | `/ssf/events` | Receive SSF event. |
| `POST` | `/realms/:realm/ssf/events` | Realm SSF event. |
| `GET` | `/.well-known/openid-credential-issuer` | OID4VCI metadata. |
| `POST` | `/vc/v1/credential` | Credential endpoint. |
| `GET` | `/vc/v1/status/:credential_id` | Public credential status: revocation and expiry only, no subject or revocation details. |
| `POST` | `/vc/v1/status/:credential_id/revoke` | Revoke credential status. |
| `POST` | `/vc/v1/presentation/verify` | Verify presentation. |

VC routes are only merged in the `vc` profile.

### Inbound HR lifecycle batches

`POST /directory/v1/providers/:id/hr?realm=<realm>` requires
`x-qid-admin-session-id`, the existing administrator step-up/elevation policy,
and one of `tenant.owner`, `realm.admin`, `directory.admin`, or `security.admin`.
The realm selector follows the directory routes: it may be omitted only for a
single configured realm. Its configured `tenant_id` must match the session's
administrator and elevation tenant. A path/query identifier selects a resource,
never authorizes it. Directory and selected provider must both be enabled,
and the provider type must be `webhook`. There is no unauthenticated fallback,
new secret, pull job or deployment-exposure setting.

The body must use `Content-Type: application/json` (optional parameters such as
`charset` are accepted) and is a strict JSON object (not an array), with only
`sequence` and `records`; each record is an object with only the fields shown
below. Unknown fields, including caller-supplied realm/tenant/provider authority,
are rejected.
Required nonblank record fields are `external_id` and `user_name`; `event` is
also required and is `joiner`, `mover`, or `leaver`. The four other fields are
optional strings or null. On movers, absent/null department and manager clear
those stored values; joiner/leaver absent department/manager preserve them.
Joiner and mover absent email/display-name clear those projections; leavers
preserve them. HR target lookup matches raw external ID uniquely within the
realm, including provider-owned users; duplicates/ambiguity are never resolved
by choosing a first match.

```json
{
  "sequence": 1,
  "records": [{
    "external_id": "employee-example",
    "user_name": "worker@example.com",
    "event": "joiner",
    "email": "worker@example.com",
    "display_name": "Example Worker",
    "department": "Research",
    "manager_external_id": null
  }]
}
```

The sequence is a positive integer in 1..=9,223,372,036,854,775,807, contiguous
per `(realm_id, provider_id)`, starting at 1. Empty batches are allowed and
advance the sequence. The source **must send batches in order**. On a timeout,
connection failure or uncertain response, retry the **identical sequence and
exact request bytes**, including whitespace and field ordering; qid hashes the
accepted bytes with SHA-256, not a normalized JSON representation.

- Next contiguous sequence: fully preflight, revalidate targeted expected users
  at backend serialization, and commit all user mutations and the receipt together.
- Latest sequence plus identical bytes: `200` with the stored summary and
  `replayed: true`, with no user or receipt writes.
- Latest sequence with different bytes, any gap, zero/out-of-range or stale
  sequence: `409`, no effects. An old joiner cannot reactivate a user after a
  later leaver by replaying its old sequence.
- Duplicate external IDs in a batch, ambiguous realm targets, missing leaver
  targets, username collisions or targets changed since planning also produce
  `409`, with no batch effects or sequence advance.

Only the latest successful sequence, request digest and non-PII counters are
retained per binding; older response history is not retained. Provider IDs must
remain stable and **must not be reused for a different source**. A successful
response contains no employee identifiers, names, emails or record results:

```json
{"sequence":1,"created":1,"updated":0,"deprovisioned":0,"replayed":false}
```

Both file and SQL backends commit atomically. File imports persist a candidate
under the save/state locks before publishing it in memory, even with interval
flushing; once started they finish despite request cancellation. SQL uses one
transaction with a guarded sequence advance and serialized target revalidation.
This is **durable ordered idempotency for this binding**, not exactly-once across
network or external effects. The route does not perform external provisioning.

Failure responses contain no record values. A non-`application/json` content
type returns `415`; invalid JSON/shape/unknown fields or blank required
`external_id`/`user_name` return `400`; byte or record ceilings return `413`
before preflight. Missing or
ineligible administrator sessions/tenant bindings return `401`; unknown configured
realm/provider returns `404`; a disabled directory/provider or non-webhook type
returns `403`. No import has started for these failures. `409` means no effects
from this attempt. Storage/connection/commit uncertainty returns `503` instructing
an identical retry; it does **not** claim rollback or commit. If the response is
lost, retry identically regardless of whether the caller saw a status. Do not
change the body/sequence to work around an uncertain outcome. Limits and their
bounded defaults are documented in [configuration](configuration.md#inbound-hr-webhook-bindings).
