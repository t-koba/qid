# HTTP API Surfaces

This file lists routes wired by `qidd`. It is an operator/developer index, not a replacement for protocol specifications.

The route model follows the qid product boundary:

- OIDC/OAuth/SAML/FedCM routes expose qid as IdP, authorization server, and federation broker.
- SCIM/directory/device/workload routes expose qid as lifecycle and identity authority.
- Admin/IGA/risk routes expose qid as control plane.
- AuthZEN and `/pep/decision/v1/evaluate` expose qid as PDP for external PEPs.
- qid does not expose routing, TLS inspection, caching, mirroring, packet capture, or proxy data-plane APIs.

Many paths are configurable through `server.paths`. The table marks those as `configurable`.

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
| `GET, POST` | configurable `authorize`, default `/oauth2/authorize` | Authorization endpoint. |
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
| `POST` | configurable `introspect`, default `/oauth2/introspect` | Token introspection. |
| `POST` | configurable `revoke`, default `/oauth2/revoke` | Token revocation. |
| `POST` | configurable `dynamic_client_registration`, default `/oauth2/register` | Dynamic client registration. |
| `GET, PUT, DELETE` | configurable `dynamic_client_registration_management`, default `/oauth2/register/:client_id` | DCR management. |
| `POST` | configurable `device_authorization`, default `/oauth2/device_authorization` | Device authorization. |
| `POST` | `<device_authorization>/approve` | Device flow approval. |
| `POST` | configurable `backchannel_authentication`, default `/oauth2/backchannel-authentication` | CIBA back-channel authentication. |
| `POST` | `<backchannel_authentication>/approve` | CIBA approval. |
| `POST` | `/oauth2/challenge` | OAuth challenge helper. |
| `POST` | configurable `par`, default `/oauth2/par` | Pushed Authorization Request, installed when PAR is enabled. |

## Session, WebAuthn, TOTP, push, email magic link

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | configurable `auth_password`, default `/api/v1/:realm/auth/password` | Password authentication. |
| `POST` | configurable `auth_session_refresh`, default `/api/v1/:realm/auth/session/refresh` | Refresh browser session. |
| `POST` | configurable `auth_session_revoke`, default `/api/v1/:realm/auth/session/revoke` | Revoke browser session. |
| `POST` | configurable `auth_webauthn_start`, default `/api/v1/:realm/auth/webauthn/start` | WebAuthn registration start. |
| `POST` | configurable `auth_webauthn_finish`, default `/api/v1/:realm/auth/webauthn/finish` | WebAuthn registration finish. |
| `POST` | configurable `auth_webauthn_auth_start`, default `/api/v1/:realm/auth/webauthn/auth/start` | WebAuthn auth start. |
| `POST` | configurable `auth_webauthn_auth_finish`, default `/api/v1/:realm/auth/webauthn/auth/finish` | WebAuthn auth finish. |
| `POST` | configurable `auth_webauthn_discoverable_start`, default `/api/v1/:realm/auth/webauthn/discoverable/start` | Discoverable credential auth start. |
| `POST` | configurable `auth_webauthn_discoverable_finish`, default `/api/v1/:realm/auth/webauthn/discoverable/finish` | Discoverable credential auth finish. |
| `POST` | configurable `auth_email_magic_link_send`, default `/api/v1/:realm/auth/email-magic-link/send` | Send magic link. |
| `POST` | configurable `auth_email_magic_link_verify`, default `/api/v1/:realm/auth/email-magic-link/verify` | Verify magic link. |
| `POST` | `/api/v1/:realm/auth/totp/enroll` | Enroll TOTP. |
| `POST` | `/api/v1/:realm/auth/totp/verify` | Verify enrolled TOTP. |
| `POST` | `/api/v1/:realm/auth/totp/authenticate` | TOTP authentication. |
| `POST` | `/api/v1/:realm/auth/push/register` | Register push MFA device. |
| `POST` | `/api/v1/:realm/auth/push/challenge` | Create push MFA challenge. |
| `POST` | `/api/v1/:realm/auth/push/verify` | Verify push MFA challenge. |
| `GET` | `/api/v1/:realm/auth/push/devices` | List push devices. |
| `DELETE` | `/api/v1/:realm/auth/push/devices/:device_id` | Remove push device. |

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
| `GET, POST` | `/admin/api/v1/:realm/users` | List/create users. |
| `GET, PUT, DELETE` | `/admin/api/v1/:realm/users/:user_id` | Get/update/delete user. |
| `GET` | `/admin/api/v1/:realm/sessions` | List sessions. |
| `POST` | `/admin/api/v1/:realm/sessions/:session_id/revoke` | Revoke session. |
| `GET` | `/admin/api/v1/:realm/token-families` | List token families. |
| `POST` | `/admin/api/v1/:realm/token-families/:family_id/revoke` | Revoke token family. |
| `GET` | `/admin/api/v1/:realm/pep-decisions` | List PEP decisions. |
| `GET` | `/admin/api/v1/:realm/risk-events` | List risk events. |
| `GET, POST` | `/admin/api/v1/:realm/clients` | List/create clients. |
| `DELETE` | `/admin/api/v1/:realm/clients/:client_id` | Delete client. |
| `GET, POST` | `/admin/api/v1/:realm/service-accounts` | List/create service accounts. |
| `DELETE` | `/admin/api/v1/:realm/service-accounts/:sa_id` | Delete service account. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/custom-domains` | List/create custom domains. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id` | Delete custom domain. |
| `POST` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/activate` | Activate custom domain. |
| `POST` | `/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/renew-certificate` | Renew custom domain certificate. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/app-catalog` | List/create app catalog entries. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/app-catalog/:entry_id` | Delete app catalog entry. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/ciam-brands` | List/create CIAM brands. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/ciam-brands/:brand_id` | Delete CIAM brand. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/marketplace-connectors` | List/create marketplace connectors. |
| `DELETE` | `/admin/api/v1/tenants/:tenant/marketplace-connectors/:connector_id` | Delete marketplace connector. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/usage-billing-events` | List/create usage billing events. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/compliance-evidence-packs` | List/create compliance evidence packs. |
| `GET, POST` | `/admin/api/v1/tenants/:tenant/delegated-admins` | List/create delegated tenant admins. |
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
| `GET` | `/api/v1/:realm/captive-portal/api/v1/details` | CAPPORT details. |

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

## SAML

Installed when any realm enables SAML.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/saml/:realm/metadata` | IdP metadata. |
| `POST` | `/saml/:realm/sso` | SSO endpoint. |
| `POST` | `/saml/:realm/slo` | SLO endpoint. |
| `GET` | `/saml/:realm/slo/initiate` | Initiate SLO. |
| `POST` | `/saml/:realm/artifact` | Artifact resolution. |
| `POST` | `/saml/:realm/attribute-query` | Attribute query. |

## FedCM, federation, CIAM

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/.well-known/web-identity` | FedCM web identity manifest. |
| `GET` | `/.well-known/fedcm.json` | FedCM config. |
| `GET, POST` | `/api/v1/:realm/fedcm/accounts` | List/create FedCM accounts. |
| `POST` | `/api/v1/:realm/fedcm/token` | Generate FedCM token. |
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
| `POST` | `/api/v1/:realm/ciam/consent/grants` | Grant consent. |
| `POST` | `/api/v1/:realm/ciam/identity-links` | Create identity link. |
| `POST` | `/api/v1/:realm/ciam/identity-links/lookup` | Lookup identity link. |
| `GET` | `/api/v1/:realm/ciam/users/:user_id/identity-links` | List identity links. |
| `DELETE` | `/api/v1/:realm/ciam/identity-links/:link_id` | Delete identity link. |
| `GET` | `/api/v1/:realm/ciam/privacy/:user_id` | Privacy dashboard. |
| `POST` | `/api/v1/:realm/ciam/verification/issue` | Issue verification challenge. |
| `POST` | `/api/v1/:realm/ciam/verification/confirm` | Confirm verification. |
| `POST` | `/api/v1/:realm/ciam/password-reset/issue` | Issue password reset. |
| `POST` | `/api/v1/:realm/ciam/password-reset/consume` | Consume password reset. |
| `POST` | `/api/v1/:realm/ciam/protection/evaluate` | Protection/risk evaluation. |

## Device, workload, SPIFFE

| Method | Path | Notes |
| --- | --- | --- |
| `GET, POST` | `/api/v1/:realm/devices` | List/register devices. |
| `PUT` | `/api/v1/:realm/devices/:device_id/heartbeat` | Device heartbeat. |
| `POST` | `/api/v1/:realm/workload-identities` | Create workload identity. |
| `GET` | `/api/v1/:realm/workload-identities/:spiffe_id` | Get workload identity. |
| `GET, POST` | `/api/v1/:realm/workload-certificates` | List/issue workload certificates. |
| `POST` | `/api/v1/:realm/workload-certificates/:certificate_id/revoke` | Revoke workload certificate. |
| `GET` | `/api/v1/:realm/spiffe/workload-api/x509-svid` | Fetch X.509-SVID. |
| `GET` | `/api/v1/:realm/spiffe/workload-api/jwt-svid` | Fetch JWT-SVID. |
| `GET` | `/.well-known/spiffe-bundle` | SPIFFE bundle. |

Workload and SPIFFE routes are only merged in the `workload` profile.

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
| `GET, POST` | `/iga/v1/access-reviews` | List/create access review. |
| `POST` | `/iga/v1/access-reviews/:id/close` | Close access review. |
| `GET, POST` | `/iga/v1/access-reviews/:id/decisions` | List/create review decisions. |
| `GET, POST` | `/iga/v1/certifications` | List/create certifications. |
| `GET` | `/iga/v1/findings` | List findings. |
| `POST` | `/iga/v1/findings/detect` | Detect findings. |
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
| `GET` | `/directory/v1/providers` | List directory providers. |
| `GET, PATCH` | `/directory/v1/providers/:id` | Get/update provider status. |
| `POST` | `/directory/v1/providers/:id/sync` | Trigger sync. |
| `GET` | `/directory/v1/providers/:id/sync/status` | Sync status. |
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
| `GET` | `/vc/v1/status/:credential_id` | Credential status. |
| `POST` | `/vc/v1/status/:credential_id/revoke` | Revoke credential status. |
| `POST` | `/vc/v1/presentation/verify` | Verify presentation. |

VC routes are only merged in the `vc` profile.
