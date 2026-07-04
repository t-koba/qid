# qid config samples

`qid` configuration samples are organized by use case. Every file under
`config/usecases/` is intended to be a standalone `QidConfig` document that can
be loaded with `qidc --config <file> check`.

## How to use this folder

- Start with `config/usecases/01-getting-started/`.
- Move to the directory that matches the deployment goal.
- Replace hostnames, listen addresses, storage URLs, credentials, and key paths.
- Most samples use the file-backed JSON repository and write per-sample state
  under `config/usecases/data/runtime/` so different use cases do not collide
  when `qidd` seeds realms, clients, and policy bundles.
- `config/usecases/01-getting-started/local-dev.yaml` includes a minimal
  password-backed user in `config/usecases/data/01-getting-started/local-dev.json`
  for immediate local inspection. The sample password is `change-me`.
- RDB examples are kept in `config/usecases/10-storage-and-ops/`: use
  `sqlite-file.yaml` for local SQLite and `postgres-url-env.yaml`,
  `multi-region-active-active.yaml`, or `valkey-cache.yaml` for Postgres-backed
  deployments.
- Keep `observability.metrics.listen` on loopback unless the daemon is protected
  by a separate network boundary.
- Keep policy bundle paths relative to the config file location, or use
  `https://` / `http://` when bundles are fetched by an external deployment
  process.

The current validator accepts production profiles only. Use `oidc` for the
smallest interoperable OIDC authorization-code deployment, then move to
`edge-pep`, `fapi`, `enterprise`, `ciam`, `workload`, `vc`, `network-aaa`, or
`high-assurance` when the corresponding protocol surface is configured.

## Use-case index

### 01-getting-started

- `minimal-oidc.yaml`: smallest useful config with one realm.
- `local-dev.yaml`: localhost-only developer config.
- `oidc-web-app.yaml`: confidential web app using authorization code + PKCE.
- `oidc-spa-pkce.yaml`: public SPA using authorization code + PKCE.
- `multi-realm-baseline.yaml`: workforce and customer realms on one issuer host.

### 02-application-sign-in

- `device-flow-tv.yaml`: TV / CLI device authorization flow.
- `ciba-poll-client.yaml`: CIBA poll-mode client.
- `ciam-customer-identity.yaml`: CIAM sign-in with FedCM, consent, identity proofing, and social login.
- `passkeys-preferred.yaml`: passkeys preferred with password fallback.
- `passwordless-passkeys-only.yaml`: passkey-only realm.
- `totp-admin-step-up.yaml`: TOTP and admin step-up.
- `client-certificate-mfa.yaml`: certificate-backed MFA signals.
- `enterprise-webauthn-attestation.yaml`: managed passkey attestation and certificate-backed admin MFA.
- `sms-recovery-step-up.yaml`: SMS-assisted recovery with safer passkey/TOTP primary MFA.
- `password-policy-lockout.yaml`: Argon2id and lockout tuning.
- `browser-session-and-refresh-rotation.yaml`: browser and refresh token lifetimes.

### 03-api-and-service-access

- `api-resource-introspection.yaml`: protected API with JWT introspection.
- `machine-to-machine-client-credentials.yaml`: service-to-service client.
- `mtls-confidential-client.yaml`: certificate-bound confidential API client.
- `dpop-sender-constrained-api.yaml`: DPoP sender-constrained API.
- `par-rar-authorization-details.yaml`: PAR and RAR for structured consent.
- `token-exchange-delegation.yaml`: OAuth token exchange / on-behalf-of delegation.
- `jwt-bearer-assertion-grant.yaml`: external JWT assertion bridge.
- `revocation-webhook.yaml`: token revocation events and refresh-token reuse response.
- `dynamic-client-registration-controlled.yaml`: guarded DCR without open registration.
- `fapi2-baseline.yaml`: complete FAPI-style profile baseline.
- `fapi2-payments-high-risk.yaml`: high-risk payments API with sender constraint.
- `high-assurance-remote-signers.yaml`: high-assurance profile with remote signer metadata.

### 04-federation-and-sso

- `saml-idp-service-provider.yaml`: SAML IdP service provider registration.
- `inbound-oidc-broker.yaml`: inbound OIDC identity provider.
- `inbound-saml-broker.yaml`: inbound SAML identity provider.
- `saml-to-oidc-migration.yaml`: legacy SAML coexistence while moving apps to OIDC.
- `domain-home-realm-discovery.yaml`: domain-based inbound IdP routing for partner portals.

### 05-lifecycle-and-provisioning

- `active-directory-sync.yaml`: LDAP / Active Directory sync.
- `multi-directory-authority.yaml`: multiple LDAP / AD authorities during coexistence or consolidation.
- `hr-driven-jml.yaml`: HR-driven joiner / mover / leaver lifecycle feeds.
- `scim-provisioning-custom-schema.yaml`: SCIM with custom schema extensions.
- `enterprise-workforce-suite.yaml`: workforce lifecycle suite with SCIM, SAML, and LDAPS directory authority.

### 06-edge-access-policy

- `edge-pep-qpx-pep-decision.yaml`: edge PEP profile exercised with the qpx sister-product sample.
- `zero-trust-access-gateway.yaml`: complete edge PEP profile for ZTNA-style access gateways.
- `pep-assertion.yaml`: PEP assertion issuance in the OIDC profile.
- `device-bound-pep-assertion.yaml`: device-aware PEP assertions for endpoint agents.
- `authzen-policy-bundles.yaml`: AuthZEN endpoint path with policy bundles.
- `policy-dry-run-rollout.yaml`: enforce + dry-run policy rollout.
- `http-message-signatures-rotation.yaml`: multiple HTTP Message Signature keys.

### 07-workload-and-device-identity

- `spiffe-workload-svid.yaml`: workload profile with SPIFFE Workload API, SVIDs, RATS/EAT, and short-lived credentials.
- `kubernetes-service-account-token-exchange.yaml`: Kubernetes service account to workload credential exchange.
- `cloud-workload-federation.yaml`: cloud workload identity federation into qid-issued SVIDs.
- `cicd-deployment-bot.yaml`: short-lived deployment automation tokens.

### 08-verifiable-credentials

- `oid4vci-haip.yaml`: VC profile with OID4VCI, OID4VP, HAIP, status, and holder binding.
- `verifier-presentation-only.yaml`: verifier-oriented OID4VP / holder-bound presentation checks.
- `issuance-revocation-status-list.yaml`: credential issuance, revocation, and status-list operations.

### 09-network-access

- `radius-eap-tls.yaml`: network access profile with RADIUS/TLS, EAP-TLS, CAPPORT, accounting, and directory authority.
- `captive-portal-oidc-bridge.yaml`: CAPPORT / captive-portal bridge from network access to OIDC login.

### 10-storage-and-ops

- `sqlite-file.yaml`: local SQLite state in `target/tmp`.
- `postgres-url-env.yaml`: primary store URL from an environment variable.
- `valkey-cache.yaml`: Valkey-backed ops and storage cache.
- `multi-region-active-active.yaml`: active-active cluster metadata.
- `backup-readiness.yaml`: backup configuration.
- `emergency-read-only.yaml`: read-only emergency mode.

### 11-observability-debug

- `json-audit-file.yaml`: JSON logs and file audit sink.
- `otlp-tracing.yaml`: OTLP tracing endpoint from environment.
- `metrics-loopback.yaml`: explicit loopback metrics listener.
- `pii-redaction.yaml`: PII-redacted logs with audit field inclusion.

### 12-composition

- `multi-realm-ciam-and-workforce.yaml`: workforce and customer realm composition.
- `edge-pep-plus-fapi-api.yaml`: PEP registration plus FAPI-style API realm.

### 13-operator-governance

- `breakglass-admin-approval.yaml`: reason-required admin elevation with approval and break-glass.
- `delegated-admin-step-up.yaml`: delegated operations console with step-up and directory-backed operator groups.

### 99-test-fixtures

- `minimal-e2e.yaml`: small deterministic fixture.
- `policy-bundle-e2e.yaml`: fixture with local policy bundle.

## Validation

```bash
scripts/check-config-samples.sh
```

The script validates `config/qid.example.yaml` and every YAML file below
`config/usecases/`. It treats configuration load failures and `qidc check`
errors as failures, while leaving operational warnings visible in the generated
report.
