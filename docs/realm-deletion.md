# Realm deletion and persisted ownership

`RealmRepository::delete_realm` is an idempotent deletion of live state, not
just removal of an issuer binding. Recreating an ID with another tenant/issuer
starts empty. It does not delete the tenant or guess ownership from opaque
subject strings, client IDs, relationship namespaces, or JSON payloads.

## Inventory

This inventory covers every `file::Store` field and every table in the storage
migrations through `20250630000012`. Names below are Store fields unless a SQL
name differs. No migration changes are required.

| Ownership | Persisted resources | SQL lifecycle |
| --- | --- | --- |
| Realm root | `realm_issuers`, `realm_tenants` (`realms`) | Explicit root delete |
| Realm live state | `users`, `clients`, `sessions`, `token_families`, `access_tokens`, `devices`, `scim_users`, `scim_groups`, `fedcm_identities`, `workload_identities`, `policy_bundles` | Existing realm FK `ON DELETE CASCADE` |
| Realm and user live state | `ciam_consent_grants`, `ciam_verification_challenges`, `password_reset_tokens`, `ciam_profiles` | Existing realm and user cascades |
| User-only live state | `credentials_password`, `webauthn_credentials` (`credentials_webauthn`), `totp_credentials` (`credentials_totp`) | Existing user cascades; users are exclusively realm-owned |
| Realm live state without realm FK | `authorization_codes`, `device_authorization_grants`, `backchannel_authentication_grants`, `ciam_identity_links` | Explicit realm deletes; existing user cascades also retained. Pending grants have NULL user owners |
| Realm live state without FK | `service_accounts`, `par_requests`, `vc_credential_statuses`, `workload_certificates`, `custom_domains`, `ciam_brands`, `app_catalog_entries`, `scim_devices`, `scim_event_subscriptions`, `ssf_streams`, `ssf_set_replay` | Explicit realm deletes, even when the realm parent is already absent |
| Independent security history | `audit_events`, `audit_retention_configs`, `siem_deliveries` (`siem_delivery_queue`) | Retained, no realm FK. Includes queued audit exports: realm deletion must not silently lose undelivered audit evidence |
| Tenant-owned SaaS/admin state | `marketplace_connectors`, `usage_billing_events`, `compliance_evidence_packs`, `delegated_tenant_admins`, `admins`, `admin_elevations`, `admin_approvals` | Retained; admin child FKs are unrelated to realm lifetime |
| Tenant-owned IGA state/history | `iga_entitlements`, `iga_access_packages`, `iga_access_requests`, `iga_approvals`, `iga_access_grants`, `iga_jit_privilege_grants`, `iga_access_review_campaigns`, `iga_access_review_decisions`, `iga_certifications`, `iga_findings` | Retained; subjects/constraints are not realm ownership links |
| Global namespace-owned state | `relationship_tuples` | Retained; namespace/subject strings are not realm bindings |

Authentication dependencies are followed before deleting parents: codes and
refresh families can reference sessions; access tokens can reference families.
Deleting a realm removes those dependents even if their direct realm/subject
binding differs. Access-token subjects intentionally have no user FK, so removal
also matches actual deleted user IDs explicitly. Other realms' non-user tokens
without a removed family are preserved. Tokens belonging to the deleted realm
are removed regardless of subject type. Existing user deletion has the same
authentication ownership walk.

## Atomicity and persistence

SQL cleanup uses one transaction and static, bound DELETE statements followed by
the realm delete and existing FK cascades. Failure rolls back the entire cleanup.
Non-FK records are cleaned even after a legacy parent-only deletion.

File cleanup runs under the exclusive Store lock. Immediate mode acquires
`save_lock` **before** Store, retains both through serialization and the atomic
file replacement, and restores the previous Store on a returned persistence
error. Neither readers nor concurrent flushes see a partially deleted snapshot.
Interval mode accepts the complete in-memory deletion and marks the store dirty;
failed background flushes keep it dirty for retry rather than undoing accepted
mutations. In immediate mode the deletion task owns the repository until it
persists or rolls back, so dropping the request future does not interrupt a
filesystem write. Runtime shutdown is outside this task-level guarantee.

Audit history and its retention configuration intentionally remain queryable by
historical realm ID after deletion/recreation; they are not live identity or
trust configuration. SIEM delivery continues independently for that evidence.
