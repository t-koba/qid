# Storage ownership inventory (qid-storage)

Factual inventory of the ID-keyed persistent writes in the two `qid-storage`
backends: the file backend (`qid-storage/src/file/`) and the SQL backend
(`qid-storage/src/sql/`). One section per crate module, sorted by module name.
Every claim is backed by a `file:line` citation; where a rule is not in the
code, the cell says so instead of guessing.

Scope: writes that persist a record under an ID the caller supplies or that the
record is keyed by (create / store / update / upsert), plus the owner-scoped
deletes that carry the ownership contract. Pure reads are not listed.

Terminology used in the tables:

- **owner key** - the realm, tenant or user the record belongs to, and whether
  the record is realm-scoped, token/replay-scoped, or an internal record that is
  not tenant-scoped.
- **identity key** - the immutable key that names the record inside its owner
  (for example the SPIFFE ID of a workload identity, the email of a user, the
  `request_uri` of a PAR request).
- **same-owner collision** - what the code does today when a second record
  arrives for the same owner with the same identity key: the error returned, or
  the documented overwrite / no-op.

Error vocabulary used below, taken from the code:

- `QidError::Conflict`, `QidError::BadRequest`, `QidError::NotFound` are
  returned directly by the backends.
- The SQL backend funnels every other database error through
  `storage_to_qid_error`, which produces `QidError::Storage`
  (`qid-storage/src/sql/row.rs:10`). A plain `INSERT` that violates a primary
  key or a `UNIQUE` index therefore surfaces as `Storage`, not as `Conflict`.
- `ownership::ensure_same_binding` returns `Conflict` when an incumbent record
  is bound to a different owner (`qid-storage/src/ownership.rs:6`,
  `qid-storage/src/ownership.rs:12`); it runs under the file store's exclusive
  write lock.
- `ownership::ensure_upsert_applied` returns `Conflict` when an atomic SQL
  upsert with an owner/identity predicate changed no row
  (`qid-storage/src/ownership.rs:19`, `qid-storage/src/ownership.rs:24`).

Where a backend's behaviour differs from the other's, both files are named.

## admin

Model types: `Admin`, `AdminElevation`, `AdminApproval`. The owner is the
tenant (`tenant_id`); the table declares `UNIQUE(tenant_id, subject)`
(`qid-storage/migrations/20250626000001_admin_tables.sql:7`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `upsert_admin` - `Admin` | tenant (`tenant_id`) | `(tenant_id, subject)` | roles, `created_at` | File: the incumbent with the same tenant and subject is removed and the new record inserted, so the write replaces and never errors (`qid-storage/src/file/admin.rs:23`, `qid-storage/src/file/admin.rs:26`). SQL: `ON CONFLICT(tenant_id, subject) DO UPDATE SET roles_json`, an upsert that keeps the incumbent row ID and never errors (`qid-storage/src/sql/admin.rs:29`, `qid-storage/src/sql/admin.rs:30`). Both replace; the file path also changes the record ID, the SQL path keeps it. | file `qid-storage/src/file/admin.rs:23`; sql `qid-storage/src/sql/admin.rs:30`; schema `qid-storage/migrations/20250626000001_admin_tables.sql:7` |
| `store_admin_elevation` - `AdminElevation` | tenant (`tenant_id`) | record `id` | acr, amr, `elevation_expires_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/admin.rs:39`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/admin.rs:55`, `qid-storage/src/sql/row.rs:10`). **Backends disagree.** | file `qid-storage/src/file/admin.rs:39`; sql `qid-storage/src/sql/admin.rs:55` (not enforced as a conflict in SQL) |
| `store_admin_approval` - `AdminApproval` | tenant (`tenant_id`) | record `id` | approver, target, reason, `approved_at`, `expires_at`, `consumed` | File: overwrite, no error (`qid-storage/src/file/admin.rs:52`). SQL: plain `INSERT` into a table whose primary key is `id`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/admin.rs:82`). **Backends disagree.** | file `qid-storage/src/file/admin.rs:52`; sql `qid-storage/src/sql/admin.rs:82` (not enforced as a conflict in SQL) |

## audit

Model types: `AuditEvent`, `AuditRetentionConfig`. Audit records are
realm-scoped but not tenant-scoped: `realm_id` is optional and `None` denotes
the global stream (`qid-storage/src/file/audit.rs:13`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `append_audit_event` - `AuditEvent` | realm (`realm_id`, `None` = global stream); internal record, not tenant-scoped | event `id` plus the chain hash | none, append-only | File: the event is pushed onto a `Vec`, so a repeated event ID is stored a second time and never refused (`qid-storage/src/file/audit.rs:15`, `qid-storage/src/file/audit.rs:17`). SQL: `INSERT INTO audit_events` where `id` is the primary key, so a repeated ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/audit.rs:27`). **Backends disagree.** | file `qid-storage/src/file/audit.rs:15`; sql `qid-storage/src/sql/audit.rs:27`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:72` |
| `set_audit_retention_config` - `AuditRetentionConfig` | realm (`realm_id`, `None` = global key `__global__`) | the retention key, realm or `__global__` (`qid-storage/src/file/mod.rs:438`, `qid-storage/src/sql/row/security.rs:144`) | `retention_days`, `legal_hold`, `updated_by`, `reason`, `updated_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/audit.rs:71`). SQL: `ON CONFLICT(stream_id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/audit.rs:101`). Both replace. | file `qid-storage/src/file/audit.rs:69`, `qid-storage/src/file/audit.rs:71`; sql `qid-storage/src/sql/audit.rs:101`, `qid-storage/src/sql/audit.rs:103` |

## ciam

Model types: `CiamConsentGrant`, `CiamVerificationChallengeRecord`,
`CiamIdentityLink`, `PasswordResetToken`, `CiamProgressiveProfile`.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_ciam_consent_grant` - `CiamConsentGrant` | realm + user (`realm_id`, `user_id`) | `client_id` inside that owner | granted claims, terms version, `revoked` | File: an incumbent with the same ID but another `(realm, user, client)` binding is refused with `Conflict` under the exclusive write lock; the same binding overwrites (`qid-storage/src/file/ciam.rs:11`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the same `(realm, user, client)` binding, so a different binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:12`, `qid-storage/src/sql/ciam.rs:13`, `qid-storage/src/sql/ciam.rs:26`). Both refuse a foreign binding with `Conflict`. | file `qid-storage/src/file/ciam.rs:11`; sql `qid-storage/src/sql/ciam.rs:12`, `qid-storage/src/sql/ciam.rs:26` |
| `store_ciam_verification_challenge` - `CiamVerificationChallengeRecord` | realm (`realm_id`) | record `id` | `consumed_at_epoch_seconds` | File: overwrite of the map entry, no error (`qid-storage/src/file/ciam.rs:69`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/ciam.rs:75`). **Backends disagree.** | file `qid-storage/src/file/ciam.rs:69`; sql `qid-storage/src/sql/ciam.rs:75` (not enforced as a conflict in SQL) |
| `store_ciam_identity_link` - `CiamIdentityLink` | realm + user (`realm_id`, `user_id`) | `(realm_id, provider, external_subject)`, unique index (`qid-storage/migrations/20250618000031_ciam_identity_links.sql:13`) | `external_email`, profile, `linked_at`, `verified` | File: a second verified link for the same `(realm, provider, external_subject)` is refused with `BadRequest` (`qid-storage/src/file/ciam.rs:126`, `qid-storage/src/file/ciam.rs:134`); an existing ID whose owner or identity key differs is refused with `Conflict` (`qid-storage/src/domain/mod.rs:81`, `qid-storage/src/domain/mod.rs:87`); a verified link may not revert to unverified (`qid-storage/src/domain/mod.rs:94`, `qid-storage/src/domain/mod.rs:98`). SQL: a verified duplicate is refused with `BadRequest` (`qid-storage/src/sql/ciam.rs:159`, `qid-storage/src/sql/ciam.rs:170`); the upsert's `WHERE` predicate covers realm, user and identity key, so a foreign binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:176`, `qid-storage/src/sql/ciam.rs:177`, `qid-storage/src/sql/ciam.rs:192`). Both refuse the same cases with the same errors. | file `qid-storage/src/file/ciam.rs:126`, `qid-storage/src/domain/mod.rs:81`; sql `qid-storage/src/sql/ciam.rs:159`, `qid-storage/src/sql/ciam.rs:192` |
| `store_password_reset_token` - `PasswordResetToken` | realm + user (`realm_id`, `user_id`) | record `id` | `consumed_at_epoch_seconds` | File: overwrite of the map entry, no error (`qid-storage/src/file/ciam.rs:215`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/ciam.rs:259`). **Backends disagree.** | file `qid-storage/src/file/ciam.rs:215`; sql `qid-storage/src/sql/ciam.rs:259` (not enforced as a conflict in SQL) |
| `store_ciam_progressive_profile` - `CiamProgressiveProfile` | realm + user (`realm_id`, `user_id`); the file key is `realm_id` + `user_id` (`qid-storage/src/file/mod.rs:52`) | record `id`, unique per `(realm, user)` (`qid-storage/migrations/20250625000001_ciam_profiles.sql:11`) | `profile_json`, `passwordless_migrated_at`, `updated_at` | File: an ID already held by another `(realm, user)` is refused with `Conflict`, and the key's identity (`id`, realm, user) may not change (`qid-storage/src/file/ciam.rs:316`, `qid-storage/src/file/ciam.rs:328`); the same owner and ID overwrites. SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` realm and user match, so a foreign binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:386`, `qid-storage/src/sql/ciam.rs:387`, `qid-storage/src/sql/ciam.rs:406`); a unique violation on the `(realm, user)` index is mapped to `Conflict` (`qid-storage/src/sql/ciam.rs:399`). Both refuse a foreign binding with `Conflict`. | file `qid-storage/src/file/ciam.rs:316`, `qid-storage/src/file/ciam.rs:328`; sql `qid-storage/src/sql/ciam.rs:386`, `qid-storage/src/sql/ciam.rs:406` |

## client

Model type: `Client`. The owner is the realm; the client ID names one client
inside a realm (`UNIQUE(realm_id, client_id)`,
`qid-storage/migrations/20250101000001_initial_schema.sql:52`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_client` - `Client` | realm (`realm_id`) | record `id` and `client_id` (unique per realm) | redirect URIs, grant types, secret hash, mTLS thumbprints, jwks, contacts, metadata | File: an existing record ID is refused with `Conflict` and an existing `(realm, client_id)` is refused with `Conflict`, both under the store's exclusive write lock (`qid-storage/src/file/client.rs:13`, `qid-storage/src/file/client.rs:14`, `qid-storage/src/file/client.rs:18`, `qid-storage/src/file/client.rs:21`). SQL: `ON CONFLICT DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` with a message naming which key was taken (`qid-storage/src/sql/client.rs:12`, `qid-storage/src/sql/client.rs:42`, `qid-storage/src/sql/client.rs:57`). Both refuse with `Conflict`. | file `qid-storage/src/file/client.rs:13`, `qid-storage/src/file/client.rs:18`; sql `qid-storage/src/sql/client.rs:12`, `qid-storage/src/sql/client.rs:42`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:52` |
| `update_client` - `Client` | realm (`realm_id`) | record `id` | client metadata fields | File: overwrite of the map entry, no error (`qid-storage/src/file/client.rs:34`). SQL: `UPDATE` by `id`; no row affected is not an error (`qid-storage/src/sql/client.rs:64`). Both replace. | file `qid-storage/src/file/client.rs:34`; sql `qid-storage/src/sql/client.rs:64` |

## credential

Model types: `WebAuthnCredential`, `TotpCredential`. The owner is the user
(`user_id`); the WebAuthn table's primary key is the record `id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:33`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_webauthn_credential` - `WebAuthnCredential` | user (`user_id`) | record `id` | counter, `device_name`, public key | File: the credential is appended to the user's list, so the same credential ID is stored twice and never refused (`qid-storage/src/file/credential.rs:20`, `qid-storage/src/file/credential.rs:22`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/credential.rs:25`). **Backends disagree.** | file `qid-storage/src/file/credential.rs:20`; sql `qid-storage/src/sql/credential.rs:25` (not enforced as a conflict in SQL) |
| `update_webauthn_credential_counter` - `WebAuthnCredential` | user (`user_id`) | record `id` | counter | File: the first matching credential in any user's list is updated; an unknown ID is a silent no-op (`qid-storage/src/file/credential.rs:30`, `qid-storage/src/file/credential.rs:31`). SQL: `UPDATE ... WHERE id = ?`; no row affected is not an error (`qid-storage/src/sql/credential.rs:42`). Both are silent no-ops for an unknown ID. | file `qid-storage/src/file/credential.rs:30`; sql `qid-storage/src/sql/credential.rs:42` |
| `store_totp_credential` - `TotpCredential` | user (`user_id`) | record `id` | secret, algorithm, digits, period, `enabled`, `last_used_step` | File: overwrite of the map entry, no error (`qid-storage/src/file/credential.rs:58`). SQL: `ON CONFLICT(id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/credential.rs:53`). Both replace. | file `qid-storage/src/file/credential.rs:58`; sql `qid-storage/src/sql/credential.rs:53` |
| `consume_totp_step` - `TotpCredential` | user (`user_id`) | record `id` | `last_used_step` (monotonic) | File: a step that is not newer than the recorded one is refused and `false` is returned (`qid-storage/src/file/credential.rs:76`, `qid-storage/src/file/credential.rs:79`). SQL: `UPDATE ... WHERE last_used_step IS NULL OR last_used_step < ?` and the affected-row count decides the answer (`qid-storage/src/sql/credential.rs:82`, `qid-storage/src/sql/credential.rs:89`). Both refuse a replayed step. | file `qid-storage/src/file/credential.rs:76`; sql `qid-storage/src/sql/credential.rs:82` |

## device

Model type: `Device`. Owner: realm and user (`realm_id`, `user_id`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `register_device` - `Device` | realm + user (`realm_id`, `user_id`) | record `id` | posture, `last_seen_at`, `device_name` | File: overwrite of the map entry, no error (`qid-storage/src/file/device.rs:9`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/device.rs:9`). **Backends disagree.** | file `qid-storage/src/file/device.rs:9`; sql `qid-storage/src/sql/device.rs:9` (not enforced as a conflict in SQL) |
| `update_device_last_seen` - `Device` | realm + user | record `id` | `last_seen_at` | File: in-place update, an unknown ID is a silent no-op (`qid-storage/src/file/device.rs:32`). SQL: `UPDATE ... WHERE id = ?`; no row affected is not an error (`qid-storage/src/sql/device.rs:44`). Both are silent no-ops. | file `qid-storage/src/file/device.rs:32`; sql `qid-storage/src/sql/device.rs:44` |

## fedcm

Model type: `FedCmIdentity`. Owner: realm (`realm_id`); the record is also
readable by `account_id` inside a realm (`qid-storage/src/file/fedcm.rs:25`),
but the table declares no uniqueness on `account_id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:230`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_fedcm_identity` - `FedCmIdentity` | realm (`realm_id`) | record `id` | email, name, given name, picture URL, approved clients | File: overwrite of the map entry, no error (`qid-storage/src/file/fedcm.rs:11`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/fedcm.rs:9`). **Backends disagree.** | file `qid-storage/src/file/fedcm.rs:11`; sql `qid-storage/src/sql/fedcm.rs:9` (not enforced as a conflict in SQL) |

## iga

Model types: `IgaEntitlementRecord`, `IgaAccessPackageRecord`,
`IgaAccessRequestRecord`, `IgaApprovalRecord`, `IgaAccessGrantRecord`,
`IgaJitPrivilegeGrantRecord`, `IgaAccessReviewCampaignRecord`,
`IgaAccessReviewDecisionRecord`, `IgaCertificationRecord`, `IgaFindingRecord`.
The owner is the tenant (`tenant_id`). Entitlements and access packages are
keyed by tenant plus ID (`qid-storage/src/file/mod.rs:442`,
`qid-storage/migrations/20250618000019_iga_entitlements.sql:10`,
`qid-storage/migrations/20250618000021_iga_access_packages.sql:10`); the other
IGA tables declare `id` alone as the primary key
(`qid-storage/migrations/20250618000017_iga_records.sql:2`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_iga_entitlement` - `IgaEntitlementRecord` | tenant (`tenant_id`) | `(tenant_id, id)` | display name, owner, risk level, conflicting entitlements, max duration, `active` | File: overwrite of the tenant-scoped map entry, no error (`qid-storage/src/file/iga.rs:10`). SQL: `ON CONFLICT(tenant_id, id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/iga.rs:10`). Both end with the incoming values. | file `qid-storage/src/file/iga.rs:10`; sql `qid-storage/src/sql/iga.rs:10` |
| `store_iga_access_package` - `IgaAccessPackageRecord` | tenant (`tenant_id`) | `(tenant_id, id)` | display name, owner, entitlement IDs, approval policy, max duration, `active` | File: overwrite of the tenant-scoped map entry, no error (`qid-storage/src/file/iga.rs:42`). SQL: `ON CONFLICT(tenant_id, id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/iga.rs:49`). Both end with the incoming values. | file `qid-storage/src/file/iga.rs:42`; sql `qid-storage/src/sql/iga.rs:49` |
| `store_iga_access_request` - `IgaAccessRequestRecord` | tenant (`tenant_id`) | record `id` (global in both backends) | status, approval steps, violations, `expires_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:79`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:91`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:79`; sql `qid-storage/src/sql/iga.rs:91` (not enforced as a conflict in SQL) |
| `update_iga_access_request_status` - `IgaAccessRequestRecord` | tenant (`tenant_id`) | record `id` | status | File: the status is changed only when the record's tenant matches; otherwise a silent no-op (`qid-storage/src/file/iga.rs:105`, `qid-storage/src/file/iga.rs:106`). SQL: `UPDATE ... WHERE tenant_id = ? AND id = ?`; no row affected is not an error (`qid-storage/src/sql/iga.rs:132`). Both are tenant-scoped silent no-ops. | file `qid-storage/src/file/iga.rs:105`; sql `qid-storage/src/sql/iga.rs:132` |
| `store_iga_approval` - `IgaApprovalRecord` | tenant (`tenant_id`) | record `id` | decision, `approved_at`, `expires_at`, reason | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:138`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:159`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:138`; sql `qid-storage/src/sql/iga.rs:159` (not enforced as a conflict in SQL) |
| `store_iga_access_grant` - `IgaAccessGrantRecord` | tenant (`tenant_id`) | record `id` | `revoked`, `expires_at`, approval IDs | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:168`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:194`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:168`; sql `qid-storage/src/sql/iga.rs:194` (not enforced as a conflict in SQL) |
| `ensure_iga_access_grants` - `IgaAccessGrantRecord` (batch) | tenant (`tenant_id`) | record `id`; the parent is the access request | grant fields of the missing grants | File: a missing parent request is `BadRequest` (`qid-storage/src/file/iga.rs:474`, `qid-storage/src/file/iga.rs:478`); an incumbent grant ID bound to another `(tenant, request, subject, entitlement)` is `BadRequest` (`qid-storage/src/file/iga.rs:491`, `qid-storage/src/file/iga.rs:497`); an already present grant is a no-op, only missing grants are written (`qid-storage/src/file/iga.rs:489`, `qid-storage/src/file/iga.rs:508`). SQL: the same two refusals inside the transaction, a missing parent (`qid-storage/src/sql/iga.rs:240`, `qid-storage/src/sql/iga.rs:241`) and a foreign binding (`qid-storage/src/sql/iga.rs:264`, `qid-storage/src/sql/iga.rs:279`). Both refuse the same cases with `BadRequest`. | file `qid-storage/src/file/iga.rs:491`; sql `qid-storage/src/sql/iga.rs:264`, `qid-storage/src/sql/iga.rs:279` |
| `store_iga_jit_privilege_grant` - `IgaJitPrivilegeGrantRecord` | tenant (`tenant_id`) | record `id` | `revoked`, `expires_at`, constraints | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:235`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:360`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:235`; sql `qid-storage/src/sql/iga.rs:360` (not enforced as a conflict in SQL) |
| `store_iga_access_review_campaign` - `IgaAccessReviewCampaignRecord` | tenant (`tenant_id`) | record `id` | status, `due_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:281`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:423`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:281`; sql `qid-storage/src/sql/iga.rs:423` (not enforced as a conflict in SQL) |
| `store_iga_access_review_decision` - `IgaAccessReviewDecisionRecord` | tenant (`tenant_id`) | record `id` | none after the insert | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:346`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:486`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:346`; sql `qid-storage/src/sql/iga.rs:486` (not enforced as a conflict in SQL) |
| `store_iga_certification` - `IgaCertificationRecord` | tenant (`tenant_id`) | record `id` | none after the insert | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:381`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:524`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:381`; sql `qid-storage/src/sql/iga.rs:524` (not enforced as a conflict in SQL) |
| `store_iga_finding` - `IgaFindingRecord` | tenant (`tenant_id`) | record `id` | `resolved` | File: overwrite of the map entry, no error (`qid-storage/src/file/iga.rs:415`). SQL: plain `INSERT`, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/iga.rs:572`). **Backends disagree.** | file `qid-storage/src/file/iga.rs:415`; sql `qid-storage/src/sql/iga.rs:572` (not enforced as a conflict in SQL) |
| `resolve_iga_finding` - `IgaFindingRecord` | tenant (`tenant_id`) in the record; the write itself is not tenant-filtered | record `id` | `resolved` | File: the flag is set when the ID exists, otherwise a silent no-op (`qid-storage/src/file/iga.rs:445`). SQL: `UPDATE iga_findings SET resolved = 1 WHERE id = ?`, with no tenant predicate (`qid-storage/src/sql/iga.rs:615`). Both update by ID only. | file `qid-storage/src/file/iga.rs:445`; sql `qid-storage/src/sql/iga.rs:615` |
| `delete_iga_entitlement` (delete) | tenant (`tenant_id`) | `(tenant_id, id)` | none, removal | File: the tenant-scoped key is removed; a missing record is a silent no-op (`qid-storage/src/file/iga.rs:34`). SQL: `DELETE ... WHERE tenant_id = ? AND id = ?`; a missing record is a silent no-op (`qid-storage/src/sql/iga.rs:37`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/iga.rs:34`; sql `qid-storage/src/sql/iga.rs:37` |
| `delete_iga_access_package` (delete) | tenant (`tenant_id`) | `(tenant_id, id)` | none, removal | File: the tenant-scoped key is removed (`qid-storage/src/file/iga.rs:69`). SQL: `DELETE ... WHERE tenant_id = ? AND id = ?` (`qid-storage/src/sql/iga.rs:79`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/iga.rs:69`; sql `qid-storage/src/sql/iga.rs:79` |

## policy

Model type: `PolicyBundle`. Owner: realm (`realm_id`); the table also declares
`UNIQUE(realm_id, name)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:263`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_policy_bundle` - `PolicyBundle` | realm (`realm_id`) | record `id`; the schema also names a bundle by `(realm_id, name)` | name, `source_hash`, `compiled_json`, version, `active` | File: overwrite of the map entry, no error, and the `(realm, name)` uniqueness of the SQL schema is not checked in the file path (`qid-storage/src/file/policy.rs:11`). SQL: plain `INSERT`, so a duplicate ID or a duplicate `(realm, name)` is a unique violation surfaced as `Storage` (`qid-storage/src/sql/policy.rs:9`). **Backends disagree.** | file `qid-storage/src/file/policy.rs:11` (no name check); sql `qid-storage/src/sql/policy.rs:9`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:263` |

## realm

Model type: the `realms` row (no model struct in `qid-core`). Owner: the
tenant (`tenant_id`); the table declares `UNIQUE(issuer)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:6`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_realm` - `realms` row | tenant (`tenant_id`) | realm `id`; the schema also makes `issuer` unique | issuer, `display_name` | File: both maps are overwritten, so a repeated realm ID or issuer is accepted silently (`qid-storage/src/file/realm.rs:15`, `qid-storage/src/file/realm.rs:18`). SQL: plain `INSERT`, so a duplicate realm ID or a duplicate issuer is a unique violation surfaced as `Storage` (`qid-storage/src/sql/realm.rs:14`). **Backends disagree.** | file `qid-storage/src/file/realm.rs:15`; sql `qid-storage/src/sql/realm.rs:14` (not enforced as a conflict in SQL); schema `qid-storage/migrations/20250101000001_initial_schema.sql:6` |

## rebac

Model type: `RelationshipTuple`. The tuple has no realm or tenant column
(`qid-core/src/models/rebac.rs:10`); the scope is the `namespace`, so this is
an internal record that is not tenant-scoped. The identity is the six-part
tuple, which is the SQL primary key
(`qid-storage/migrations/20250622000005_relationship_tuples.sql:9`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_relationship_tuple` - `RelationshipTuple` | namespace only; not realm- or tenant-scoped (no owner column in the model) | `(namespace, object_id, relation, subject_namespace, subject_id, subject_relation)` | `created_at_epoch_seconds` | File: the tuple is pushed onto a `Vec`, so the same tuple is stored twice and never refused (`qid-storage/src/file/rebac.rs:9`). SQL: plain `INSERT` into a table whose primary key is the six-part tuple, so a repeated tuple is a unique violation surfaced as `Storage` (`qid-storage/src/sql/rebac.rs:9`). **Backends disagree.** | file `qid-storage/src/file/rebac.rs:9`; sql `qid-storage/src/sql/rebac.rs:9` (not enforced as a conflict in SQL) |

## saas

Model types: `CustomDomain`, `CiamBrand`, `AppCatalogEntry`,
`MarketplaceConnector`, `UsageBillingEvent`, `ComplianceEvidencePack`,
`DelegatedTenantAdmin`. The owner is the tenant (`tenant_id`); several writes
also require the referenced realm to belong to that tenant.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_custom_domain` - `CustomDomain` | tenant (`tenant_id`); the realm must belong to it | record `id`; the schema also makes `hostname` unique (`qid-storage/migrations/20250618000016_saas_models.sql:5`) | hostname, certificate ref, verification fields, dates | File: another domain with the same hostname (case-insensitive) is refused with `Storage` (`qid-storage/src/file/saas.rs:68`, `qid-storage/src/file/saas.rs:71`); an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:75`); a realm of another tenant is `Storage` (`qid-storage/src/file/saas.rs:63`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:50`, `qid-storage/src/sql/saas.rs:51`, `qid-storage/src/sql/saas.rs:68`); a duplicate hostname is a unique violation surfaced as `Storage` (`qid-storage/src/sql/row.rs:10`); a realm of another tenant is `Storage` (`qid-storage/src/sql/saas.rs:44`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:75`; sql `qid-storage/src/sql/saas.rs:51`, `qid-storage/src/sql/saas.rs:68` |
| `store_ciam_brand` - `CiamBrand` | tenant (`tenant_id`); the realm must belong to it | record `id` | display name, colours, logo and policy URIs, terms version, `active` | File: an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:128`); a realm of another tenant is `Storage` (`qid-storage/src/file/saas.rs:124`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:113`, `qid-storage/src/sql/saas.rs:114`, `qid-storage/src/sql/saas.rs:129`); a realm of another tenant is `Storage` (`qid-storage/src/sql/saas.rs:107`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:128`; sql `qid-storage/src/sql/saas.rs:114`, `qid-storage/src/sql/saas.rs:129` |
| `store_app_catalog_entry` - `AppCatalogEntry` | tenant (`tenant_id`); the realm must belong to it, and the referenced client and connector must exist | record `id` | display name, category, OIDC client ID, SAML entity ID, SCIM flag, connector ID | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:216`, `qid-storage/src/file/saas.rs:217`); a foreign realm, a missing client or a connector of another tenant are `Storage` (`qid-storage/src/file/saas.rs:174`, `qid-storage/src/file/saas.rs:184`, `qid-storage/src/file/saas.rs:196`). SQL: plain `INSERT` whose unique violation is mapped to `Conflict` (`qid-storage/src/sql/saas.rs:229`, `qid-storage/src/sql/saas.rs:243`); the same reference checks produce `Storage` (`qid-storage/src/sql/saas.rs:168`, `qid-storage/src/sql/saas.rs:181`, `qid-storage/src/sql/saas.rs:195`). Both refuse a duplicate ID with `Conflict`. | file `qid-storage/src/file/saas.rs:216`; sql `qid-storage/src/sql/saas.rs:243` |
| `store_marketplace_connector` - `MarketplaceConnector` | tenant (`tenant_id`) | record `id` | provider, connector type, config, `enabled` | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:256`, `qid-storage/src/file/saas.rs:257`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:276`, `qid-storage/src/sql/saas.rs:287`). Both refuse with `Conflict`. | file `qid-storage/src/file/saas.rs:256`; sql `qid-storage/src/sql/saas.rs:276`, `qid-storage/src/sql/saas.rs:287` |
| `store_usage_billing_event` - `UsageBillingEvent` | tenant (`tenant_id`) | record `id`; the schema also makes `(tenant_id, idempotency_key)` unique (`qid-storage/migrations/20250618000016_saas_models.sql:47`) | meter, quantity, `occurred_at`, dimensions | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:306`, `qid-storage/src/file/saas.rs:307`); a repeated idempotency key in the tenant is `Storage` (`qid-storage/src/file/saas.rs:311`, `qid-storage/src/file/saas.rs:314`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:335`, `qid-storage/src/sql/saas.rs:347`); a repeated idempotency key is a unique violation surfaced as `Storage` (`qid-storage/src/sql/row.rs:10`). Both refuse a duplicate ID with `Conflict` and a repeated key with `Storage`. | file `qid-storage/src/file/saas.rs:306`; sql `qid-storage/src/sql/saas.rs:335`, `qid-storage/src/sql/saas.rs:347` |
| `store_compliance_evidence_pack` - `ComplianceEvidencePack` | tenant (`tenant_id`) | record `id` | period, controls, object URI, sha256 | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:349`, `qid-storage/src/file/saas.rs:350`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:374`, `qid-storage/src/sql/saas.rs:387`). Both refuse with `Conflict`. | file `qid-storage/src/file/saas.rs:349`; sql `qid-storage/src/sql/saas.rs:374`, `qid-storage/src/sql/saas.rs:387` |
| `store_delegated_tenant_admin` - `DelegatedTenantAdmin` | tenant (`tenant_id`); every allowed realm must belong to it | record `id` | subject, roles, allowed realm IDs, granted by, `expires_at`, `revoked` | File: an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:401`); an allowed realm of another tenant or a missing realm is `BadRequest` (`qid-storage/src/file/saas.rs:387`, `qid-storage/src/file/saas.rs:393`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:435`, `qid-storage/src/sql/saas.rs:436`); a realm of another tenant or a missing realm is `BadRequest` (`qid-storage/src/sql/saas.rs:421`, `qid-storage/src/sql/saas.rs:427`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:401`; sql `qid-storage/src/sql/saas.rs:436` |
| `delete_custom_domain` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: the record is removed when its tenant matches (`qid-storage/src/file/saas.rs:109`). SQL: `DELETE ... WHERE id = ? AND tenant_id = ?` (`qid-storage/src/sql/saas.rs:84`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/saas.rs:109`; sql `qid-storage/src/sql/saas.rs:84` |
| `delete_marketplace_connector` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: a connector still referenced by a catalog entry of the tenant is `Storage`; otherwise the record is removed when its tenant matches (`qid-storage/src/file/saas.rs:285`, `qid-storage/src/file/saas.rs:288`, `qid-storage/src/file/saas.rs:295`). SQL: the same reference check is `Storage` (`qid-storage/src/sql/saas.rs:319`) and the delete is tenant-scoped (`qid-storage/src/sql/saas.rs:323`). Both behave the same. | file `qid-storage/src/file/saas.rs:288`; sql `qid-storage/src/sql/saas.rs:319`, `qid-storage/src/sql/saas.rs:323` |

## scim

Model types: `ScimUser`, `ScimGroup`, `ScimDeviceRecord`,
`ScimEventSubscriptionRecord`. Owner: realm (`realm_id`). The tables also
declare `UNIQUE(realm_id, user_name)` and `UNIQUE(realm_id, display_name)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:217`,
`qid-storage/migrations/20250101000001_initial_schema.sql:227`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_scim_user` - `ScimUser` | realm (`realm_id`) | record `id`; the schema also names a user by `(realm_id, user_name)` | external ID, user name, name, emails, enterprise fields, provider, `active`, `deprovisioned_at` | File: `create_scim_user` delegates to `update_scim_user`, which overwrites the map entry, so a duplicate ID or a duplicate `(realm, user_name)` is accepted silently (`qid-storage/src/file/scim.rs:8`, `qid-storage/src/file/scim.rs:47`). SQL: plain `INSERT`, so a duplicate ID or a duplicate `(realm, user_name)` is a unique violation surfaced as `Storage` (`qid-storage/src/sql/scim.rs:71`). **Backends disagree.** | file `qid-storage/src/file/scim.rs:8`, `qid-storage/src/file/scim.rs:47`; sql `qid-storage/src/sql/scim.rs:71` (not enforced as a conflict in SQL) |
| `update_scim_user` - `ScimUser` | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | as above | File: overwrite by ID only (`qid-storage/src/file/scim.rs:47`). SQL: `UPDATE ... WHERE id = ?`, with no realm predicate (`qid-storage/src/sql/scim.rs:131`). Both update by ID only. | file `qid-storage/src/file/scim.rs:47`; sql `qid-storage/src/sql/scim.rs:131` |
| `create_scim_group` - `ScimGroup` | realm (`realm_id`) | record `id`; the schema also names a group by `(realm_id, display_name)` | display name, members | File: `create_scim_group` delegates to `update_scim_group`, which overwrites the map entry (`qid-storage/src/file/scim.rs:69`, `qid-storage/src/file/scim.rs:108`). SQL: plain `INSERT`, so a duplicate ID or a duplicate `(realm, display_name)` is a unique violation surfaced as `Storage` (`qid-storage/src/sql/scim.rs:194`). **Backends disagree.** | file `qid-storage/src/file/scim.rs:69`, `qid-storage/src/file/scim.rs:108`; sql `qid-storage/src/sql/scim.rs:194` (not enforced as a conflict in SQL) |
| `update_scim_group` - `ScimGroup` | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | display name, members | File: overwrite by ID only (`qid-storage/src/file/scim.rs:108`). SQL: `UPDATE ... WHERE id = ?` (`qid-storage/src/sql/scim.rs:248`). Both update by ID only. | file `qid-storage/src/file/scim.rs:108`; sql `qid-storage/src/sql/scim.rs:248` |
| `upsert_scim_device` - `ScimDeviceRecord` | realm (`realm_id`) | record `id` | display name, manufacturer, model, OS, OS version, `last_seen` | File: an ID already bound to another realm is refused with `Conflict` under the write lock (`qid-storage/src/file/scim.rs:132`); the same realm overwrites (`qid-storage/src/file/scim.rs:140`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm matches, so a foreign realm updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/scim.rs:301`, `qid-storage/src/sql/scim.rs:302`, `qid-storage/src/sql/scim.rs:315`). Both refuse a foreign realm with `Conflict`. | file `qid-storage/src/file/scim.rs:132`; sql `qid-storage/src/sql/scim.rs:302`, `qid-storage/src/sql/scim.rs:315` |
| `upsert_scim_event_subscription` - `ScimEventSubscriptionRecord` | realm (`realm_id`) | record `id` | callback URL, event types, `enabled` | File: an ID already bound to another realm is refused with `Conflict` (`qid-storage/src/file/scim.rs:176`); the same realm overwrites (`qid-storage/src/file/scim.rs:184`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm matches, so a foreign realm updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/scim.rs:353`, `qid-storage/src/sql/scim.rs:354`, `qid-storage/src/sql/scim.rs:365`). Both refuse a foreign realm with `Conflict`. | file `qid-storage/src/file/scim.rs:176`; sql `qid-storage/src/sql/scim.rs:354`, `qid-storage/src/sql/scim.rs:365` |
| `delete_scim_device` (delete) | none in the write; the record carries `realm_id` | record `id` | none, removal | File: removed by ID without a realm predicate, reported as a boolean (`qid-storage/src/file/scim.rs:163`). SQL: `DELETE ... WHERE id = ?` reported as a boolean (`qid-storage/src/sql/scim.rs:340`). Both delete by ID only. | file `qid-storage/src/file/scim.rs:163`; sql `qid-storage/src/sql/scim.rs:340` |
| `delete_scim_event_subscription` (delete) | none in the write; the record carries `realm_id` | record `id` | none, removal | File: removed by ID without a realm predicate (`qid-storage/src/file/scim.rs:216`). SQL: `DELETE ... WHERE id = ?` (`qid-storage/src/sql/scim.rs:398`). Both delete by ID only. | file `qid-storage/src/file/scim.rs:216`; sql `qid-storage/src/sql/scim.rs:398` |

## service_account

Model type: `ServiceAccount`. Owner: realm (`realm_id`); the record references
a `client_id`.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_service_account` - `ServiceAccount` | realm (`realm_id`) | record `id` | description | File: overwrite of the map entry, no error (`qid-storage/src/file/service_account.rs:9`). SQL: plain `INSERT` with `id` as primary key, so a duplicate ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/service_account.rs:9`). **Backends disagree.** | file `qid-storage/src/file/service_account.rs:9`; sql `qid-storage/src/sql/service_account.rs:9` (not enforced as a conflict in SQL) |

## session

Model type: `Session`. Owner: realm and user (`realm_id`, `user_id`); the
session ID is the primary key (`qid-storage/migrations/20250101000001_initial_schema.sql:56`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_session` - `Session` | realm + user (`realm_id`, `user_id`) | record `id` | `idle_expires_at`, `revoked`, `cnf` | File: an existing ID is refused with `BadRequest` by `validate_session_creation` under the write lock (`qid-storage/src/file/session.rs:9`, `qid-storage/src/domain/mod.rs:17`, `qid-storage/src/domain/mod.rs:19`). SQL: a pre-read of the ID is refused with `BadRequest` (`qid-storage/src/sql/session.rs:9`, `qid-storage/src/sql/session.rs:15`); because that check is a read before the insert, a concurrent insert of the same ID is refused by the primary key as a `Storage` error instead (`qid-storage/src/sql/session.rs:24`). The sequential case agrees (`BadRequest`); the concurrent case does not. | file `qid-storage/src/file/session.rs:9`, `qid-storage/src/domain/mod.rs:19`; sql `qid-storage/src/sql/session.rs:9`, `qid-storage/src/sql/session.rs:15` |
| `update_session_idle_expiry` - `Session` | realm + user | record `id` | `idle_expires_at` | File: in-place update, an unknown ID is a silent no-op (`qid-storage/src/file/session.rs:21`). SQL: `UPDATE ... WHERE id = ?`; no row affected is not an error (`qid-storage/src/sql/session.rs:53`). Both are silent no-ops. | file `qid-storage/src/file/session.rs:21`; sql `qid-storage/src/sql/session.rs:53` |
| `revoke_session` - `Session` | realm + user | record `id` | `revoked` | File: an already revoked session is refused with `BadRequest` (`qid-storage/src/file/session.rs:31`, `qid-storage/src/domain/mod.rs:9`); an unknown ID is a silent no-op. SQL: `UPDATE ... SET revoked = 1 WHERE id = ?`; no row affected is not an error (`qid-storage/src/sql/session.rs:63`). The already-revoked check is file-path only. | file `qid-storage/src/file/session.rs:31`, `qid-storage/src/domain/mod.rs:9`; sql `qid-storage/src/sql/session.rs:63` |

## siem

Model type: `SiemDeliveryRecord`. Owner: realm (`realm_id`, optional; `None` is
the global scope). The delivery ID is the identity
(`qid-storage/migrations/20250630000001_siem_delivery_queue.sql:2`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `upsert_siem_delivery` - `SiemDeliveryRecord` | realm scope (`realm_id`, `None` = global) | record `id` | endpoint URL, payload, attempts, `next_retry_at`, status, `last_error`, `updated_at`; `created_at` is kept from the incumbent on the file path | File: an ID already bound to another realm scope is refused with `Conflict` by `ensure_same_binding` under the write lock (`qid-storage/src/file/siem.rs:10`); the same scope overwrites and keeps the original `created_at` (`qid-storage/src/file/siem.rs:15`, `qid-storage/src/file/siem.rs:20`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm scope matches (or both are `NULL`), so a foreign scope updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/siem.rs:9`, `qid-storage/src/sql/siem.rs:24`). Both refuse a foreign scope with `Conflict`. | file `qid-storage/src/file/siem.rs:10`; sql `qid-storage/src/sql/siem.rs:9`, `qid-storage/src/sql/siem.rs:24` |

## ssf

Model types: `SsfStreamRecord` and the `ssf_set_replay` record. Owner: realm
(`realm_id`). The stream identity is `(realm_id, stream_id)`
(`qid-storage/migrations/20250628000001_ssf_streams.sql:13`); the replay
identity is `(realm_id, issuer, stream_id, jti)`
(`qid-storage/migrations/20250628000001_ssf_streams.sql:22`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `upsert_ssf_stream` - `SsfStreamRecord` | realm (`realm_id`) | `(realm_id, stream_id)`; the file key is the same pair (`qid-storage/src/file/mod.rs:446`) | delivery JSON, requested events, transmitter issuer, jwks, alg, audience, status, `updated_at` | File: overwrite of the key's map entry, no error (`qid-storage/src/file/ssf.rs:9`). SQL: `ON CONFLICT(realm_id, stream_id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/ssf.rs:44`, `qid-storage/src/sql/ssf.rs:47`). Both replace. | file `qid-storage/src/file/ssf.rs:9`; sql `qid-storage/src/sql/ssf.rs:44`, `qid-storage/src/sql/ssf.rs:47` |
| `record_ssf_set_jti` - replay record | realm (`realm_id`) plus issuer and stream | `(realm_id, issuer, stream_id, jti)` | `expires_at` | File: a JTI already recorded is refused and `false` is returned (`qid-storage/src/file/ssf.rs:64`). SQL: `ON CONFLICT(realm_id, issuer, stream_id, jti) DO NOTHING` and the affected-row count decides the answer (`qid-storage/src/sql/ssf.rs:124`, `qid-storage/src/sql/ssf.rs:135`). Both refuse a replayed JTI. | file `qid-storage/src/file/ssf.rs:64`; sql `qid-storage/src/sql/ssf.rs:124` |
| `delete_ssf_stream` (delete) | realm (`realm_id`) | `(realm_id, stream_id)` | none, removal | File: the key is removed and a boolean reports whether it existed (`qid-storage/src/file/ssf.rs:41`). SQL: `DELETE ... WHERE realm_id = ? AND stream_id = ?` reported as a boolean (`qid-storage/src/sql/ssf.rs:100`, `qid-storage/src/sql/ssf.rs:106`). Both are realm-scoped. | file `qid-storage/src/file/ssf.rs:41`; sql `qid-storage/src/sql/ssf.rs:100` |

## token

Model types: `AuthorizationCode`, `TokenFamily`, `AccessToken`, `ParRequest`,
`DeviceAuthorizationGrant`, `BackchannelAuthenticationGrant`. These are
token/replay-scoped records: the owner is the realm, client and user the
record is bound to, and the identity is the opaque handle the caller presents.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_authorization_code` - `AuthorizationCode` | realm + client + user (`realm_id`, `client_id`, `user_id`) | `code_hash` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:87`) | `used`, `expires_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:11`). SQL: plain `INSERT` with `code_hash` as primary key, so a repeated hash is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:9`). **Backends disagree.** | file `qid-storage/src/file/token.rs:11`; sql `qid-storage/src/sql/token.rs:9` (not enforced as a conflict in SQL) |
| `mark_authorization_code_used` - `AuthorizationCode` | realm + client + user | `code_hash` | `used` (one-shot) | File: an unknown code is `NotFound` (`qid-storage/src/file/token.rs:29`) and an already used code is `Conflict` (`qid-storage/src/file/token.rs:33`). SQL: `UPDATE ... SET used = 1 WHERE code_hash = ? AND used = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:58`, `qid-storage/src/sql/token.rs:64`). The already-used case agrees; the unknown-ID case differs (`NotFound` against `Conflict`). | file `qid-storage/src/file/token.rs:29`, `qid-storage/src/file/token.rs:33`; sql `qid-storage/src/sql/token.rs:58`, `qid-storage/src/sql/token.rs:64` |
| `create_token_family` - `TokenFamily` | realm + client + user (`realm_id`, `client_id`, `user_id`) | record `id` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:104`) | `current_refresh_hash`, scopes, `revoked` | File: the operation replaces an existing ID, as its own comment states, and never errors (`qid-storage/src/file/token.rs:43`, `qid-storage/src/file/token.rs:53`). SQL: plain `INSERT` with `id` as primary key, so a repeated ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:73`). **Backends disagree:** the file path replaces, the SQL path refuses. | file `qid-storage/src/file/token.rs:43`, `qid-storage/src/file/token.rs:53`; sql `qid-storage/src/sql/token.rs:73` (not enforced as a conflict in SQL) |
| `create_access_token` - `AccessToken` | realm + client + user + family (`realm_id`, `client_id`, `user_id`, `family_id`) | `jti` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:116`) | `revoked` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:148`). SQL: plain `INSERT` with `jti` as primary key, so a repeated JTI is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:223`). **Backends disagree.** | file `qid-storage/src/file/token.rs:148`; sql `qid-storage/src/sql/token.rs:223` (not enforced as a conflict in SQL) |
| `store_par_request` - `ParRequest` | realm + client (`realm_id`, `client_id`) | `request_uri` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:163`) | `used`, `expires_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:170`). SQL: plain `INSERT` with `request_uri` as primary key, so a repeated URI is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:271`). **Backends disagree.** | file `qid-storage/src/file/token.rs:170`; sql `qid-storage/src/sql/token.rs:271` (not enforced as a conflict in SQL) |
| `mark_par_request_used` - `ParRequest` | realm + client | `request_uri` | `used` (one-shot) | File: an unknown URI is `NotFound` (`qid-storage/src/file/token.rs:186`) and an already used request is `Conflict` (`qid-storage/src/file/token.rs:190`). SQL: `UPDATE ... WHERE request_uri = ? AND used = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:298`, `qid-storage/src/sql/token.rs:304`). The already-used case agrees; the unknown-ID case differs. | file `qid-storage/src/file/token.rs:186`, `qid-storage/src/file/token.rs:190`; sql `qid-storage/src/sql/token.rs:298`, `qid-storage/src/sql/token.rs:304` |
| `store_device_authorization_grant` - `DeviceAuthorizationGrant` | realm + client (+ user once approved) | `device_code_hash` (primary key; `user_code` is also unique, `qid-storage/migrations/20250101000001_initial_schema.sql:174`) | `approved_at`, `consumed`, `last_poll_at`, `poll_interval_seconds` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:206`). SQL: plain `INSERT`, so a repeated device code or user code is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:316`). **Backends disagree.** | file `qid-storage/src/file/token.rs:206`; sql `qid-storage/src/sql/token.rs:316` (not enforced as a conflict in SQL) |
| `consume_device_authorization_grant` - `DeviceAuthorizationGrant` | realm + client + user | `device_code_hash` | `consumed` (one-shot) | File: an already consumed grant is `Conflict` (`qid-storage/src/file/token.rs:280`). SQL: `UPDATE ... WHERE device_code_hash = ? AND consumed = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:405`, `qid-storage/src/sql/token.rs:412`). Both refuse a replayed consumption. | file `qid-storage/src/file/token.rs:280`; sql `qid-storage/src/sql/token.rs:405`, `qid-storage/src/sql/token.rs:412` |
| `store_backchannel_authentication_grant` - `BackchannelAuthenticationGrant` | realm + client (+ user once approved) | `auth_req_id_hash` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:190`) | `approved_at`, `consumed`, `last_poll_at`, `poll_interval_seconds` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:296`). SQL: plain `INSERT` with `auth_req_id_hash` as primary key, so a repeated request ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:424`). **Backends disagree.** | file `qid-storage/src/file/token.rs:296`; sql `qid-storage/src/sql/token.rs:424` (not enforced as a conflict in SQL) |

## user

Model types: `User`, `PasswordCredential`. Owner: realm (`realm_id`); the
password credential is owned by the user (`user_id`). The users table
declares `UNIQUE(realm_id, email)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:21`) and the
password credential table is keyed by `user_id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:25`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_user` - `User` | realm (`realm_id`) | record `id`; the schema also names a user by `(realm_id, email)` | email, `email_verified`, display name, `failed_login_attempts`, `locked_until`, `org` | File: a taken record ID and a taken email in the realm are both refused with `Conflict` under the exclusive write lock, and the incumbent user is left unchanged (`qid-storage/src/file/user.rs:14`, `qid-storage/src/file/user.rs:19`, `qid-storage/src/file/user.rs:24`). SQL: the insert carries `ON CONFLICT DO NOTHING`, so the primary key and the `UNIQUE(realm_id, email)` index refuse the duplicate inside the insert, and the zero-row result becomes a `Conflict` that names the taken key (`qid-storage/src/sql/user.rs:13`, `qid-storage/src/sql/user.rs:26`, `qid-storage/src/sql/user.rs:36`). Both refuse with `Conflict`; the same email in another realm names another user and is allowed. | file `qid-storage/src/file/user.rs:14`; sql `qid-storage/src/sql/user.rs:13`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:21` |
| `update_user` - `User` | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | email, `email_verified`, display name, `failed_login_attempts`, `locked_until`, `org`, `updated_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/user.rs:69`). SQL: `UPDATE ... WHERE id = ?`; no row affected is not an error (`qid-storage/src/sql/user.rs:160`). Both update by ID only, and neither re-checks the email uniqueness. | file `qid-storage/src/file/user.rs:69`; sql `qid-storage/src/sql/user.rs:160` |
| `store_password_credential` - `PasswordCredential` | user (`user_id`) | `user_id` (primary key) | hash, algorithm | File: overwrite of the map entry, no error (`qid-storage/src/file/user.rs:77`). SQL: `ON CONFLICT(user_id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/user.rs:63`, `qid-storage/src/sql/user.rs:64`). Both replace. | file `qid-storage/src/file/user.rs:77`; sql `qid-storage/src/sql/user.rs:63` |

## vc

Model type: `VcCredentialStatusRecord`. Owner: realm and subject
(`realm_id`, `subject`); the identity is the credential ID (primary key,
`qid-storage/migrations/20250618000027_vc_credential_statuses.sql:2`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_vc_credential_status` - `VcCredentialStatusRecord` | realm + subject (`realm_id`, `subject`) | credential `credential_id` | `revoked`, `revocation_reason`, `revoked_at` | File: an existing credential ID is refused with `Storage` before the write (`qid-storage/src/file/vc.rs:9`, `qid-storage/src/file/vc.rs:13`). SQL: plain `INSERT` with `credential_id` as primary key, so a duplicate credential ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/vc.rs:9`, `qid-storage/src/sql/row.rs:10`). Both refuse a duplicate with `Storage`. | file `qid-storage/src/file/vc.rs:9`; sql `qid-storage/src/sql/vc.rs:9` |
| `revoke_vc_credential` - `VcCredentialStatusRecord` | realm + subject | credential `credential_id` | `revoked`, `revocation_reason`, `revoked_at` | File: an unknown credential ID is `NotFound` (`qid-storage/src/file/vc.rs:40`). SQL: `UPDATE ... WHERE credential_id = ?` and no affected row is `NotFound` (`qid-storage/src/sql/vc.rs:47`, `qid-storage/src/sql/vc.rs:56`). Both agree. | file `qid-storage/src/file/vc.rs:40`; sql `qid-storage/src/sql/vc.rs:56` |

## workload

Model types: `WorkloadIdentity`, `WorkloadCertificate`. This family is the
migrated prototype of the ownership contract.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_workload_identity` - `WorkloadIdentity` | realm (`realm_id`) | SPIFFE ID (`spiffe_id`), unique per realm (`qid-storage/migrations/20250702000001_workload_identities_spiffe_unique.sql:4`); the record `id` names the same identity | description, trust domain, authorities | File: a second identity for one SPIFFE ID in the realm is refused with `BadRequest` under the store's exclusive write lock (`qid-storage/src/file/workload.rs:17`, `qid-storage/src/file/workload.rs:20`); an incumbent ID bound to another `(realm, spiffe_id)` is refused with `Conflict` (`qid-storage/src/file/workload.rs:9`); the same identity under the same ID overwrites (`qid-storage/src/file/workload.rs:24`). SQL: the unique violation on `(realm_id, spiffe_id)` is mapped to `BadRequest` inside the insert (`qid-storage/src/sql/workload.rs:26`, `qid-storage/src/sql/workload.rs:27`); the upsert's `WHERE` predicate covers the same `(realm, spiffe_id)`, so an ID bound to another identity updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/workload.rs:14`, `qid-storage/src/sql/workload.rs:15`, `qid-storage/src/sql/workload.rs:33`). Both refuse a second identity for one SPIFFE ID with `BadRequest` and a foreign binding with `Conflict`. | file `qid-storage/src/file/workload.rs:9`, `qid-storage/src/file/workload.rs:17`; sql `qid-storage/src/sql/workload.rs:14`, `qid-storage/src/sql/workload.rs:26`, `qid-storage/src/sql/workload.rs:33` |
| `delete_workload_identity` (delete) | realm (`realm_id`) | record `id` | none, removal | File: an identity of another realm or an unknown ID is `NotFound` under the write lock (`qid-storage/src/file/workload.rs:62`, `qid-storage/src/file/workload.rs:67`). SQL: `DELETE ... WHERE realm_id = ? AND id = ?` and no affected row is `NotFound` (`qid-storage/src/sql/workload.rs:69`, `qid-storage/src/sql/workload.rs:76`). Both agree. | file `qid-storage/src/file/workload.rs:62`, `qid-storage/src/file/workload.rs:67`; sql `qid-storage/src/sql/workload.rs:69`, `qid-storage/src/sql/workload.rs:76` |
| `store_workload_certificate` - `WorkloadCertificate` | realm + workload (`realm_id`, `workload_id`); the referenced identity must exist and match | record `id`; the thumbprint `x5t_s256` is unique per realm (`qid-storage/migrations/20250618000034_workload_certificates.sql:17`) | serial number, CSR, certificate PEM, `revoked_at`, validity dates | File: a missing workload is `BadRequest` (`qid-storage/src/file/workload.rs:79`, `qid-storage/src/file/workload.rs:80`) and a workload of another realm or SPIFFE ID is `BadRequest` (`qid-storage/src/file/workload.rs:84`, `qid-storage/src/file/workload.rs:86`); an incumbent ID bound to another `(realm, workload, spiffe_id)` is `Conflict` (`qid-storage/src/file/workload.rs:90`); another certificate with the same thumbprint in the realm is `BadRequest` (`qid-storage/src/file/workload.rs:102`, `qid-storage/src/file/workload.rs:107`). SQL: the same identity checks produce `BadRequest` (`qid-storage/src/sql/workload.rs:92`, `qid-storage/src/sql/workload.rs:97`) and a repeated thumbprint is `BadRequest` (`qid-storage/src/sql/workload.rs:101`, `qid-storage/src/sql/workload.rs:111`); the upsert's `WHERE` predicate covers `(realm, workload, spiffe_id)`, so an ID bound to another identity updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/workload.rs:117`, `qid-storage/src/sql/workload.rs:118`, `qid-storage/src/sql/workload.rs:136`). Both refuse the same cases with the same errors. | file `qid-storage/src/file/workload.rs:90`, `qid-storage/src/file/workload.rs:102`; sql `qid-storage/src/sql/workload.rs:101`, `qid-storage/src/sql/workload.rs:117`, `qid-storage/src/sql/workload.rs:136` |
