# Storage ownership inventory (qid-storage)

Factual inventory of the ID-keyed persistent writes in the two `qid-storage`
backends: the file backend (`qid-storage/src/file/`) and the SQL backend
(`qid-storage/src/sql/`). One section per crate module, sorted by module name.
Every claim is backed by a `file:line` citation; where a rule is not in the
code, the cell says so instead of guessing.

Scope: every write the repository traits declare. That is the writes that
persist a record under an ID the caller supplies or that the record is keyed by
(create / store / update / upsert), the one-shot consumption, revocation,
approval, poll, mutation and deletion writes, and the owner-scoped deletes that
carry the ownership contract. The traits declare 130 write methods, all listed in the tables below. The push lifecycle table also shows its owner-bound reads
for context.

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

## Email challenge admission

`try_issue_email_challenge` is the shared atomic admission for email magic-link
login and session-bound email verification. It persists before delivery under a
per-(realm,user,purpose) rolling quota; consumed, expired, failed-delivery and
newer records count. Both backends check the current realm/user and exact stored
address. Magic-link admission still requires a verified email and digest-pair
proof; email verification requires an unverified email and no magic-link proof.
Duplicates return `Conflict` without overwriting the incumbent; quota or owner
ineligibility returns false without insertion. File admission holds the exclusive
save/store locks through persistence with rollback on error, including interval
flush mode. SQL uses `BEGIN IMMEDIATE` on SQLite, or a purpose-bound advisory
transaction lock and owner-row lock on PostgreSQL, before counting and inserting.
See `qid-storage/src/file/ciam.rs` and `qid-storage/src/sql/ciam.rs`.

## The ownership contract

One shape covers every migrated write. A resource states three things and
the backends enforce them in their own idiom:

- the **owner key** - the realm, tenant or user the record belongs to;
- the **identity key** - the immutable key that names the record inside its
  owner, so a second record with the same identity belongs to no one;
- the **collision rule** - what a write does when the identity key is
  already taken: refuse and leave the incumbent unchanged, or replace the
  incumbent.

The file backend holds the store's exclusive write lock, so it checks the
owner and identity keys there and refuses before the write. The SQL backend
lets the table's primary key and unique indexes refuse the duplicate inside
the statement, so no read precedes the write and no duplicate can slip
between a check and an insert. The two idioms differ; the outcome does not.

Shared helpers in `qid-storage/src/ownership.rs` classify common error
outcomes, while each concrete File or SQL method enforces the documented
semantics through lock-protected checks or atomic statements:

- `ensure_same_binding` - the file path, under the write lock, refuses a
  write whose identity key is bound to another owner; the SQL client update
  reuses it after the guarded statement to classify a zero-row result.
- `ensure_upsert_applied` - the SQL path translates a zero-row atomic write
  into `Conflict` when a duplicate identity, owner/identity predicate, or
  one-shot lifecycle predicate refused it.
- `ensure_row_present` - the SQL path refuses a write that changed no row
  because the record is gone.
- `user_email_conflict` - the refusal a user write earns when the realm
  already holds the email for another user.
- `file::insert::insert_new` - a typed create-only map operation, called under
  the exclusive store lock, reads the global ID and optional `(owner, identity)`
  projection itself, refuses a taken key before mutation, and inserts only
  when both keys are clear. Its private `InsertIdentity` implementations
  cover `PolicyBundle`, `User`, `ScimUser`, `ScimGroup`, `Client`,
  `ParRequest`, `DeviceAuthorizationGrant`, and
  `BackchannelAuthenticationGrant`.
  `ParRequest` and `BackchannelAuthenticationGrant` use only their record IDs;
  device user codes are globally unique. `User.email=None` has no identity key,
  matching SQL's multiple-NULL behavior. ID conflicts take precedence on the
  file path and retain the resource's existing messages.
- `ClientRepository::update_client` - the File path checks the incumbent
  `(realm_id, client_id)` binding with `ensure_same_binding` under the exclusive
  store lock before replacement; a missing ID still inserts. SQL keeps the same
  binding in its static atomic update predicate and classifies zero-row results.
  File and SQL enforcement are in `qid-storage/src/file/client.rs:14` and
  `qid-storage/src/sql/client.rs:63`, respectively; the repository trait
  contract is at `qid-storage/src/traits.rs:131`.

The inventory tables below record owner keys, identity keys, collision rules,
and backend behavior. Shared helpers standardize error outcomes; they do not
execute or dispatch resource writes. Each backend retains resource-specific
enforcement under the File write lock or in its static SQL statement.
Replacement, append-only and lifecycle operations remain separate; the
create-only primitive does not apply to them.

The migrated families are the workload identity, the client, the CIAM
consent grant, the user, the realm, the device, the FedCM identity, the service
account, the WebAuthn credential, the policy bundle, IGA access requests,
approvals, access grants, JIT privilege grants, and access review campaigns.
The remaining disagreements are listed above; they are not all defects. A
write whose identity key is a token the product generates (an authorization code, a PAR request, a device or
backchannel grant) has no owner
to protect, and a write whose same-owner semantics are
"replace" (an upsert of a configuration record) states that on purpose.

The rows for one-shot consumption, bounded attempts, revocation, approval, poll,
mutation and deletion writes record a second class of difference. A write whose
identity key is a token the product generates, or a record the caller owns, asks
its backend whether the record is still in play. The SQL statement's WHERE
clause cannot distinguish an unknown ID from an existing record that no longer
meets the operation's preconditions, so the update matches no row in both
cases. The backend may classify the zero-row result with a post-write lookup to
preserve the intended errors.
For `attempt_ciam_verification_challenge`, SQL classifies a zero-row update with
a post-write owner lookup, matching the file path's `NotFound` for missing or
foreign-realm records and `Conflict` for an unusable challenge owned by the
realm (wrong hash, expired, exhausted or already consumed).
For `consume_password_reset_token`, SQL now classifies a zero-row update with
a post-write existence lookup, matching the file path's `NotFound` for an
unknown ID and `Conflict` for an already consumed token.
The reverse shape is there too: `revoke_token_family(id, realm_id)` leaves a
missing or foreign-realm family unchanged, with a silent no-op in the file
path and `NotFound` in the SQL path. Both accept repeated same-realm revocation.

## admin

Model types: `Admin`, `AdminElevation`, `AdminApproval`. The owner is the
tenant (`tenant_id`); the table declares `UNIQUE(tenant_id, subject)`
(`qid-storage/migrations/20250626000001_admin_tables.sql:7`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `upsert_admin` - `Admin` | tenant (`tenant_id`) | `(tenant_id, subject)` | roles, `created_at` | File: the incumbent with the same tenant and subject is removed and the new record inserted, so the write replaces and never errors (`qid-storage/src/file/admin.rs:23`, `qid-storage/src/file/admin.rs:26`). SQL: `ON CONFLICT(tenant_id, subject) DO UPDATE SET roles_json`, an upsert that keeps the incumbent row ID and never errors (`qid-storage/src/sql/admin.rs:29`, `qid-storage/src/sql/admin.rs:30`). Both replace; the file path also changes the record ID, the SQL path keeps it. | file `qid-storage/src/file/admin.rs:23`; sql `qid-storage/src/sql/admin.rs:30`; schema `qid-storage/migrations/20250626000001_admin_tables.sql:7` |
| `store_admin_elevation` - `AdminElevation` | tenant (`tenant_id`) | globally unique record `id` | none; elevation claims and expiry belong to the immutable record | File: an existing ID is refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/admin.rs:37`, `qid-storage/src/file/admin.rs:38`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/admin.rs:55`, `qid-storage/src/sql/admin.rs:67`). Both refuse same-tenant and cross-tenant collisions and preserve the incumbent context. | file `qid-storage/src/file/admin.rs:37`, `qid-storage/src/file/admin.rs:38`; sql `qid-storage/src/sql/admin.rs:55`, `qid-storage/src/sql/admin.rs:67`; schema `qid-storage/migrations/20250626000001_admin_tables.sql:10` |
| `store_admin_approval` - `AdminApproval` | tenant (`tenant_id`) | globally unique record `id` | approver, target, reason, `approved_at`, `expires_at`, one-shot `consumed` | File: an existing ID is refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/admin.rs:55`, `qid-storage/src/file/admin.rs:56`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/admin.rs:85`, `qid-storage/src/sql/admin.rs:98`). Both refuse same-tenant and cross-tenant collisions and preserve the incumbent, including consumed state. | file `qid-storage/src/file/admin.rs:55`, `qid-storage/src/file/admin.rs:56`; sql `qid-storage/src/sql/admin.rs:85`, `qid-storage/src/sql/admin.rs:98`; schema `qid-storage/migrations/20250626000001_admin_tables.sql:22` |
| `consume_admin_approval_if_unconsumed` - `AdminApproval` | tenant (`tenant_id`) in the record; the write is not tenant-filtered | record `id` | `consumed` (one-shot) | File: an unknown ID is `Ok(false)` and an already consumed approval is `Ok(false)` without a write (`qid-storage/src/file/admin.rs:69`, `qid-storage/src/file/admin.rs:70`, `qid-storage/src/file/admin.rs:76`). SQL: `UPDATE ... WHERE id = ? AND consumed = 0` and the affected-row count answers the boolean, so an unknown ID and an already consumed approval are both `Ok(false)` (`qid-storage/src/sql/admin.rs:106`, `qid-storage/src/sql/admin.rs:111`). Both agree. | file `qid-storage/src/file/admin.rs:76`; sql `qid-storage/src/sql/admin.rs:111` |

Call-site review at commit `76c706a997c7154064f020245be3b6d2a6bf6cc5`: both live authorization paths resolve the approval by ID and check `approval.tenant_id` against the authenticated admin before consumption (`qid-admin/src/authz.rs:524`, `qid-admin/src/authz.rs:599`, `qid-admin/src/authz.rs:620-628`). The `AdminRepository` contract exposes get/store/consume but no update/delete (`qid-storage/src/traits.rs:932-940`); both stores reject duplicate approval IDs, and consumption changes only `consumed` (`qid-storage/src/file/admin.rs:51-78`, `qid-storage/src/sql/admin.rs:83-118`). No tenant-reassignment path was identified for this ID-only one-shot write.

## audit

Model types: `AuditEvent`, `AuditRetentionConfig`. Audit records are
realm-scoped but not tenant-scoped: `realm_id` is optional and `None` denotes
the global stream (`qid-storage/src/file/audit.rs:13`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `append_audit_event` - `AuditEvent` | realm (`realm_id`, `None` = global stream); internal record, not tenant-scoped | globally unique event `id` | none, append-only; chain hashes are derived on append | File: any existing ID is refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/audit.rs:9`, `qid-storage/src/file/audit.rs:14`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/audit.rs:27`, `qid-storage/src/sql/audit.rs:43`). Both refuse same-stream and cross-realm duplicate IDs and preserve the incumbent history. | file `qid-storage/src/file/audit.rs:9`, `qid-storage/src/file/audit.rs:14`; sql `qid-storage/src/sql/audit.rs:27`, `qid-storage/src/sql/audit.rs:43`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:72` |
| `set_audit_retention_config` - `AuditRetentionConfig` | realm (`realm_id`, `None` = global key `__global__`) | the retention key, realm or `__global__` (`qid-storage/src/file/mod.rs:438`, `qid-storage/src/sql/row/security.rs:144`) | `retention_days`, `legal_hold`, `updated_by`, `reason`, `updated_at` | File: overwrite of the map entry, no error (`qid-storage/src/file/audit.rs:71`). SQL: `ON CONFLICT(stream_id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/audit.rs:101`). Both replace. | file `qid-storage/src/file/audit.rs:69`, `qid-storage/src/file/audit.rs:71`; sql `qid-storage/src/sql/audit.rs:101`, `qid-storage/src/sql/audit.rs:103` |

## ciam

Model types: `CiamConsentGrant`, `CiamVerificationChallengeRecord`,
`CiamIdentityLink`, `PasswordResetToken`, `CiamProgressiveProfile`.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_ciam_consent_grant` - `CiamConsentGrant` | realm + user (`realm_id`, `user_id`) | `client_id` inside that owner | granted claims, terms version, `revoked` | File: an incumbent with the same ID but another `(realm, user, client)` binding is refused with `Conflict` under the exclusive write lock; the same binding overwrites (`qid-storage/src/file/ciam.rs:11`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the same `(realm, user, client)` binding, so a different binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:12`, `qid-storage/src/sql/ciam.rs:13`, `qid-storage/src/sql/ciam.rs:26`). Both refuse a foreign binding with `Conflict`. | file `qid-storage/src/file/ciam.rs:11`; sql `qid-storage/src/sql/ciam.rs:12`, `qid-storage/src/sql/ciam.rs:26` |
| `revoke_ciam_consent_grant` - `CiamConsentGrant` | realm + user (`realm_id`, `user_id`) in the record; the write is not realm-filtered | record `id` | `revoked` | Both: an unknown ID is a silent `Ok` no-op that creates nothing; revoking an existing grant sets `revoked = true`, and repeated revocation succeeds with the incumbent still revoked. File checks under the exclusive write lock (`qid-storage/src/file/ciam.rs:48`). SQL is the static `UPDATE ciam_consent_grants SET revoked = 1 WHERE id = ?` where no affected row is not an error (`qid-storage/src/sql/ciam.rs:60`). Contract: `qid-storage/src/traits.rs:480`. | file `qid-storage/src/file/ciam.rs:48`; sql `qid-storage/src/sql/ciam.rs:60`; contract `qid-storage/src/traits.rs:480` |
| `store_ciam_verification_challenge` - `CiamVerificationChallengeRecord` | realm (`realm_id`) | globally unique record `id` | none on creation; later attempt/confirmation/redemption operations change attempts and may consume | File: duplicate IDs are refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/ciam.rs:67`, `qid-storage/src/file/ciam.rs:71`). SQL: `ON CONFLICT(id) DO NOTHING` plus `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/ciam.rs:75`, `qid-storage/src/sql/ciam.rs:90`). Both same-realm and cross-realm collisions preserve the incumbent challenge and its consumed state. | file `qid-storage/src/file/ciam.rs:67`, `qid-storage/src/file/ciam.rs:71`; sql `qid-storage/src/sql/ciam.rs:75`, `qid-storage/src/sql/ciam.rs:90`; schema `qid-storage/migrations/20250618000029_ciam_records.sql:16` |
| `attempt_ciam_verification_challenge` - `CiamVerificationChallengeRecord` | realm (`realm_id`) | challenge record `id` | `attempt_count`, `consumed_at_epoch_seconds` | File: under the exclusive write lock, a missing or foreign ID is `NotFound`; the exact stored code hash must match in constant time and an unconsumed, unexpired, under-limit challenge is required (`qid-storage/src/file/ciam.rs:108`, `qid-storage/src/file/ciam.rs:117`, `qid-storage/src/file/ciam.rs:125`). A valid attempt increments the count and a verified attempt consumes. SQL: one atomic `UPDATE` predicates on realm, ID, expected hash, unconsumed state, expiry and attempt limit; a zero-row result is classified as `NotFound` for missing/foreign IDs and `Conflict` otherwise (`qid-storage/src/sql/ciam.rs:115`, `qid-storage/src/sql/ciam.rs:124`, `qid-storage/src/sql/ciam.rs:137`). | file `qid-storage/src/file/ciam.rs:117`, `qid-storage/src/file/ciam.rs:125-141`; sql `qid-storage/src/sql/ciam.rs:124`, `qid-storage/src/sql/ciam.rs:137`; contract `qid-storage/src/traits.rs:563` |
| `confirm_ciam_email_verification` - `CiamVerificationChallengeRecord` and `User` | realm + user (`realm_id`, `user_id`) | challenge record `id` | `attempt_count`, `consumed_at_epoch_seconds`, user's `email_verified` | File: the save lock and exclusive store lock bind the challenge to the realm/user, email-verification purpose and the user's current stored address; an eligible attempt increments durably, a match consumes and verifies that address atomically, and persistence failure rolls both records back (`qid-storage/src/file/ciam.rs:162-185`, `qid-storage/src/file/ciam.rs:195-229`). SQL: a transaction's conditional challenge `UPDATE ... RETURNING` includes realm, ID, user, purpose, active-state and limit predicates plus an `EXISTS` check for the current user's realm/address; a wrong code commits only the bounded attempt, while a match verifies the same current address and consumes in the transaction (`qid-storage/src/sql/ciam.rs:169-204`). Ineligible, foreign or stale-owner challenges return false without mutation; an eligible code mismatch still records its bounded attempt. Both backends keep the challenge and user change atomic. | file `qid-storage/src/file/ciam.rs:162-185`, `qid-storage/src/file/ciam.rs:195-229`; sql `qid-storage/src/sql/ciam.rs:169-204`; contract `qid-storage/src/traits.rs:578` |
| `try_issue_email_challenge` - `CiamVerificationChallengeRecord` | realm + user (`realm_id`, `user_id`); `purpose` partitions the rolling quota | globally unique challenge record `id` | none on admission; starts with zero attempts and no consumption, which later lifecycle operations may change | File: under the save and exclusive store locks, rejects a duplicate ID with `Conflict`, requires the current user in the challenge realm with the exact address and purpose-appropriate verification state, and counts every challenge of that purpose inside the rolling window. `true` persists the fresh challenge; quota or owner ineligibility returns false without insertion; persistence errors roll back (`qid-storage/src/file/ciam.rs:239`, `qid-storage/src/file/ciam.rs:251-276`, `qid-storage/src/file/ciam.rs:279-292`). SQL: serializes admission with SQLite `BEGIN IMMEDIATE` or a PostgreSQL purpose-bound advisory transaction lock, rejects duplicate IDs, locks/checks the user, and conditionally inserts only below quota; `true` inserts, false suppresses, and duplicate IDs conflict (`qid-storage/src/sql/ciam.rs:208`, `qid-storage/src/sql/ciam.rs:217-269`, `qid-storage/src/sql/ciam.rs:276-284`). | file `qid-storage/src/file/ciam.rs:251-292`; sql `qid-storage/src/sql/ciam.rs:217-284`; contract `qid-storage/src/traits.rs:587-602` |
| `redeem_email_magic_link_challenge` - `CiamVerificationChallengeRecord` and `User` | realm + user (`realm_id`, `user_id`) | challenge record `id` | `attempt_count`, `consumed_at_epoch_seconds` | File: under the save and exclusive store locks, redemption requires the realm, email/magic-link purpose, active time/attempt bounds and the user's current verified address; malformed or wrong binding proofs do not spend attempts, a bound token mismatch increments durably, and a match increments, consumes once and returns the bound user only after persistence (`qid-storage/src/file/ciam.rs:315-365`). SQL: a transaction locks/updates the realm-scoped challenge without spending an attempt, locks and rechecks the current owner, rejects invalid binding proofs without writing, then atomically records the attempt and consumes a match before returning the user (`qid-storage/src/sql/ciam.rs:298-347`). Foreign, stale, expired, unverified or exhausted challenges return no user without mutation. | file `qid-storage/src/file/ciam.rs:315-365`; sql `qid-storage/src/sql/ciam.rs:298-347`; contract `qid-storage/src/traits.rs:618` |
| `store_ciam_identity_link` - `CiamIdentityLink` | realm + user (`realm_id`, `user_id`) | `(realm_id, provider, external_subject)`, unique index (`qid-storage/migrations/20250618000031_ciam_identity_links.sql:13`) | `external_email`, profile, `linked_at`, `verified` | File: a second verified link for the same `(realm, provider, external_subject)` is refused with `BadRequest` (`qid-storage/src/file/ciam.rs:126`, `qid-storage/src/file/ciam.rs:134`); an existing ID whose owner or identity key differs is refused with `Conflict` (`qid-storage/src/domain/mod.rs:81`, `qid-storage/src/domain/mod.rs:87`); a verified link may not revert to unverified (`qid-storage/src/domain/mod.rs:94`, `qid-storage/src/domain/mod.rs:98`). SQL: a verified duplicate is refused with `BadRequest` (`qid-storage/src/sql/ciam.rs:157`, `qid-storage/src/sql/ciam.rs:170`); the upsert's `WHERE` predicate covers realm, user and identity key, so a foreign binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:174`, `qid-storage/src/sql/ciam.rs:175`, `qid-storage/src/sql/ciam.rs:192`). Both refuse the same cases with the same errors. | file `qid-storage/src/file/ciam.rs:126`, `qid-storage/src/domain/mod.rs:81`; sql `qid-storage/src/sql/ciam.rs:157`, `qid-storage/src/sql/ciam.rs:192` |
| `delete_ciam_identity_link` (delete) | realm (`realm_id`) | record `id` | none, removal | File: the link is removed only when its realm matches, and a missing link or a link of another realm is a silent no-op (`qid-storage/src/file/ciam.rs:202`, `qid-storage/src/file/ciam.rs:204`). SQL: `DELETE ... WHERE realm_id = ? AND id = ?` and a missing link is a silent no-op (`qid-storage/src/sql/ciam.rs:245`). Both are realm-scoped. | file `qid-storage/src/file/ciam.rs:204`; sql `qid-storage/src/sql/ciam.rs:245` |
| `store_password_reset_token` - `PasswordResetToken` | realm + user (`realm_id`, `user_id`) | globally unique record `id` | none; token identity and context are immutable; consumption changes only through its one-shot operation | File: duplicate IDs are refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/ciam.rs:224`, `qid-storage/src/file/ciam.rs:225`). SQL: `ON CONFLICT(id) DO NOTHING` plus `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/ciam.rs:263`, `qid-storage/src/sql/ciam.rs:277`). Both same-realm and cross-realm collisions preserve the incumbent token and its consumed state. | file `qid-storage/src/file/ciam.rs:224`, `qid-storage/src/file/ciam.rs:225`; sql `qid-storage/src/sql/ciam.rs:263`, `qid-storage/src/sql/ciam.rs:277`; schema `qid-storage/migrations/20250618000029_ciam_records.sql:32` |
| `try_issue_password_reset_token` - `PasswordResetToken` | realm + user (`realm_id`, `user_id`) | globally unique record `id` | insert only; creation time and policy are server-authored | File: check rolling budget and duplicate ID under the exclusive storage lock. SQL: serialize per-account issuance in a transaction (SQLite `BEGIN IMMEDIATE`, PostgreSQL transaction advisory lock), then conditional insert using the existing realm/user/creation index. All records since the window start count regardless of delivery, expiry or consumption. `true` inserts, `false` suppresses with no write; duplicate IDs and storage failures remain errors even over budget. Checked timestamp bounds prevent integer wrapping. | `qid-storage/src/file/ciam.rs`, `qid-storage/src/sql/ciam.rs`; contract tests `qid-storage/tests/password_reset.rs` |
| `consume_password_reset_token` - `PasswordResetToken` | realm + user (`realm_id`, `user_id`) in the record; the write is not realm-filtered | record `id` | `consumed_at_epoch_seconds` (one-shot) | Both: an unknown ID is `NotFound`; an already consumed token is `Conflict`. Rejected calls leave the incumbent unchanged. File reads the record under the write lock. SQL uses a static atomic `UPDATE ... WHERE id = ? AND consumed_at_epoch_seconds IS NULL`; after zero rows, a static existence lookup returns `NotFound` for a missing ID and `Conflict` otherwise. | file `qid-storage/src/file/ciam.rs:247`; sql `qid-storage/src/sql/ciam.rs:308` |
| `replace_password_with_reset_token` - `PasswordResetToken` and `PasswordCredential` | realm + user (`realm_id`, `user_id`); the token and the credential must name the same realm and user | record `id` of the reset token | the credential's hash and algorithm, and the token's `consumed_at_epoch_seconds` | File: an unknown token is `NotFound` (`qid-storage/src/file/ciam.rs:392`); `validate_password_reset` refuses a foreign realm or user with `BadRequest`, a consumed token with `Conflict`, and an expired token, a wrong device or a wrong hash with `BadRequest` (`qid-storage/src/domain/mod.rs:118`, `qid-storage/src/domain/mod.rs:123`, `qid-storage/src/domain/mod.rs:137`). SQL: the same refusals, and a row the claim did not match is read back and refused the same way, with `Conflict` as the last answer (`qid-storage/src/sql/ciam.rs:334`, `qid-storage/src/sql/ciam.rs:337`, `qid-storage/src/sql/ciam.rs:345`). Both refuse the same cases with the same errors. | file `qid-storage/src/file/ciam.rs:392`; sql `qid-storage/src/sql/ciam.rs:345` |
| `store_ciam_progressive_profile` - `CiamProgressiveProfile` | realm + user (`realm_id`, `user_id`); the file key is `realm_id` + `user_id` (`qid-storage/src/file/mod.rs:52`) | record `id`, unique per `(realm, user)` (`qid-storage/migrations/20250625000001_ciam_profiles.sql:11`) | `profile_json`, `passwordless_migrated_at`, `updated_at` | File: an ID already held by another `(realm, user)` is refused with `Conflict`, and the key's identity (`id`, realm, user) may not change (`qid-storage/src/file/ciam.rs:316`, `qid-storage/src/file/ciam.rs:328`); the same owner and ID overwrites. SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` realm and user match, so a foreign binding updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/ciam.rs:382`, `qid-storage/src/sql/ciam.rs:383`, `qid-storage/src/sql/ciam.rs:406`); a unique violation on the `(realm, user)` index is mapped to `Conflict` (`qid-storage/src/sql/ciam.rs:395`). Both refuse a foreign binding with `Conflict`. | file `qid-storage/src/file/ciam.rs:316`, `qid-storage/src/file/ciam.rs:328`; sql `qid-storage/src/sql/ciam.rs:382`, `qid-storage/src/sql/ciam.rs:406` |
| `delete_ciam_progressive_profile` (delete) | realm + user (`realm_id`, `user_id`); the file key is `realm_id` + `user_id` (`qid-storage/src/file/mod.rs:52`) | `(realm_id, user_id)` | none, removal | File: the key is removed and a missing profile is a silent no-op (`qid-storage/src/file/ciam.rs:344`, `qid-storage/src/file/ciam.rs:345`). SQL: `DELETE ... WHERE realm_id = ? AND user_id = ?` and a missing profile is a silent no-op (`qid-storage/src/sql/ciam.rs:415`). Both are realm- and user-scoped. | file `qid-storage/src/file/ciam.rs:345`; sql `qid-storage/src/sql/ciam.rs:415` |

Call-site review at commit `d3797dc`: the CIAM routes expose consent evaluation and grant submission plus a read-only privacy dashboard, but no revoke route (`qid-resource/src/lib.rs:261-288`). The grant handler binds the path realm, requires a session for that realm/user, and calls `store_ciam_consent_grant` (`qid-resource/src/ciam/profile.rs:287-301`); no in-workspace production caller of `revoke_ciam_consent_grant` was found. The standalone `consume_password_reset_token` also has no in-workspace production caller: the public password-reset consume route validates the submitted proof and uses `replace_password_with_reset_token` with the path realm, token hash, device and credential (`qid-resource/src/lib.rs:298-304`, `qid-resource/src/ciam/auth.rs:252-300`), whose storage contract atomically checks those bindings. These ID-only standalone operations are not current product call paths, so no isolated guard change is proposed.

## client

Model type: `Client`. The owner is the realm; the client ID names one client
inside a realm (`UNIQUE(realm_id, client_id)`,
`qid-storage/migrations/20250101000001_initial_schema.sql:52`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_client` - `Client` | realm (`realm_id`) | record `id` and `client_id` (unique per realm) | redirect URIs, grant types, secret hash, mTLS thumbprints, jwks, contacts, metadata including `require_pushed_authorization_requests` | File: `insert_new` under the store's exclusive write lock refuses an existing record ID with `Conflict` and an existing `(realm, client_id)` with `Conflict` (`qid-storage/src/file/client.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:58`). SQL: `ON CONFLICT DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` with a message naming which key was taken (`qid-storage/src/sql/client.rs:12`, `qid-storage/src/sql/client.rs:43`, `qid-storage/src/sql/client.rs:58`). Both refuse with `Conflict`. | file `qid-storage/src/file/client.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:58`; sql `qid-storage/src/sql/client.rs:12`, `qid-storage/src/sql/client.rs:43`, `qid-storage/src/sql/client.rs:58`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:52`, `qid-storage/migrations/20250703000001_clients_require_par.sql:1` |
| `update_client` - `Client` | realm (`realm_id`) | record `id` plus stable `(realm_id, client_id)` binding | client metadata fields including `require_pushed_authorization_requests` | File: the resource-local `update_client` check calls `ensure_same_binding` under the exclusive write lock and refuses a mismatched `(realm_id, client_id)` binding with `Conflict` before mutation; a matching binding, including an identical retry, replaces, and a missing ID inserts (`qid-storage/src/file/client.rs:14-24`). SQL: static `UPDATE ... WHERE id = ? AND realm_id = ? AND client_id = ?` updates only the same binding; a zero-row result is classified after the write with `ensure_same_binding`, so a present mismatch is `Conflict` and a present match (the identical update) succeeds (`qid-storage/src/sql/client.rs:63`, `qid-storage/src/sql/client.rs:69`, `qid-storage/src/sql/client.rs:100`, `qid-storage/src/sql/client.rs:111`). Both refuse a binding change with `Conflict`. The missing-ID difference is intentional and unchanged: the file backend inserts, the SQL backend is a silent no-op. | file `qid-storage/src/file/client.rs:14-24`; sql `qid-storage/src/sql/client.rs:63`, `qid-storage/src/sql/client.rs:69`, `qid-storage/src/sql/client.rs:100`, `qid-storage/src/sql/client.rs:111`, `qid-storage/migrations/20250703000001_clients_require_par.sql:1`; contract `qid-storage/src/ownership.rs:100`, `qid-storage/src/traits.rs:131` |
| `delete_client` (delete) | realm (`realm_id`) | internal client record `id` | none, removal | File: under the exclusive write lock, a missing ID or realm mismatch is a no-op; only a matching `(realm_id, id)` is removed (`qid-storage/src/file/client.rs:65`). SQL: static `DELETE FROM clients WHERE realm_id = ? AND id = ?`; foreign and missing IDs are silent no-ops (`qid-storage/src/sql/client.rs:180`). | file `qid-storage/src/file/client.rs:65`; sql `qid-storage/src/sql/client.rs:180`; trait `qid-storage/src/traits.rs:165` |


Call-site review at commit `24414a5bce345a2fec01acc84595231431390695`:
DCR metadata updates authenticate the management client for the realm/client,
read the record by `(realm_id, client_id)`, preserve its stable ID and client
ID in the replacement, then call `update_client`
(`qid-oauth/src/endpoints/dcr.rs:750-826`). DCR deletion resolves and
reauthenticates the realm, reads by realm/client ID, then calls
`delete_client(realm, id)` (`qid-oauth/src/endpoints/dcr.rs:860-900`). The admin
directory delete authorizes the path realm, reads the matching realm/client,
then calls the same realm+ID delete and audits it
(`qid-admin/src/directory.rs:521-553`). Both stores enforce the delete owner
inside the write; the DCR update also enforces its stable identity binding.
These routes use pre-reads for existing response behavior, but no production
client deletion path writes by ID alone. The documented missing-ID behavior
for `update_client` remains relevant if its pre-read races with deletion.

## credential

Model types: `WebAuthnCredential`, `TotpCredential`. The owner is the user
(`user_id`); the WebAuthn table's primary key is the record `id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:33`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_webauthn_credential` - `WebAuthnCredential` | user (`user_id`) | record `id` | credential data, counter, device name | File: a credential record ID already in any user's list is refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/credential.rs:20`, `qid-storage/src/file/credential.rs:25`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/credential.rs:25`, `qid-storage/src/sql/credential.rs:38`). Both refuse a duplicate record ID, including one presented for another user. | file `qid-storage/src/file/credential.rs:20`, `qid-storage/src/file/credential.rs:25`; sql `qid-storage/src/sql/credential.rs:25`, `qid-storage/src/sql/credential.rs:38` |
| `update_webauthn_credential_counter` - `WebAuthnCredential` | user (`user_id`) | record `id` | counter | File: only the specified user's credential list is inspected and updated under the write lock. SQL: `UPDATE ... WHERE user_id = ? AND id = ?`. Both silently leave the counter unchanged for a wrong owner or unknown ID. | file `qid-storage/src/file/credential.rs:43`, `qid-storage/src/file/credential.rs:46`; sql `qid-storage/src/sql/credential.rs:50` |
| `delete_webauthn_credential` (delete) | user (`user_id`) | record `id` | none, removal | File: only the specified user's list is modified under the write lock. SQL: `DELETE FROM credentials_webauthn WHERE user_id = ? AND id = ?`. Both silently leave credentials unchanged for a wrong owner or unknown ID. | file `qid-storage/src/file/credential.rs:55`; sql `qid-storage/src/sql/credential.rs:102` |
| `store_totp_credential` - `TotpCredential` | user (`user_id`) | record `id` | secret, algorithm, digits, period, `enabled`, `last_used_step` | File: checks the existing record owner under the exclusive write lock before replacing the whole record; SQL: the static `ON CONFLICT(id) DO UPDATE` includes `credentials_totp.user_id = excluded.user_id` and maps a zero-row result to `Conflict`. Both refuse a cross-user ID collision without changing the incumbent; same-owner IDs replace. | file `qid-storage/src/file/credential.rs:64-76`; sql `qid-storage/src/sql/credential.rs:59-78` |
| `consume_totp_step` - `TotpCredential` | user (`user_id`) + record `id`, supplied together as the credential identity | record `id` | `last_used_step` (monotonic) | File: under the write lock, a missing ID, owner mismatch or non-newer step returns `false` without mutation (`qid-storage/src/file/credential.rs:80`, `qid-storage/src/file/credential.rs:83`). SQL: one static atomic update predicates on both `user_id` and `id` plus the monotonic-step condition; the affected-row count decides the answer (`qid-storage/src/sql/credential.rs:91`, `qid-storage/src/sql/credential.rs:99`). Both refuse wrong-owner, unknown and replayed claims. | file `qid-storage/src/file/credential.rs:80`, `qid-storage/src/file/credential.rs:83`; sql `qid-storage/src/sql/credential.rs:91`, `qid-storage/src/sql/credential.rs:99` |

Call-site review at source commit `24414a5bce345a2fec01acc84595231431390695`:
TOTP enrollment checks the browser-session user against the path realm, creates
a server-generated ULID credential ID, and stores the disabled credential;
verification reloads by session user, atomically claims the step with the
credential's user+ID, then stores the enabled snapshot
(`qid-session/src/totp_api.rs:95-150,153-227`). Authentication also checks the
user's path realm, reads the user-owned credential and claims its step through
the same owner-bound operation (`qid-session/src/totp_api.rs:235-315`). These
routes do not accept a TOTP credential ID from the caller; the historical
cross-owner collision behavior was a storage-contract gap, not a demonstrated
production exploit. Same-ID replacement now rejects a mismatched `user_id`
atomically in both backends while preserving same-owner replacement; the shared
cross-backend contract test checks refusal and verifies every incumbent field
remains unchanged (`qid-storage/tests/support/mod.rs`). WebAuthn registration
binds the session to the same user
and realm before storing; authentication updates counters with both user ID and
credential ID. No production caller of `delete_webauthn_credential` was found
(`qid-session/src/api/webauthn.rs:121-170,296-335,457-492`).

## device

Model type: `Device`. Owner: realm and user (`realm_id`, `user_id`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `register_device` - `Device` | realm + user (`realm_id`, `user_id`) | record `id` | posture, `last_seen_at`, `device_name` | File: a second device that carries a taken record ID is refused with `Conflict` under the store's exclusive write lock (`qid-storage/src/file/device.rs:10`, `qid-storage/src/file/device.rs:13`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/device.rs:12`, `qid-storage/src/sql/device.rs:27`). Both refuse with `Conflict`. | file `qid-storage/src/file/device.rs:10`, `qid-storage/src/file/device.rs:13`; sql `qid-storage/src/sql/device.rs:12`, `qid-storage/src/sql/device.rs:27` |
| `update_device_last_seen` - `Device` | realm + user (`realm_id`, `user_id`) | record `id` | `last_seen_at` only | Same-owner updates replace the timestamp. Missing IDs and foreign realm/user bindings succeed without changing the incumbent. File compares the owner and updates under the same exclusive write lock, then saves even on a no-op, preserving its persistence behavior. SQL uses one static `UPDATE ... WHERE id = ? AND realm_id = ? AND user_id = ?`; no row affected is not an error. | file `qid-storage/src/file/device.rs:37`; sql `qid-storage/src/sql/device.rs:48` |

The public heartbeat route is reachable at `PUT /api/v1/:realm/devices/:device_id/heartbeat` (`qid-resource/src/lib.rs:39-40`). It reads by ID, checks that the record realm matches the path, and requires a session for the record's user. It sets `last_seen_at` on that pre-read `Device` and passes it to the owner-bound write (`qid-resource/src/device.rs:79-105`). The qid-agent CLI likewise passes its pre-read `Device` with the requested timestamp (`qid-agent/src/main.rs:134-145`); it is a local command using the configured repository, not a network route. The storage write atomically enforces the expected ID/realm/user binding rather than relying on either caller's pre-read for enforcement. Both HTTP and qid-agent registration generate IDs with `Ulid::new()` and the stores reject duplicate IDs. This is a contract-consistency improvement, not a demonstrated production exploit; no device-delete/replacement path was found in the call-site review.

The shared `assert_device_heartbeat_ownership` contract runs against isolated File and SQLite repositories in `qid-storage/tests/ownership_contract.rs`: same-owner timestamp updates, same-ID foreign realm and foreign user silent no-ops with the incumbent unchanged, and missing-ID silent no-ops.

## fedcm

Model type: `FedCmIdentity`. Owner: realm (`realm_id`); the record is also
readable by `account_id` inside a realm (`qid-storage/src/file/fedcm.rs:25`),
but the table declares no uniqueness on `account_id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:230`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_fedcm_identity` - `FedCmIdentity` | realm (`realm_id`) | record `id` | email, name, given name, picture URL, approved clients | File: a second identity that carries a taken record ID is refused with `Conflict` under the store's exclusive write lock (`qid-storage/src/file/fedcm.rs:10`, `qid-storage/src/file/fedcm.rs:13`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/fedcm.rs:9`, `qid-storage/src/sql/fedcm.rs:22`). Both refuse with `Conflict`. | file `qid-storage/src/file/fedcm.rs:10`, `qid-storage/src/file/fedcm.rs:13`; sql `qid-storage/src/sql/fedcm.rs:9`, `qid-storage/src/sql/fedcm.rs:22` |
| `delete_fedcm_identity` (delete) | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | none, removal | File: the identity is removed by ID and a missing identity is a silent no-op (`qid-storage/src/file/fedcm.rs:33`). SQL: `DELETE FROM fedcm_identities WHERE id = ?` and a missing identity is a silent no-op (`qid-storage/src/sql/fedcm.rs:41`). Both delete by ID only, so an identity of another realm is removed as well. | file `qid-storage/src/file/fedcm.rs:33`; sql `qid-storage/src/sql/fedcm.rs:41` |

Call-site review at commit `ddee7abe39e4`: the FedCM router exposes account listing, identity creation and token generation, but no delete route (`qid-resource/src/lib.rs:70-95`). The creation handler requires FedCM to be enabled and a session bound to the path realm/account, then assigns the identity ID with `Ulid::new()` before storing it (`qid-resource/src/fedcm.rs:82-106`). A workspace call-site search found no production caller of `delete_fedcm_identity`; this ID-only operation is not currently reachable through the product API. Defer a delete-contract change until an authorized deletion path is introduced.

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
| `store_iga_access_request` - `IgaAccessRequestRecord` | tenant (`tenant_id`) | globally unique record `id` | subject, entitlement, reason, status, approval steps, violations, package membership, expiry | File: duplicate IDs return `Conflict` under the exclusive write lock without replacing the incumbent (`qid-storage/src/file/iga.rs:77`, `qid-storage/src/file/iga.rs:78`). SQL: static `ON CONFLICT(id) DO NOTHING`; `ensure_upsert_applied` maps zero affected rows to `Conflict` (`qid-storage/src/sql/iga.rs:91`, `qid-storage/src/sql/iga.rs:107`). Both reject same-tenant and cross-tenant collisions, preserving the lifecycle record. | file `qid-storage/src/file/iga.rs:77`, `qid-storage/src/file/iga.rs:78`; sql `qid-storage/src/sql/iga.rs:91`, `qid-storage/src/sql/iga.rs:107` |
| `update_iga_access_request_status` - `IgaAccessRequestRecord` | tenant (`tenant_id`) | record `id` | status | File: the status is changed only when the record's tenant matches; otherwise a silent no-op (`qid-storage/src/file/iga.rs:110`, `qid-storage/src/file/iga.rs:111`). SQL: `UPDATE ... WHERE tenant_id = ? AND id = ?`; no row affected is not an error (`qid-storage/src/sql/iga.rs:135`). Both are tenant-scoped silent no-ops. | file `qid-storage/src/file/iga.rs:110`; sql `qid-storage/src/sql/iga.rs:135` |
| `store_iga_approval` - `IgaApprovalRecord` | tenant (`tenant_id`) | globally unique record `id` | request, approver, decision, approval time, expiry, reason; immutable evidence | File: duplicate IDs return `Conflict` under the exclusive write lock without replacing the incumbent (`qid-storage/src/file/iga.rs:141`, `qid-storage/src/file/iga.rs:142`). SQL: static `ON CONFLICT(id) DO NOTHING`; `ensure_upsert_applied` maps zero affected rows to `Conflict` (`qid-storage/src/sql/iga.rs:162`, `qid-storage/src/sql/iga.rs:175`). Both reject same-tenant and cross-tenant collisions, preserving the immutable approval. | file `qid-storage/src/file/iga.rs:141`, `qid-storage/src/file/iga.rs:142`; sql `qid-storage/src/sql/iga.rs:162`, `qid-storage/src/sql/iga.rs:175` |
| `store_iga_access_grant` - `IgaAccessGrantRecord` | tenant (`tenant_id`) | globally unique record `id` | request, subject, entitlement, expiry, approval IDs, `revoked` | File: duplicate IDs return `Conflict` under the exclusive write lock without replacing the incumbent (`qid-storage/src/file/iga.rs:176`, `qid-storage/src/file/iga.rs:177`). SQL: static `ON CONFLICT(id) DO NOTHING`; `ensure_upsert_applied` maps zero affected rows to `Conflict` (`qid-storage/src/sql/iga.rs:200`, `qid-storage/src/sql/iga.rs:214`). Both reject same-tenant and cross-tenant collisions; a duplicate store cannot undo revocation. | file `qid-storage/src/file/iga.rs:176`, `qid-storage/src/file/iga.rs:177`; sql `qid-storage/src/sql/iga.rs:200`, `qid-storage/src/sql/iga.rs:214` |
| `revoke_iga_access_grant` - `IgaAccessGrantRecord` | tenant (`tenant_id`) | record `id` | `revoked` | File: the grant is revoked only when its tenant matches, and an unknown grant or a grant of another tenant is a silent no-op (`qid-storage/src/file/iga.rs:233`, `qid-storage/src/file/iga.rs:236`). SQL: `UPDATE iga_access_grants SET revoked = 1 WHERE id = ? AND tenant_id = ?` and no affected row is not an error (`qid-storage/src/sql/iga.rs:352`). Both are tenant-scoped silent no-ops. | file `qid-storage/src/file/iga.rs:236`; sql `qid-storage/src/sql/iga.rs:352` |
| `ensure_iga_access_grants` - `IgaAccessGrantRecord` (batch) | tenant (`tenant_id`) | record `id`; the parent is the access request | grant fields of the missing grants | File: a missing parent request is `BadRequest` (`qid-storage/src/file/iga.rs:489`, `qid-storage/src/file/iga.rs:493`); an incumbent grant ID bound to another `(tenant, request, subject, entitlement)` is `BadRequest` (`qid-storage/src/file/iga.rs:506`, `qid-storage/src/file/iga.rs:512`); an already present grant is a no-op, only missing grants are written (`qid-storage/src/file/iga.rs:504`, `qid-storage/src/file/iga.rs:523`). SQL: the same two refusals inside the transaction, a missing parent (`qid-storage/src/sql/iga.rs:247`, `qid-storage/src/sql/iga.rs:248`) and a foreign binding (`qid-storage/src/sql/iga.rs:271`, `qid-storage/src/sql/iga.rs:286`). Both refuse the same cases with `BadRequest`. | file `qid-storage/src/file/iga.rs:506`; sql `qid-storage/src/sql/iga.rs:271`, `qid-storage/src/sql/iga.rs:286` |
| `store_iga_jit_privilege_grant` - `IgaJitPrivilegeGrantRecord` | tenant (`tenant_id`) | globally unique record `id` | `revoked`, `expires_at`, constraints | File: duplicate IDs return `Conflict` under the exclusive write lock without replacing the incumbent (`qid-storage/src/file/iga.rs:248`, `qid-storage/src/file/iga.rs:255`). SQL: static `ON CONFLICT(id) DO NOTHING`; `ensure_upsert_applied` maps zero affected rows to `Conflict` (`qid-storage/src/sql/iga.rs:367`, `qid-storage/src/sql/iga.rs:383`). Both reject same-tenant and cross-tenant collisions and preserve the incumbent's revoked state. | file `qid-storage/src/file/iga.rs:248`, `qid-storage/src/file/iga.rs:255`; sql `qid-storage/src/sql/iga.rs:367`, `qid-storage/src/sql/iga.rs:383` |
| `revoke_iga_jit_privilege_grant` - `IgaJitPrivilegeGrantRecord` | tenant (`tenant_id`) | record `id` | `revoked` | File: the grant is revoked only when its tenant matches, and an unknown grant or a grant of another tenant is a silent no-op (`qid-storage/src/file/iga.rs:279`, `qid-storage/src/file/iga.rs:282`). SQL: `UPDATE iga_jit_privilege_grants SET revoked = 1 WHERE id = ? AND tenant_id = ?` and no affected row is not an error (`qid-storage/src/sql/iga.rs:413`). Both are tenant-scoped silent no-ops. | file `qid-storage/src/file/iga.rs:282`; sql `qid-storage/src/sql/iga.rs:413` |
| `store_iga_access_review_campaign` - `IgaAccessReviewCampaignRecord` | tenant (`tenant_id`) | globally unique record `id` | status, `due_at` | File: duplicate IDs return `Conflict` under the exclusive write lock without replacing the incumbent (`qid-storage/src/file/iga.rs:286`, `qid-storage/src/file/iga.rs:292`). SQL: static `ON CONFLICT(id) DO NOTHING`; `ensure_upsert_applied` maps zero affected rows to `Conflict` (`qid-storage/src/sql/iga.rs:433`, `qid-storage/src/sql/iga.rs:445`). Both reject same-tenant and cross-tenant collisions, preserving the closed incumbent. | file `qid-storage/src/file/iga.rs:292`; sql `qid-storage/src/sql/iga.rs:433`, `qid-storage/src/sql/iga.rs:445` |
| `close_iga_access_review_campaign` - `IgaAccessReviewCampaignRecord` | tenant (`tenant_id`) | record `id` | `status` | File: the campaign is closed only when its tenant matches, and an unknown campaign or a campaign of another tenant is `Ok(false)` (`qid-storage/src/file/iga.rs:338`, `qid-storage/src/file/iga.rs:342`, `qid-storage/src/file/iga.rs:347`). SQL: `UPDATE ... WHERE tenant_id = ? AND id = ?` and the affected-row count answers the boolean (`qid-storage/src/sql/iga.rs:477`, `qid-storage/src/sql/iga.rs:484`). Both are tenant-scoped and answer `false` for an unknown campaign. | file `qid-storage/src/file/iga.rs:347`; sql `qid-storage/src/sql/iga.rs:484` |
| `store_iga_access_review_decision` - `IgaAccessReviewDecisionRecord` | tenant (`tenant_id`) | globally unique record `id` | none; review decisions are permanent records | File: duplicate IDs are refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/iga.rs:359`, `qid-storage/src/file/iga.rs:360`). SQL: `ON CONFLICT(id) DO NOTHING` plus `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/iga.rs:493`, `qid-storage/src/sql/iga.rs:506`). Both same-tenant and cross-tenant collisions preserve the incumbent decision. | file `qid-storage/src/file/iga.rs:359`, `qid-storage/src/file/iga.rs:360`; sql `qid-storage/src/sql/iga.rs:493`, `qid-storage/src/sql/iga.rs:506`; schema `qid-storage/migrations/20250618000020_iga_access_review_decisions.sql:2` |
| `store_iga_certification` - `IgaCertificationRecord` | tenant (`tenant_id`) | globally unique record `id` | none; certifications are permanent evidence and decision records | File: duplicate IDs are refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/iga.rs:402`, `qid-storage/src/file/iga.rs:403`). SQL: `ON CONFLICT(id) DO NOTHING` plus `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/iga.rs:537`, `qid-storage/src/sql/iga.rs:553`). Both same-tenant and cross-tenant collisions preserve the incumbent certification. | file `qid-storage/src/file/iga.rs:402`, `qid-storage/src/file/iga.rs:403`; sql `qid-storage/src/sql/iga.rs:537`, `qid-storage/src/sql/iga.rs:553`; schema `qid-storage/migrations/20250618000023_iga_certifications.sql:2` |
| `store_iga_finding` - `IgaFindingRecord` | tenant (`tenant_id`) | globally unique record `id` | `resolved` through the separate `resolve_iga_finding` transition | File: duplicate IDs are refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/iga.rs:441`, `qid-storage/src/file/iga.rs:442`). SQL: `ON CONFLICT(id) DO NOTHING` plus `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/iga.rs:588`, `qid-storage/src/sql/iga.rs:601`). A duplicate store cannot replace evidence or reset a resolved finding. | file `qid-storage/src/file/iga.rs:441`, `qid-storage/src/file/iga.rs:442`; sql `qid-storage/src/sql/iga.rs:588`, `qid-storage/src/sql/iga.rs:601`; schema `qid-storage/migrations/20250618000024_iga_findings.sql:2` |
| `resolve_iga_finding` - `IgaFindingRecord` | tenant (`tenant_id`) | record `id` | `resolved` | File: the flag is set only when the record's tenant matches, otherwise a silent no-op (`qid-storage/src/file/iga.rs:481`, `qid-storage/src/file/iga.rs:484`). SQL: `UPDATE iga_findings SET resolved = 1 WHERE tenant_id = ? AND id = ?`; no row affected is not an error (`qid-storage/src/sql/iga.rs:642`, `qid-storage/src/sql/iga.rs:643`). Both are tenant-scoped silent no-ops and the transition is monotonic `resolved=false -> true`. | file `qid-storage/src/file/iga.rs:481`; sql `qid-storage/src/sql/iga.rs:642` |
| `delete_iga_entitlement` (delete) | tenant (`tenant_id`) | `(tenant_id, id)` | none, removal | File: the tenant-scoped key is removed; a missing record is a silent no-op (`qid-storage/src/file/iga.rs:34`). SQL: `DELETE ... WHERE tenant_id = ? AND id = ?`; a missing record is a silent no-op (`qid-storage/src/sql/iga.rs:37`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/iga.rs:34`; sql `qid-storage/src/sql/iga.rs:37` |
| `delete_iga_access_package` (delete) | tenant (`tenant_id`) | `(tenant_id, id)` | none, removal | File: the tenant-scoped key is removed (`qid-storage/src/file/iga.rs:69`). SQL: `DELETE ... WHERE tenant_id = ? AND id = ?` (`qid-storage/src/sql/iga.rs:79`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/iga.rs:69`; sql `qid-storage/src/sql/iga.rs:79` |

## oidc_continuation

`OidcAuthorizationContinuation` stores protocol context only, never
authentication or authorization-code authority. Ownership is exact realm + user
+ client; IDs are globally unique. The record carries a nonempty JSON-object
context bounded to 64 KiB and only a SHA-256 browser-binding verifier. Creation
requires trusted server time. Consumption is one-use and requires every owner key,
the browser binding, and `created_at <= now < expires_at`; cleanup is bounded to
1..=1000 expired rows.

| Method - record type | Owner key | Identity key | Mutable fields | Transition rule | Sources |
| --- | --- | --- | --- | --- | --- |
| `create_oidc_continuation` - `OidcAuthorizationContinuation` | realm + user + client | global continuation ID | none | Requires `created_at == now`; any existing ID is `Conflict`. | file `qid-storage/src/file/oidc_continuation.rs:57`; sql `qid-storage/src/sql/oidc_continuation.rs:8`; schema `qid-storage/migrations/20261025000001_oidc_continuations.sql:4` |
| `consume_oidc_continuation` - `OidcAuthorizationContinuation` | realm + user + client | ID + browser-binding verifier | one `consumed_at` | Atomic one-use transition; wrong owner/binding, replay, not-yet-valid or expired records return none. | file `qid-storage/src/file/oidc_continuation.rs:83`; sql `qid-storage/src/sql/oidc_continuation.rs:27`; schema `qid-storage/migrations/20261025000001_oidc_continuations.sql:12` |
| `cleanup_expired_oidc_continuations` - expired protocol context | global maintenance | ID + expiry | removal | Removes only expired rows, at most 1000 per call. | file `qid-storage/src/file/oidc_continuation.rs:125`; sql `qid-storage/src/sql/oidc_continuation.rs:63`; schema `qid-storage/migrations/20261025000001_oidc_continuations.sql:17` |

## policy

Model type: `PolicyBundle`. Owner: realm (`realm_id`); the table also declares
`UNIQUE(realm_id, name)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:263`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_policy_bundle` - `PolicyBundle` | realm (`realm_id`) | record `id` and `(realm_id, name)` | name, `source_hash`, `compiled_json`, version, `active` | File: `insert_new` under the exclusive write lock refuses a taken record ID or a taken `(realm, name)` with `Conflict` and leaves the incumbent unchanged (`qid-storage/src/file/policy.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:12`). SQL: `INSERT ... ON CONFLICT DO NOTHING` refuses either taken key atomically and `ensure_upsert_applied` turns the zero-row result into `Conflict` (`qid-storage/src/sql/policy.rs:11`, `qid-storage/src/sql/policy.rs:24`). Both refuse; same name in another realm and a distinct name in the same realm are allowed. | file `qid-storage/src/file/policy.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:12`; sql `qid-storage/src/sql/policy.rs:11`, `qid-storage/src/sql/policy.rs:24`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:263` |
| `delete_policy_bundle` (delete) | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | none, removal | File: the bundle is removed by ID and a missing bundle is a silent no-op (`qid-storage/src/file/policy.rs:41`). SQL: `DELETE FROM policy_bundles WHERE id = ?` and a missing bundle is a silent no-op (`qid-storage/src/sql/policy.rs:48`). Both delete by ID only, so a bundle of another realm is removed as well. | file `qid-storage/src/file/policy.rs:41`; sql `qid-storage/src/sql/policy.rs:48` |

Call-site review at commit `ddee7abe39e4`: configured policy bundles are read and created per realm during qidd initialization (`qidd/src/main.rs:1140-1166`), and the admin dashboard lists bundles (`qid-admin/src/policy.rs:200`). A workspace call-site search found no production caller of `delete_policy_bundle`; its only non-storage call is the PEP decision unit test (`qid-proxy/src/pep_decision/tests.rs:1099`). The ID-only delete is therefore not an in-workspace production deletion path; defer a realm-bound delete change until product code exposes authorized deletion.

## push

Model: `PushAuthenticatorRecord` is the single persisted lifecycle row for one
registration/authenticator ID; `PushLoginChallenge` is a separate one-use login
challenge. Owners are exact `realm_id` + `user_id`; IDs are immutable and never
upserted. Storage does not verify signatures or deliver notifications. The service
must perform recent account-bound reauthentication, validate the candidate key,
deliver fresh nonces, and verify domain-separated signatures over every immutable
claim before passing a successful transition. Delivery acceptance is never proof.

A pending registration is never login authority. Successful proof atomically
replaces its pending payload with an enrolled authenticator payload in the same row,
removing the registration nonce verifier, expiry and attempt state. The row's global
ID remains reserved after enrollment and one-way revocation. `get_push_registration`
returns pending rows only (including expired/exhausted rows); authenticator get/list
return enrolled rows only (including revoked tombstones). Every read is owner-bound.

A login challenge's `id` is also its unique login-transaction ID; one row is the
authoritative password-login transaction. The service selects one current
authenticator before issuing a challenge and must not create independently
redeemable per-device rows for one password success. Redemption atomically checks
the current authenticator, approval, exclusive expiry, browser-binding verifier and
one-use state. Invalid signatures count against the fixed attempt cap but never
approve. All timestamps are server epoch seconds. Only lowercase hex SHA-256
nonce/browser verifiers are persisted. Debug redacts destinations, key contents
and verifier values; IDs and lifecycle state are not secrets.

File mutations hold the exclusive lock through immediate persistence and roll back
on write failure. SQL uses static owner-checked statements: registration activation
and revocation update the same primary-key row; login mutations lock the enrolled
authenticator before the challenge, serializing decisions and redemption with
revocation. User/realm deletion removes owned push state in both backends.

| Method - record type | Owner key | Identity key | Mutable fields | Transition rule | Sources |
| --- | --- | --- | --- | --- | --- |
| `try_issue_push_registration` - pending lifecycle | realm + user | global registration/authenticator ID | none | Requires a current account and explicit validated issuance budget; any existing ID is `Conflict`. | file `qid-storage/src/file/push.rs:297`; sql `qid-storage/src/sql/push.rs:296` |
| `get_push_registration` - pending lifecycle | realm + user | ID | none | Returns pending only; expired/exhausted state remains non-authoritative. | file `qid-storage/src/file/push.rs:90`; sql `qid-storage/src/sql/push.rs:142` |
| `attempt_push_registration` - lifecycle row | realm + user | ID + candidate destination/key + nonce verifier + expiry/cap | bounded attempts; pending-to-enrolled replacement | Exact immutable snapshot required; only verified, unexpired proof enrolls. | file `qid-storage/src/file/push.rs:109`; sql `qid-storage/src/sql/push.rs:156` |
| `get_push_authenticator` / `list_push_authenticators` - enrolled rows | realm + user | global authenticator ID | none | Enrolled rows only, including revoked tombstones; pending rows return none. | file `qid-storage/src/file/push.rs:137`, `qid-storage/src/file/push.rs:155`; sql `qid-storage/src/sql/push.rs:177`, `qid-storage/src/sql/push.rs:188` |
| `revoke_push_authenticator` - enrolled row | realm + user | global authenticator ID | one `revoked_at` | One-way revocation; missing, foreign, pending or already revoked rows return false. | file `qid-storage/src/file/push.rs:173`; sql `qid-storage/src/sql/push.rs:203` |
| `try_issue_push_login` / `get_push_login` - `PushLoginChallenge` | realm + user | global challenge/transaction ID + authenticator + purpose + verifiers + expiry/cap | none | Requires the current authenticator and explicit validated issuance budget; duplicate IDs are `Conflict`. | file `qid-storage/src/file/push.rs:346`, `qid-storage/src/file/push.rs:202`; sql `qid-storage/src/sql/push.rs:363`, `qid-storage/src/sql/push.rs:222` |
| `attempt_push_login` - `PushLoginChallenge` | realm + user | all immutable challenge bindings | bounded attempts; one approve/deny decision | Rechecks current registration; bad signatures count, one verified decision is terminal. | file `qid-storage/src/file/push.rs:221`; sql `qid-storage/src/sql/push.rs:233` |
| `redeem_push_login` - `PushLoginChallenge` | realm + user | immutable bindings + browser verifier | one `consumed_at` | Rechecks registration, approval, expiry and browser binding atomically; one winner only. | file `qid-storage/src/file/push.rs:254`; sql `qid-storage/src/sql/push.rs:263` |
| `try_resend_push_login` - `PushLoginChallenge` | realm + user + purpose quota, current authenticator | exact expected challenge/nonce/browser bindings | fresh nonce verifier; append-only bounded send history | Locks quota then authenticator then challenge, preserving current attempts and original lifetime. Initial/resend admissions share one rolling quota; provider failure does not refund it. | file `qid-storage/src/file/push.rs`; sql `qid-storage/src/sql/push.rs` |
| `cleanup_expired_push_records` - expired issuance | global maintenance | ID + issuance + expiry + pending state/snapshot | removal only | At most 1000 rows per call; strictly retain the maximum quota window and all enrolled/revoked authenticators. | file `qid-storage/src/file/push.rs`; sql `qid-storage/src/sql/push.rs` |

Push issuance has no unrestricted creation entry point. Admission `issued_at` is
sampled from trusted server time **after** the storage
and owner/purpose admission locks are held. It is persisted separately from the
challenge lifecycle (`created_at`, `expires_at`), which must satisfy
`created_at <= issued_at < expires_at`. Creation supplied by the service/device
is never authority for quota accounting. Both `try_issue_*` methods and login resend
require a positive maximum and a window of 1..=86400 seconds, counting every
issuance in that owner/purpose window regardless of its subsequent lifecycle.
Cleanup accepts only 1..=1000 rows per call and retains registration issuance
and immutable login expiry at the exact 86400-second retention boundary. SQL expiry/state metadata is indexed, mirrors
JSON on every read and transition, and is cleared for enrolled/revoked
authenticators. Cleanup selects only expired eligible rows with a bounded LIMIT;
conditional deletes recheck pending state, expiry, issuance and the selected JSON
under the database row lock, so concurrent activation cannot delete an enrolled
registration. PostgreSQL cleanup also takes the same owner/purpose admission
lock before deletion, so it cannot remove quota history between admission-time
sampling and counting. SQLite selection/deletion remains under BEGIN IMMEDIATE.
File cleanup scans but selects only up to `limit` deterministic oldest candidates
with a bounded heap (O(N log limit) work, O(limit) selection memory). It retains
only removed records for rollback, at most 1000, never a full-store clone.
Serialization for durable file persistence still covers the full store.


## realm

Model type: the `realms` row (no model struct in `qid-core`). Owner: the
tenant (`tenant_id`); the table declares `UNIQUE(issuer)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:6`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_realm` - `realms` row | tenant (`tenant_id`) | globally unique realm `id` and `issuer` | issuer, `display_name` | File: duplicate IDs in either realm map and duplicate issuers return `Conflict` before either map is changed (`qid-storage/src/file/realm.rs:15`, `qid-storage/src/file/realm.rs:23`). SQL: static `ON CONFLICT DO NOTHING`; `ensure_upsert_applied` maps a duplicate ID or issuer to `Conflict` (`qid-storage/src/sql/realm.rs:15`, `qid-storage/src/sql/realm.rs:24`). Both preserve the incumbent realm and tenant binding. | file `qid-storage/src/file/realm.rs:23`; sql `qid-storage/src/sql/realm.rs:24`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:6` |
| `delete_realm` (delete) | realm (`realm_id`) | realm `id` | none, removal of the realm and the live state it owns | File: `remove_realm` drops the realm's users and their authentication state, then the realm-scoped clients, service accounts, policy bundles, credential statuses, PAR requests, SCIM, FedCM, workload, SaaS and SSF records, and the realm's issuer and tenant bindings (`qid-storage/src/file/realm.rs:99`, `qid-storage/src/file/realm.rs:105`, `qid-storage/src/file/realm.rs:136`); an unknown realm is a silent no-op. SQL: the realm-scoped rows are deleted in one transaction and the realm row is deleted last (`qid-storage/src/sql/realm.rs:56`, `qid-storage/src/sql/realm.rs:93`); an unknown realm is a silent no-op. Both keep the audit, retention and SIEM history. | file `qid-storage/src/file/realm.rs:105`; sql `qid-storage/src/sql/realm.rs:93` |

## rebac

Model type: `RelationshipTuple`. The tuple has no realm or tenant column
(`qid-core/src/models/rebac.rs:10`); the scope is the `namespace`, so this is
an internal record that is not tenant-scoped. The identity is the six-part
tuple, which is the SQL primary key
(`qid-storage/migrations/20250622000005_relationship_tuples.sql:9`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_relationship_tuple` - `RelationshipTuple` | namespace only; not realm- or tenant-scoped (no owner column in the model) | `(namespace, object_id, relation, subject_namespace, subject_id, subject_relation)` | `created_at_epoch_seconds` | File: checks the six-field identity under the exclusive write lock and returns `Conflict` without changing the incumbent (`qid-storage/src/file/rebac.rs:18`). SQL: static `ON CONFLICT` on the same six columns with `DO NOTHING`; `ensure_upsert_applied` returns `Conflict` for a duplicate (`qid-storage/src/sql/rebac.rs:9`, `qid-storage/src/sql/rebac.rs:21`). `created_at_epoch_seconds` is not identity, so a duplicate with another timestamp leaves the original tuple unchanged. Both refuse. | file `qid-storage/src/file/rebac.rs:18`; sql `qid-storage/src/sql/rebac.rs:24`; schema `qid-storage/migrations/20250622000005_relationship_tuples.sql:9` |
| `delete_relationship_tuple` (delete) | namespace only; not realm- or tenant-scoped (no owner column in the model) | the six-part tuple | none, removal | File: every stored tuple that matches the six parts is dropped, and a tuple that is not stored is a silent no-op (`qid-storage/src/file/rebac.rs:36`). SQL: `DELETE ... WHERE` the six parts match, and a tuple that is not stored is a silent no-op (`qid-storage/src/sql/rebac.rs:28`). Both remove by the whole identity. | file `qid-storage/src/file/rebac.rs:36`; sql `qid-storage/src/sql/rebac.rs:28` |

## saas

Model types: `CustomDomain`, `CiamBrand`, `AppCatalogEntry`,
`MarketplaceConnector`, `UsageBillingEvent`, `ComplianceEvidencePack`,
`DelegatedTenantAdmin`. The owner is the tenant (`tenant_id`); several writes
also require the referenced realm to belong to that tenant.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `store_custom_domain` - `CustomDomain` | tenant (`tenant_id`); the realm must belong to it | record `id`; the schema also makes `hostname` unique (`qid-storage/migrations/20250618000016_saas_models.sql:5`) | hostname, certificate ref, verification fields, dates | File: another domain with the same hostname (case-insensitive) is refused with `Storage` (`qid-storage/src/file/saas.rs:68`, `qid-storage/src/file/saas.rs:71`); an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:75`); a realm of another tenant is `Storage` (`qid-storage/src/file/saas.rs:63`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:50`, `qid-storage/src/sql/saas.rs:51`, `qid-storage/src/sql/saas.rs:68`); a duplicate hostname is a unique violation surfaced as `Storage` (`qid-storage/src/sql/row.rs:10`); a realm of another tenant is `Storage` (`qid-storage/src/sql/saas.rs:44`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:75`; sql `qid-storage/src/sql/saas.rs:51`, `qid-storage/src/sql/saas.rs:68` |
| `store_ciam_brand` - `CiamBrand` | tenant (`tenant_id`); the realm must belong to it | record `id` | display name, colours, logo and policy URIs, terms version, `active` | File: an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:128`); a realm of another tenant is `Storage` (`qid-storage/src/file/saas.rs:124`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:113`, `qid-storage/src/sql/saas.rs:114`, `qid-storage/src/sql/saas.rs:129`); a realm of another tenant is `Storage` (`qid-storage/src/sql/saas.rs:107`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:128`; sql `qid-storage/src/sql/saas.rs:114`, `qid-storage/src/sql/saas.rs:129` |
| `delete_ciam_brand` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: the brand is removed only when its tenant matches, and a missing brand or a brand of another tenant is a silent no-op (`qid-storage/src/file/saas.rs:158`, `qid-storage/src/file/saas.rs:160`). SQL: `DELETE FROM ciam_brands WHERE id = ? AND tenant_id = ?` and a missing brand is a silent no-op (`qid-storage/src/sql/saas.rs:145`). Both are tenant-scoped. | file `qid-storage/src/file/saas.rs:160`; sql `qid-storage/src/sql/saas.rs:145` |
| `store_app_catalog_entry` - `AppCatalogEntry` | tenant (`tenant_id`); the realm must belong to it, and the referenced client and connector must exist | record `id` | display name, category, OIDC client ID, SAML entity ID, SCIM flag, connector ID | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:216`, `qid-storage/src/file/saas.rs:217`); a foreign realm, a missing client or a connector of another tenant are `Storage` (`qid-storage/src/file/saas.rs:174`, `qid-storage/src/file/saas.rs:184`, `qid-storage/src/file/saas.rs:196`). SQL: plain `INSERT` whose unique violation is mapped to `Conflict` (`qid-storage/src/sql/saas.rs:229`, `qid-storage/src/sql/saas.rs:243`); the same reference checks produce `Storage` (`qid-storage/src/sql/saas.rs:168`, `qid-storage/src/sql/saas.rs:181`, `qid-storage/src/sql/saas.rs:195`). Both refuse a duplicate ID with `Conflict`. | file `qid-storage/src/file/saas.rs:216`; sql `qid-storage/src/sql/saas.rs:243` |
| `delete_app_catalog_entry` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: the entry is removed only when its tenant matches, and a missing entry or an entry of another tenant is a silent no-op (`qid-storage/src/file/saas.rs:245`, `qid-storage/src/file/saas.rs:247`). SQL: `DELETE FROM app_catalog_entries WHERE id = ? AND tenant_id = ?` and a missing entry is a silent no-op (`qid-storage/src/sql/saas.rs:264`). Both are tenant-scoped. | file `qid-storage/src/file/saas.rs:247`; sql `qid-storage/src/sql/saas.rs:264` |
| `store_marketplace_connector` - `MarketplaceConnector` | tenant (`tenant_id`) | record `id` | provider, connector type, config, `enabled` | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:256`, `qid-storage/src/file/saas.rs:257`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:276`, `qid-storage/src/sql/saas.rs:287`). Both refuse with `Conflict`. | file `qid-storage/src/file/saas.rs:256`; sql `qid-storage/src/sql/saas.rs:276`, `qid-storage/src/sql/saas.rs:287` |
| `store_usage_billing_event` - `UsageBillingEvent` | tenant (`tenant_id`) | record `id`; the schema also makes `(tenant_id, idempotency_key)` unique (`qid-storage/migrations/20250618000016_saas_models.sql:47`) | meter, quantity, `occurred_at`, dimensions | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:306`, `qid-storage/src/file/saas.rs:307`); a repeated idempotency key in the tenant is `Storage` (`qid-storage/src/file/saas.rs:311`, `qid-storage/src/file/saas.rs:314`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:333`, `qid-storage/src/sql/saas.rs:347`); a repeated idempotency key is a unique violation surfaced as `Storage` (`qid-storage/src/sql/row.rs:10`). Both refuse a duplicate ID with `Conflict` and a repeated key with `Storage`. | file `qid-storage/src/file/saas.rs:306`; sql `qid-storage/src/sql/saas.rs:333`, `qid-storage/src/sql/saas.rs:347` |
| `store_compliance_evidence_pack` - `ComplianceEvidencePack` | tenant (`tenant_id`) | record `id` | period, controls, object URI, sha256 | File: an existing record ID is refused with `Conflict` (`qid-storage/src/file/saas.rs:349`, `qid-storage/src/file/saas.rs:350`). SQL: `ON CONFLICT(id) DO NOTHING` and `rows_affected() == 0` is turned into `Conflict` (`qid-storage/src/sql/saas.rs:370`, `qid-storage/src/sql/saas.rs:387`). Both refuse with `Conflict`. | file `qid-storage/src/file/saas.rs:349`; sql `qid-storage/src/sql/saas.rs:370`, `qid-storage/src/sql/saas.rs:387` |
| `store_delegated_tenant_admin` - `DelegatedTenantAdmin` | tenant (`tenant_id`); every allowed realm must belong to it | record `id` | subject, roles, allowed realm IDs, granted by, `expires_at`, `revoked` | File: an ID already held by another tenant is refused with `Conflict` (`qid-storage/src/file/saas.rs:401`); an allowed realm of another tenant or a missing realm is `BadRequest` (`qid-storage/src/file/saas.rs:387`, `qid-storage/src/file/saas.rs:393`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the tenant matches, so a foreign tenant updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/saas.rs:429`, `qid-storage/src/sql/saas.rs:430`); a realm of another tenant or a missing realm is `BadRequest` (`qid-storage/src/sql/saas.rs:421`, `qid-storage/src/sql/saas.rs:427`). Both refuse a foreign tenant with `Conflict`. | file `qid-storage/src/file/saas.rs:401`; sql `qid-storage/src/sql/saas.rs:430` |
| `revoke_delegated_tenant_admin` - `DelegatedTenantAdmin` | tenant (`tenant_id`) | record `id` | `revoked` | File: an unknown ID or an ID of another tenant is `NotFound` (`qid-storage/src/file/saas.rs:441`). SQL: `UPDATE delegated_tenant_admins SET revoked = 1 WHERE tenant_id = ? AND id = ?` and no affected row is `NotFound` (`qid-storage/src/sql/saas.rs:465`, `qid-storage/src/sql/saas.rs:472`). Both agree. | file `qid-storage/src/file/saas.rs:441`; sql `qid-storage/src/sql/saas.rs:472` |
| `delete_custom_domain` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: the record is removed when its tenant matches (`qid-storage/src/file/saas.rs:109`). SQL: `DELETE ... WHERE id = ? AND tenant_id = ?` (`qid-storage/src/sql/saas.rs:84`). Both refuse to delete another tenant's record. | file `qid-storage/src/file/saas.rs:109`; sql `qid-storage/src/sql/saas.rs:84` |
| `delete_marketplace_connector` (delete) | tenant (`tenant_id`) | record `id` | none, removal | File: a connector still referenced by a catalog entry of the tenant is `Storage`; otherwise the record is removed when its tenant matches (`qid-storage/src/file/saas.rs:285`, `qid-storage/src/file/saas.rs:288`, `qid-storage/src/file/saas.rs:295`). SQL: the same reference check is `Storage` (`qid-storage/src/sql/saas.rs:319`) and the delete is tenant-scoped (`qid-storage/src/sql/saas.rs:321`). Both behave the same. | file `qid-storage/src/file/saas.rs:288`; sql `qid-storage/src/sql/saas.rs:319`, `qid-storage/src/sql/saas.rs:321` |

## scim

Inbound user/group PUT and PATCH, and user soft-delete, carry the realm from the
initial visibility check into `mutate_scim_user` / `mutate_scim_group`, including
requests without `If-Match`. The callback checks that realm under File's exclusive
lock or SQL's row transaction before transforming the current row. A missing or
cross-realm replacement returns 404 for unconditional writes; conditional writes
retain their ETag/realm checks and 412 result. Bulk writes with a realm context
carry that validated context realm into the same callback. Hard deletes retain
the existing realm-bound atomic deletion and idempotent no-op semantics.


Model types: `ScimUser`, `ScimGroup`, `ScimDeviceRecord`,
`ScimEventSubscriptionRecord`. Owner: realm (`realm_id`). The tables also
declare `UNIQUE(realm_id, user_name)` and `UNIQUE(realm_id, display_name)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:217`,
`qid-storage/migrations/20250101000001_initial_schema.sql:227`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `apply_hr_batch` - `HrBatch` / `HrReceipt` | realm + provider (`realm_id`, `provider_id`) ordering domain; users remain realm-scoped | receipt pair; positive contiguous sequence; expected user identities are immutable | next sequence, request digest, non-PII counters, and full planned HR user replacements | Both: same latest sequence/digest replays without user/receipt writes; different/gap/stale sequence conflicts. Revalidate expected targets, ambiguity and names under backend serialization; all changes and receipt advance commit together or none do. File persists a candidate before publishing, even in interval mode; SQL uses one transaction with writer serialization and a guarded receipt update. Uncertain persistence/commit errors require identical retry, not a rollback claim. | `qid-storage/src/hr.rs:79`; file `qid-storage/src/file/hr.rs:35`; SQL `qid-storage/src/sql/hr.rs:41`, `qid-storage/src/sql/hr.rs:84` |
| `create_scim_user` - `ScimUser` | realm (`realm_id`) | record `id`; the schema also names a user by `(realm_id, user_name)` | external ID, user name, name, emails, enterprise fields, provider, `active`, `deprovisioned_at` | File: `create_scim_user` checks both keys under the exclusive lock through the typed `insert_new` `ScimUser` identity projection, so a duplicate ID or a duplicate `(realm, user_name)` is refused with `Conflict` and the incumbent stays as it is (`qid-storage/src/file/scim.rs:8`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:36`). SQL: static `INSERT`, so the failed insert changes no row; only a unique violation becomes `Conflict`, every other storage error is preserved (`qid-storage/src/sql/scim.rs:68`, `qid-storage/src/sql/scim.rs:91`). Both agree; the same user name in another realm succeeds. | file `qid-storage/src/file/scim.rs:8`; sql `qid-storage/src/sql/scim.rs:91` |
| `update_scim_user` - `ScimUser` | realm (`realm_id`) in the record | record `id` and `realm_id` | all other fields in the replacement | Both delegate to `mutate_scim_user`: replace only an existing row under the File write lock or SQL row transaction; a different realm is rejected without changing the incumbent, and a missing row is a successful no-op. | file `qid-storage/src/file/scim.rs`; sql `qid-storage/src/sql/scim.rs` |
| `mutate_scim_user` - `ScimUser` | realm (`realm_id`) in the record; the write is not realm-filtered | record `id` | the fields the mutation's replacement carries | File: `mutate_resource` reads the record under the write lock, so an unknown ID is `Ok(None)`, a rejected mutation is `Ok(None)`, and a replacement that changes the ID or the realm is `BadRequest` (`qid-storage/src/file/scim.rs:236`, `qid-storage/src/file/scim.rs:240`, `qid-storage/src/file/scim.rs:243`). SQL: the same three answers (`qid-storage/src/sql/scim.rs:153`, `qid-storage/src/sql/scim.rs:158`, `qid-storage/src/sql/scim.rs:161`). Both refuse to change the resource identity. | file `qid-storage/src/file/scim.rs:243`; sql `qid-storage/src/sql/scim.rs:161` |
| `delete_scim_user` (delete) | optional expected realm (`realm_id`) | record `id` | none, removal | Both delegate to the atomic mutation: a supplied realm must match the incumbent, otherwise no row is removed. No realm permits unrestricted deletion. Missing and mismatched rows return `None`; a successful deletion returns the removed row. File checks under its exclusive lock; SQL checks under its row transaction. | file `qid-storage/src/file/scim.rs`; sql `qid-storage/src/sql/scim.rs` |
| `create_scim_group` - `ScimGroup` | realm (`realm_id`) | record `id`; the schema also names a group by `(realm_id, display_name)` | display name, members | File: `create_scim_group` checks both keys under the exclusive lock through the typed `insert_new` `ScimGroup` identity projection, so a duplicate ID or a duplicate `(realm, display_name)` is refused with `Conflict` and the incumbent stays as it is (`qid-storage/src/file/scim.rs:72`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:47`). SQL: static `INSERT`, so the failed insert changes no row; only a unique violation becomes `Conflict`, every other storage error is preserved (`qid-storage/src/sql/scim.rs:207`, `qid-storage/src/sql/scim.rs:220`). Both agree; the same display name in another realm succeeds. | file `qid-storage/src/file/scim.rs:72`; sql `qid-storage/src/sql/scim.rs:220` |
| `update_scim_group` - `ScimGroup` | realm (`realm_id`) | record `id` | display name, members | Both delegate to `mutate_scim_group`: an existing group is replaced only if ID and realm remain unchanged; a foreign realm returns `BadRequest` without changing the incumbent, and an absent ID is a silent no-op. File checks under the exclusive store lock; SQL checks under its row transaction. Same-owner replacement retains display name and members. | file `qid-storage/src/file/scim.rs`; sql `qid-storage/src/sql/scim.rs` |
| `mutate_scim_group` - `ScimGroup` | realm (`realm_id`) in the record | record `id` | display name, members | File reads under the write lock; SQL locks the row in a transaction. Both return `Ok(None)` for an unknown ID or rejected mutation and `BadRequest` if a replacement changes ID or realm. | file `qid-storage/src/file/scim.rs`; sql `qid-storage/src/sql/scim.rs` |
| `delete_scim_group` (delete) | optional expected realm (`realm_id`) | record `id` | none, removal | Both delegate to the atomic mutation: a supplied realm must match the incumbent, otherwise no row is removed. No realm permits unrestricted deletion. Missing and mismatched rows return `None`; a successful deletion returns the removed row. File checks under its exclusive lock; SQL checks under its row transaction. | file `qid-storage/src/file/scim.rs`; sql `qid-storage/src/sql/scim.rs` |
| `upsert_scim_device` - `ScimDeviceRecord` | realm (`realm_id`) | record `id` | display name, manufacturer, model, OS, OS version, `last_seen` | File: an ID already bound to another realm is refused with `Conflict` under the write lock (`qid-storage/src/file/scim.rs:132`); the same realm overwrites (`qid-storage/src/file/scim.rs:140`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm matches, so a foreign realm updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/scim.rs:301`, `qid-storage/src/sql/scim.rs:302`, `qid-storage/src/sql/scim.rs:315`). Both refuse a foreign realm with `Conflict`. | file `qid-storage/src/file/scim.rs:132`; sql `qid-storage/src/sql/scim.rs:302`, `qid-storage/src/sql/scim.rs:315` |
| `upsert_scim_event_subscription` - `ScimEventSubscriptionRecord` | realm (`realm_id`) | record `id` | callback URL, event types, `enabled` | File: an ID already bound to another realm is refused with `Conflict` (`qid-storage/src/file/scim.rs:176`); the same realm overwrites (`qid-storage/src/file/scim.rs:184`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm matches, so a foreign realm updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/scim.rs:353`, `qid-storage/src/sql/scim.rs:354`, `qid-storage/src/sql/scim.rs:365`). Both refuse a foreign realm with `Conflict`. | file `qid-storage/src/file/scim.rs:176`; sql `qid-storage/src/sql/scim.rs:354`, `qid-storage/src/sql/scim.rs:365` |
| `delete_scim_device` (delete) | optional expected realm (`realm_id`) | record `id` | none, removal | File: under the exclusive write lock a supplied realm must match the incumbent or no row is removed; `None` removes any realm and a missing or mismatched row reports `false` (`qid-storage/src/file/scim.rs:178`, `qid-storage/src/file/scim.rs:180`). SQL: `DELETE ... WHERE id = ? AND realm_id = COALESCE(?, realm_id)` reports `false` for a missing or mismatched row (`qid-storage/src/sql/scim.rs:361`, `qid-storage/src/sql/scim.rs:363`). The route passes `ScimRequestContext` realm with no pre-read and maps `false` to 404 (`qid-scim/src/lib.rs:241`). | file `qid-storage/src/file/scim.rs:178`; sql `qid-storage/src/sql/scim.rs:361`; route `qid-scim/src/lib.rs:241` |
| `delete_scim_event_subscription` (delete) | optional expected realm (`realm_id`) | record `id` | none, removal | File: under the exclusive write lock a supplied realm must match the incumbent or no row is removed; `None` removes any realm and a missing or mismatched row reports `false` (`qid-storage/src/file/scim.rs:233`, `qid-storage/src/file/scim.rs:239`). SQL: `DELETE ... WHERE id = ? AND realm_id = COALESCE(?, realm_id)` reports `false` for a missing or mismatched row (`qid-storage/src/sql/scim.rs:422`, `qid-storage/src/sql/scim.rs:428`). The route passes `ScimRequestContext` realm with no pre-read and maps `false` to 404 (`qid-scim/src/lib.rs:383`). | file `qid-storage/src/file/scim.rs:233`; sql `qid-storage/src/sql/scim.rs:422`; route `qid-scim/src/lib.rs:383` |

## service_account

Model type: `ServiceAccount`. Owner: realm (`realm_id`); the record references
a `client_id`.

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_service_account` - `ServiceAccount` | realm (`realm_id`) | record `id` | description | File: a second account with the same record ID is refused with `Conflict` under the exclusive write lock (`qid-storage/src/file/service_account.rs:9`, `qid-storage/src/file/service_account.rs:12`). SQL: `ON CONFLICT(id) DO NOTHING` and `ensure_upsert_applied` turns a zero-row result into `Conflict` (`qid-storage/src/sql/service_account.rs:8`, `qid-storage/src/sql/service_account.rs:21`). Both refuse a duplicate ID, including one presented for a different realm. | file `qid-storage/src/file/service_account.rs:9`, `qid-storage/src/file/service_account.rs:12`; sql `qid-storage/src/sql/service_account.rs:8`, `qid-storage/src/sql/service_account.rs:21` |
| `delete_service_account` (delete) | optional expected realm, matched to the record's `realm_id` when supplied | record `id` | none, removal | File: `Some(realm)` compares the owner and removes under the exclusive write lock; missing or foreign rows return `NotFound` unchanged. `None` retains the context-free ID-only silent no-op (`qid-storage/src/file/service_account.rs:42`). SQL: one static `DELETE` includes the realm predicate; a scoped zero-row result is `NotFound`, while `None` preserves the silent no-op (`qid-storage/src/sql/service_account.rs:49`). | file `qid-storage/src/file/service_account.rs:42`; sql `qid-storage/src/sql/service_account.rs:49` |

For first-use `client_credentials`, the endpoint preserves the legacy global
`service:{client_id}` ID when creation succeeds. If that ID conflicts and no
account exists for the requested `(realm_id, client_id)`, it tries
`service2:{UTF-8 byte length}:{realm_id}:{client_id}`. A conflict on this
fallback triggers a re-read of the exact pair; only a matching incumbent is
reused, and an unrelated ID collision remains `Conflict`. This retry does not
weaken the storage-level global ID uniqueness above (`qid-oauth/src/endpoints/token_grant.rs`).

The admin handler authorizes for the path realm and retains its realm-list pre-read for the established 404 response, then passes `Some(realm)` to the atomic storage delete (`qid-admin/src/identity.rs:325-343`). If the row is replaced between the pre-read and delete, File/SQL refuse a different realm and the handler returns before emitting a success audit. The create handler uses `Ulid::new()` rather than accepting an account ID (`qid-admin/src/identity.rs:288-296`); stale-ID reuse is conditional and is not claimed as a production exploit.

The `client_credentials` first-use path preserves the established `service:{client_id}` ID when available. If that global ID conflicts but no service account for this realm/client exists, it retries with a deterministic ID derived injectively from both values (`service2:{realm byte length}:{realm_id}:{client_id}`), distinct from legacy IDs and ULID-created admin accounts. This handles a stale account left after its client was removed and the client ID later reused in another realm, without changing ordinary token subjects. Existing persisted accounts are selected by `(realm_id, client_id)` and retain their stored IDs (`qid-oauth/src/endpoints/token_grant.rs:198-217`).

## session

Model type: `Session`. Owner: realm and user (`realm_id`, `user_id`); the
session ID is the primary key (`qid-storage/migrations/20250101000001_initial_schema.sql:56`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_session` - `Session` | realm + user (`realm_id`, `user_id`) | record `id` | `idle_expires_at`, `revoked`, `cnf` | File: an existing ID is refused with `BadRequest` by `validate_session_creation` under the write lock (`qid-storage/src/file/session.rs:9`, `qid-storage/src/domain/mod.rs:17`, `qid-storage/src/domain/mod.rs:19`). SQL: a pre-read of the ID is refused with `BadRequest` (`qid-storage/src/sql/session.rs:9`, `qid-storage/src/sql/session.rs:15`); because that check is a read before the insert, a concurrent insert of the same ID is refused by the primary key as a `Storage` error instead (`qid-storage/src/sql/session.rs:24`). The sequential case agrees (`BadRequest`); the concurrent case does not. | file `qid-storage/src/file/session.rs:9`, `qid-storage/src/domain/mod.rs:19`; sql `qid-storage/src/sql/session.rs:9`, `qid-storage/src/sql/session.rs:15` |
| `update_session_idle_expiry` - `Session` | realm + user | record `id` | `idle_expires_at` | File: the optional realm predicate is checked under the exclusive write lock; an unknown or foreign-realm ID returns `false` without mutation (`qid-storage/src/file/session.rs:21-34`). SQL: one `UPDATE` includes `(? IS NULL OR realm_id = ?)` with no pre-read; an unknown or foreign-realm ID affects no rows (`qid-storage/src/sql/session.rs:47-62`). `None` retains the context-free ID-only operation. | file `qid-storage/src/file/session.rs:21-34`; sql `qid-storage/src/sql/session.rs:47-62` |
| `revoke_session` - `Session` | realm + user | record `id` | `revoked` | File: with a realm scope, the owner check and active-state check happen under the exclusive write lock; unknown, foreign-realm or already-revoked sessions return `false` unchanged (`qid-storage/src/file/session.rs:37-50`). SQL: one `UPDATE` predicates on ID, realm and `revoked = 0` when scoped; a miss returns `false` (`qid-storage/src/sql/session.rs:65-75`). `None` preserves the legacy context-free ID-only operation and its backend-specific already-revoked behavior. | file `qid-storage/src/file/session.rs:37-50`; sql `qid-storage/src/sql/session.rs:65-75` |

Call-site review:

- Browser refresh and revoke retain `load_browser_session` realm checks for their existing response behavior, and now also pass `Some(realm)` to the atomic storage update/revoke (`qid-session/src/api/session.rs:14-61`). `SessionManager::create_with_regeneration` passes the selected realm when revoking an old cookie ID, so a foreign-realm row is not revoked (`qid-session/src/browser.rs:71-82`). The password, TOTP, WebAuthn and email-magic-link login paths use the selected realm's session manager (`qid-session/src/api/password.rs:108-121`, `qid-session/src/totp_api.rs:319-333`, `qid-session/src/api/webauthn.rs:288-307`, `qid-session/src/api/webauthn.rs:488-507`, `qid-session/src/email_magic_link.rs:353-364`). The default browser cookie name is `__Host-qid` (`qid-core/src/config/auth.rs:489-491`), shared by realms unless configured otherwise.
- OIDC RP-initiated logout compares the loaded session realm with the selected logout realm before using its identity and passes that realm to the atomic revoke (`qid-oidc/src/discovery.rs:963-979`). A foreign session is not used as logout identity or cache-invalidated. The validated backchannel `sid` branch passes the issuer-selected realm to `revoke_session`; it only invalidates cache for successful revocation or a session found in that realm (`qid-oidc/src/discovery.rs:1220-1242`). The `sub` branch lists sessions by the validated issuer realm and subject and passes that same realm to each atomic revocation (`qid-oidc/src/discovery.rs:1244-1260`). It preserves its existing per-session cache invalidation after any non-error result; actual-route scope observation is in `qid-oidc/src/discovery/logout_tests.rs`.
- SAML LogoutRequest and local SAML logout pass the validated endpoint/request realm to scoped revocation after their existing session checks (`qid-saml/src/routes.rs:539`, `qid-saml/src/routes.rs:700`); the File write lock and SQL predicate enforce realm ownership atomically. A repeated same-realm SP LogoutRequest is a success/no-op; this aligns the prior File refusal versus SQL update behavior (`qid-saml/src/routes/logout_tests.rs`). The ordinary admin revoke route passes its path realm to the atomic write after its existing checks (`qid-admin/src/identity.rs:187`); break-glass revoke checks the session realm's tenant then passes that session realm to the atomic write (`qid-admin/src/ops.rs:57`). Both admin callsites have actual-route scope-observation and repeat-call coverage in `qid-admin/src/tests/session_scope.rs`. Repeated same-realm admin revocation is an idempotent success and records an audit event for each authorized request, matching the existing SQL behavior; this intentionally normalizes File's former repeated-call error/no-audit behavior. The local qidc session-revoke command remains an ID-only operator CLI path (`qidc/src/main.rs:808-810`), distinct from realm-selected routes.

Current browser session IDs use 32 OS-random bytes; qidc's session-create CLI uses a server-generated ULID (`qid-session/src/browser.rs:52-65`, `qid-session/src/browser.rs:100-103`, `qidc/src/main.rs:791-806`). No caller-supplied HTTP session-ID creation path was found. The scoped storage-write contract for realm-selected browser operations, OIDC backchannel `sid`/`sub`, ordinary admin revoke and break-glass revoke is that the write does not mutate a session whose realm differs from the realm supplied by the caller. RP logout and SAML also reject foreign sessions before using them as logout identity or revoking them. Cache invalidation remains caller-specific: the `sid` branch confirms ownership on a scoped no-op, while the `sub` branch retains its existing post-write non-error invalidation behavior. These are source-level ownership guarantees, not evidence of a production exploit. The local qidc session-revoke command remains a separate context-free ID-only operation; future inventory slices must be measured against unchanged source caps.

## siem

Model type: `SiemDeliveryRecord`. Owner: realm (`realm_id`, optional; `None` is
the global scope). The delivery ID is the identity
(`qid-storage/migrations/20250630000001_siem_delivery_queue.sql:2`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `upsert_siem_delivery` - `SiemDeliveryRecord` | realm scope (`realm_id`, `None` = global) | record `id` | endpoint URL, payload, attempts, `next_retry_at`, status, `last_error`, `updated_at`; `created_at` is kept from the incumbent on the file path | File: an ID already bound to another realm scope is refused with `Conflict` by `ensure_same_binding` under the write lock (`qid-storage/src/file/siem.rs:10`); the same scope overwrites and keeps the original `created_at` (`qid-storage/src/file/siem.rs:15`, `qid-storage/src/file/siem.rs:20`). SQL: `ON CONFLICT(id) DO UPDATE ... WHERE` the realm scope matches (or both are `NULL`), so a foreign scope updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/siem.rs:9`, `qid-storage/src/sql/siem.rs:24`). Both refuse a foreign scope with `Conflict`. | file `qid-storage/src/file/siem.rs:10`; sql `qid-storage/src/sql/siem.rs:9`, `qid-storage/src/sql/siem.rs:24` |
| `mark_siem_delivery_status` - `SiemDeliveryRecord` | realm scope (`realm_id`, `None` = global) in the record; the write is not scope-filtered | record `id` | status, attempts, `next_retry_at`, `last_error`, `updated_at` | File: an unknown ID is `NotFound` (`qid-storage/src/file/siem.rs:76`). SQL: `UPDATE siem_delivery_queue SET ... WHERE id = ?` and no affected row is `NotFound` (`qid-storage/src/sql/siem.rs:93`, `qid-storage/src/sql/siem.rs:104`). Both agree. | file `qid-storage/src/file/siem.rs:76`; sql `qid-storage/src/sql/siem.rs:104` |

Call-site review at commit `3d3c95a`: the worker SIEM delivery job derives an ID that includes the configured realm/global scope, upserts that record with owner-checked semantics, then updates its status (`qid-worker/src/audit.rs:563-590`, `qid-worker/src/audit.rs:659-667`). The redrive job and qidc `SiemDlqRedrive` operator CLI fetch by ID before changing status (`qid-worker/src/audit.rs:719-724`, `qid-worker/src/audit.rs:803-815`, `qidc/src/main.rs:500-520`). A workspace search found no HTTP/API route caller of this status mutation; observed callers are internal worker/CLI queue operations, not tenant-authenticated writes. The storage mutation itself remains ID-only, so keep this as an internal lifecycle contract rather than treating its caller checks as a tenant boundary.

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
| `mark_authorization_code_used(&AuthorizationCode)` - `AuthorizationCode` | required realm + client + user; identity is `code_hash` plus the matching owner | `code_hash` + matching `realm_id`, `client_id`, `user_id` | `used` (one-shot) | File: checks the owner under the exclusive write lock; a missing or foreign record is `NotFound`, and an already used same-owner record is `Conflict`. SQL: pre-reads with the owner filter (`NotFound` for missing/foreign) and validates reuse (`BadRequest` for sequential same-owner reuse), then consumes with one static owner-bound `UPDATE ... WHERE code_hash = ? AND realm_id = ? AND client_id = ? AND user_id = ? AND used = 0`; a zero-row update re-reads so a missing or foreign replacement is `NotFound` while a same-owner concurrent loser is `Conflict`. Sequential reuse keeps the existing difference (`Conflict` against `BadRequest`); concurrent single-use agrees. | trait `qid-storage/src/traits.rs::TokenRepository::mark_authorization_code_used`; file `qid-storage/src/file/token.rs`; sql `qid-storage/src/sql/token.rs`; contract `qid-storage/tests/authorization_code_scope.rs`; grant `qid-oauth/src/endpoints/token_grant.rs` |
| `create_token_family` - `TokenFamily` | realm + client + user (`realm_id`, `client_id`, `user_id`) | record `id` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:104`) | `current_refresh_hash`, scopes, `revoked` | File: the operation replaces an existing ID, as its own comment states, and never errors (`qid-storage/src/file/token.rs:43`, `qid-storage/src/file/token.rs:53`). SQL: plain `INSERT` with `id` as primary key, so a repeated ID is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:71`). **Backends disagree:** the file path replaces, the SQL path refuses. | file `qid-storage/src/file/token.rs:43`, `qid-storage/src/file/token.rs:53`; sql `qid-storage/src/sql/token.rs:71` (not enforced as a conflict in SQL) |
| `update_token_family_refresh_hash(id, realm_id, ...)` - `TokenFamily` | required realm; family also binds client + user | record `id` + matching `realm_id` | `current_refresh_hash`, `refresh_expires_at` | File: checks the owner under the exclusive write lock before rotation validation or mutation; missing/foreign families are `NotFound`, while same-realm stale/reused hashes and revoked families retain `Conflict`. SQL: one static update predicates on ID, realm, expected hash, non-revoked state and a changed hash; zero-row classification checks realm before same-realm rotation validation, so missing/foreign IDs (including equal-hash calls) are `NotFound`, never reuse conflicts. Both preserve the full family on an owner mismatch. | trait `qid-storage/src/traits.rs::TokenRepository::update_token_family_refresh_hash`; file `qid-storage/src/file/token.rs`; sql `qid-storage/src/sql/token.rs`; contract `qid-storage/tests/token_family_scope.rs` |
| `revoke_token_family(id, realm_id)` - `TokenFamily` | required realm at mutation; family also binds client + user | record `id` + matching `realm_id` | `revoked` (monotonic) | File: `map_write` checks the realm under its exclusive store lock, preserves every foreign-realm field, and saves as before; missing/foreign records are successful no-ops. SQL: static `UPDATE token_families SET revoked = 1 WHERE id = $1 AND realm_id = $2`; zero affected rows is `NotFound`. Both accept repeated same-realm revocation without changing other fields. **Backends retain their missing/foreign-result difference** (`Ok` against `NotFound`), but neither can revoke another realm's family. | file `qid-storage/src/file/token.rs::revoke_token_family`, `qid-storage/src/file/mod.rs::map_write`; sql `qid-storage/src/sql/token.rs::revoke_token_family`; contract `qid-storage/tests/token_family_scope.rs` |
| `create_access_token` - `AccessToken` | realm + client + user + family (`realm_id`, `client_id`, `user_id`, `family_id`) | `jti` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:116`) | `revoked` | File: overwrite of the map entry, no error (`qid-storage/src/file/token.rs:148`). SQL: plain `INSERT` with `jti` as primary key, so a repeated JTI is a unique violation surfaced as `Storage` (`qid-storage/src/sql/token.rs:219`). **Backends disagree.** | file `qid-storage/src/file/token.rs:148`; sql `qid-storage/src/sql/token.rs:219` (not enforced as a conflict in SQL) |
| `revoke_access_token` - `AccessToken` | realm + client + user + family | `jti` | `revoked` | Requires the validated realm: File checks JTI + realm under its exclusive write lock; SQL uses static `UPDATE access_tokens SET revoked = 1 WHERE jti = $1 AND realm_id = $2`. Unknown JTI or wrong realm is a successful no-op in both backends; same-realm revocation is monotonic and changes no other fields. OAuth checks stored client + realm first, logs mismatches, then passes the authenticated client realm; RFC 7009 unknown/mismatch responses remain unchanged. | file `qid-storage/src/file/token.rs`; sql `qid-storage/src/sql/token.rs`; route `qid-oauth/src/endpoints/revoke.rs`; contracts `qid-storage/tests/access_token_scope.rs` |
| `store_par_request` - `ParRequest` | realm + client (`realm_id`, `client_id`) | `request_uri` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:163`) | `used`, `expires_at` | File: `insert_new` refuses a taken URI under the exclusive lock with `Conflict` (`qid-storage/src/file/token.rs:168`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:128`). SQL: static `ON CONFLICT (request_uri) DO NOTHING`; `ensure_upsert_applied` returns `Conflict` without changing the incumbent (`qid-storage/src/sql/token.rs:267`, `qid-storage/src/sql/token.rs:279`). Both preserve the original owner, payload and consumed state. | file `qid-storage/src/file/token.rs:168`; sql `qid-storage/src/sql/token.rs:279` |
| `mark_par_request_used` - `ParRequest` | realm + client | `request_uri` | `used` (one-shot) | File: an unknown URI is `NotFound` (`qid-storage/src/file/token.rs:184`) and an already used request is `Conflict` (`qid-storage/src/file/token.rs:188`). SQL: `UPDATE ... WHERE request_uri = ? AND used = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:296`, `qid-storage/src/sql/token.rs:301`). The already-used case agrees; the unknown-ID case differs. | file `qid-storage/src/file/token.rs:184`, `qid-storage/src/file/token.rs:188`; sql `qid-storage/src/sql/token.rs:296`, `qid-storage/src/sql/token.rs:301` |
| `store_device_authorization_grant` - `DeviceAuthorizationGrant` | realm + client (+ user once approved) | `device_code_hash` (primary key; `user_code` is globally unique, `qid-storage/migrations/20250101000001_initial_schema.sql:174`) | `approved_at`, `consumed`, `last_poll_at`, `poll_interval_seconds` | File: `insert_new` refuses a taken device code hash or a taken user code under the exclusive lock with `Conflict` (`qid-storage/src/file/token.rs:202`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:146`). SQL: static `ON CONFLICT DO NOTHING` covers both the primary key and the `UNIQUE` user code; `ensure_upsert_applied` returns `Conflict` without changing the incumbent (`qid-storage/src/sql/token.rs:312`, `qid-storage/src/sql/token.rs:329`). Both preserve the original owner, payload and lifecycle state. | file `qid-storage/src/file/token.rs:202`; sql `qid-storage/src/sql/token.rs:329` |
| `approve_device_authorization_grant` - `DeviceAuthorizationGrant` | realm + client (+ user once approved) | `user_code` (globally unique, `qid-storage/migrations/20250101000001_initial_schema.sql:174`) | `user_id`, `approved_at` | File: the grant is looked up by `user_code` in the whole store, and an unknown code is `NotFound` (`qid-storage/src/file/token.rs:240`, `qid-storage/src/file/token.rs:242`); an approval replaces the earlier one. SQL: `UPDATE device_authorization_grants SET user_id = ?, approved_at = ? WHERE user_code = ?` and no affected row is `NotFound` (`qid-storage/src/sql/token.rs:367`, `qid-storage/src/sql/token.rs:375`). Both agree. | file `qid-storage/src/file/token.rs:242`; sql `qid-storage/src/sql/token.rs:375` |
| `record_device_authorization_poll` - `DeviceAuthorizationGrant` | realm + client (+ user once approved) | `device_code_hash` | `last_poll_at`, `poll_interval_seconds` | File: the grant is updated when it exists, and an unknown hash is a silent no-op (`qid-storage/src/file/token.rs:259`, `qid-storage/src/file/token.rs:260`). SQL: `UPDATE device_authorization_grants SET ... WHERE device_code_hash = ?` and no affected row is not an error (`qid-storage/src/sql/token.rs:388`). Both are silent no-ops for an unknown hash. | file `qid-storage/src/file/token.rs:259`; sql `qid-storage/src/sql/token.rs:388` |
| `consume_backchannel_authentication_grant` - `BackchannelAuthenticationGrant` | realm + client + user | `auth_req_id_hash` | `consumed` (one-shot) | File: an unknown grant is `NotFound` (`qid-storage/src/file/token.rs:351`) and an already consumed grant is `Conflict` (`qid-storage/src/file/token.rs:355`). SQL: `UPDATE ... WHERE auth_req_id_hash = ? AND consumed = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:502`, `qid-storage/src/sql/token.rs:508`). The replayed case agrees; the unknown-ID case differs (`NotFound` against `Conflict`). | file `qid-storage/src/file/token.rs:351`, `qid-storage/src/file/token.rs:355`; sql `qid-storage/src/sql/token.rs:508` |
| `consume_device_authorization_grant` - `DeviceAuthorizationGrant` | realm + client + user | `device_code_hash` | `consumed` (one-shot) | File: an unknown grant is `NotFound` (`qid-storage/src/file/token.rs:272`) and an already consumed grant is `Conflict` (`qid-storage/src/file/token.rs:276`). SQL: `UPDATE ... WHERE device_code_hash = ? AND consumed = 0` and no affected row is `Conflict` (`qid-storage/src/sql/token.rs:401`, `qid-storage/src/sql/token.rs:407`). The replayed case agrees; the unknown-ID case differs (`NotFound` against `Conflict`). | file `qid-storage/src/file/token.rs:272`, `qid-storage/src/file/token.rs:276`; sql `qid-storage/src/sql/token.rs:407` |
| `store_backchannel_authentication_grant` - `BackchannelAuthenticationGrant` | realm + client (+ user once approved) | `auth_req_id_hash` (primary key, `qid-storage/migrations/20250101000001_initial_schema.sql:190`) | `approved_at`, `consumed`, `last_poll_at`, `poll_interval_seconds` | File: `insert_new` refuses a taken request ID under the exclusive lock with `Conflict` (`qid-storage/src/file/token.rs:290`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:152`). SQL: static `ON CONFLICT (auth_req_id_hash) DO NOTHING`; `ensure_upsert_applied` returns `Conflict` without changing the incumbent (`qid-storage/src/sql/token.rs:418`, `qid-storage/src/sql/token.rs:436`). Both preserve the original owner, payload and lifecycle state. | file `qid-storage/src/file/token.rs:290`; sql `qid-storage/src/sql/token.rs:436` |
| `approve_backchannel_authentication_grant` - `BackchannelAuthenticationGrant` | realm + client (+ user once approved) | `auth_req_id_hash` | `user_id`, `approved_at` | File: the grant is looked up by `auth_req_id_hash`, and an unknown hash is `NotFound` (`qid-storage/src/file/token.rs:316`); an approval replaces the earlier one. SQL: `UPDATE backchannel_authentication_grants SET user_id = ?, approved_at = ? WHERE auth_req_id_hash = ?` and no affected row is `NotFound` (`qid-storage/src/sql/token.rs:465`, `qid-storage/src/sql/token.rs:473`). Both agree. | file `qid-storage/src/file/token.rs:316`; sql `qid-storage/src/sql/token.rs:473` |
| `record_backchannel_authentication_poll` - `BackchannelAuthenticationGrant` | realm + client (+ user once approved) | `auth_req_id_hash` | `last_poll_at`, `poll_interval_seconds` | File: the grant is updated when it exists, and an unknown hash is a silent no-op (`qid-storage/src/file/token.rs:332`, `qid-storage/src/file/token.rs:336`). SQL: `UPDATE backchannel_authentication_grants SET ... WHERE auth_req_id_hash = ?` and no affected row is not an error (`qid-storage/src/sql/token.rs:486`). Both are silent no-ops for an unknown hash. | file `qid-storage/src/file/token.rs:332`; sql `qid-storage/src/sql/token.rs:486` |

Current token revocation and rotation call-site inventory:
- OAuth access-token revocation authenticates its client, checks the stored
  token's client and realm, and passes the authenticated client's realm to the
  storage write (`qid-oauth/src/endpoints/revoke.rs`). File and SQL enforce
  JTI + realm atomically; RFC 7009 responses and mismatch logging are retained.
- The OAuth refresh-token revocation helper checks the signed audience and the
  loaded family's client and realm, then passes that realm to the required-realm
  `revoke_token_family` write.
- The admin `revoke_token_family_handler` checks the loaded family against the
  path realm, then passes that realm into storage before its existing audit
  (`qid-admin/src/identity.rs`). Its route-observation test checks exact write
  arguments, refused requests, repeat same-realm responses and audit entries.
- Refresh-token rotation checks the authenticated client, family client/realm
  and expected refresh hash, then passes the authenticated client's validated
  realm to `update_token_family_refresh_hash`. File checks under its write lock;
  SQL includes the realm in the atomic update predicate. A wrong-realm or missing
  result stays on the generic invalid-token path and cannot enter the reuse
  revocation branch. Actual grant-callsite observation and File/SQLite complete-
  family contract tests are in `qid-oauth/src/endpoints/token_grant_rotation_tests.rs`
  and `qid-storage/tests/token_family_scope.rs`. The separate reuse branch still
  calls `revoke_reused_family`, which passes the loaded family realm to the
  atomic revoke and retains the existing metric, warning and unauthorized response.

Access-token revocation, token-family revocation and token-family rotation now
require and enforce realm ownership at their writes; none relies on the caller's
pre-read alone. New access-token JTIs and family IDs are generated with
`generate_jti` (ULIDs), not supplied by these routes
(`qid-oauth/src/endpoints/token_issue.rs`); these are storage-contract hardening
slices, not evidence of a production exploit.

The one-use redemption writes are reached through handle lookups and
validation: authorization-code redemption checks expiry, use, redirect, client,
realm and PKCE before marking the code used; PAR resolution checks expiry/use
and the merged client ID against the stored request before consumption;
device approval checks the approving user's realm, and device and CIBA
redemption check client, grant/user realm and target before consuming them
(`qid-oauth/src/endpoints/token_grant.rs:21-68`,
`qid-oidc/src/provider.rs:589-654`, `qid-oauth/src/endpoints/device_flow.rs:280-314,329-406`,
`qid-oauth/src/endpoints/ciba.rs:366-444`). These token operations preserve their existing owner validation and one-use behavior. At source commit `f896fcb30e752538175cf89bff072c9a2572fb20` (digest `5e4be4937bba4a594bb261adc03f0b4c1d3ea1e0aa7330b4e03960e1d3b0e369`), `cargo run --locked --offline -p xtask -- budget` measured 113,983/113,985 workspace lines and 15,989/15,990 qid-storage lines. Caps remain unchanged; later source changes require a fresh measurement.

## user

Model types: `User`, `PasswordCredential`. Owner: realm (`realm_id`); the
password credential is owned by the user (`user_id`). The users table
declares `UNIQUE(realm_id, email)`
(`qid-storage/migrations/20250101000001_initial_schema.sql:21`) and the
password credential table is keyed by `user_id`
(`qid-storage/migrations/20250101000001_initial_schema.sql:25`).

| write | owner key | identity key | mutable fields | same-owner collision | enforcement (file:line) |
|---|---|---|---|---|---|
| `create_user` - `User` | realm (`realm_id`) | record `id`; the schema also names a user by `(realm_id, email)` | email, `email_verified`, display name, `failed_login_attempts`, `locked_until`, `org` | File: `insert_new` refuses a taken record ID and a taken email in the realm with `Conflict` under the exclusive write lock, and the incumbent user is left unchanged (`qid-storage/src/file/user.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:23`). SQL: the insert carries `ON CONFLICT DO NOTHING`, so the primary key and the `UNIQUE(realm_id, email)` index refuse the duplicate inside the insert, and the zero-row result becomes a `Conflict` that names the taken key (`qid-storage/src/sql/user.rs:13`, `qid-storage/src/sql/user.rs:26`, `qid-storage/src/sql/user.rs:32`). Absent emails do not collide. Both refuse with `Conflict`; the same email in another realm names another user and is allowed. | file `qid-storage/src/file/user.rs:9`, `qid-storage/src/file/insert.rs:71`, `qid-storage/src/file/insert.rs:23`; sql `qid-storage/src/sql/user.rs:13`; schema `qid-storage/migrations/20250101000001_initial_schema.sql:21` |
| `update_user` - `User` | optional expected realm; record owner `realm_id` remains immutable | record `id` | email, `email_verified`, display name, `failed_login_attempts`, `locked_until`, `org`, `updated_at` | With an expected realm, File checks the incumbent under its write lock and SQL filters the atomic update by realm; missing or foreign users return `NotFound` unchanged. Without one, File retains its missing-user upsert and SQL its missing-user no-op. Both preserve the incumbent realm and refuse same-realm email conflicts. The admin directory supplies its authorized path realm; password authentication supplies the realm used for credential lookup; context-free callers use `None`. | file `qid-storage/src/file/user.rs:67-83`; sql `qid-storage/src/sql/user.rs:159-185`; trait `qid-storage/src/traits.rs:119`; admin route `qid-admin/src/directory.rs:311`; password auth `qid-session/src/auth.rs:172`, `qid-session/src/auth.rs:229`, `qid-session/src/auth.rs:255` |
| `delete_user` (delete) | optional expected realm (`realm_id`) | record `id` | removal of the user and live authentication state | A supplied realm must match the current owner; missing and wrong-owner users return `NotFound` without mutation. File checks before removing the user and its sessions, codes, families, tokens, credentials, devices, push and CIAM state under the write lock. SQL uses a predicate-checked no-op `UPDATE` to hold the matching user row/write lock in the transaction, then removes direct and session/family-linked codes, tokens and families and approved grants before deleting the user and cascading its other owned rows. Pending unowned grants, unrelated token subjects and audit history survive. `None` remains unrestricted and idempotently cleans orphaned state. | file `qid-storage/src/file/user.rs:57`, `qid-storage/src/file/user.rs:64`, `qid-storage/src/file/user.rs:110`; sql `qid-storage/src/sql/user.rs:125`, `qid-storage/src/sql/user.rs:128`, `qid-storage/src/sql/user.rs:140`, `qid-storage/src/sql/user.rs:147`; migration `qid-storage/migrations/20250630000012_user_authentication_lifecycle.sql` |
| `store_password_credential` - `PasswordCredential` | user (`user_id`) | `user_id` (primary key) | hash, algorithm | File: overwrite of the map entry, no error (`qid-storage/src/file/user.rs:91`). SQL: `ON CONFLICT(user_id) DO UPDATE`, an upsert that never errors (`qid-storage/src/sql/user.rs:75`). Both replace. | file `qid-storage/src/file/user.rs:91`; sql `qid-storage/src/sql/user.rs:75` |
| `update_password_credential_in_realm` - `PasswordCredential` | expected realm through current user (`realm_id`, `user_id`) | existing credential `user_id` | hash, algorithm | Update-only rehash: File checks the current user's realm and incumbent credential under one exclusive write lock before replacement. SQL uses one static `UPDATE` with a user/realm `EXISTS` predicate; zero affected rows is `NotFound`. Both refuse missing/foreign users or missing credentials without insertion or mutation. | file `qid-storage/src/file/user.rs` (`update_password_credential_in_realm`); sql `qid-storage/src/sql/user.rs` (same method); trait `qid-storage/src/traits.rs` (`UserRepository`) |

Password authentication rehash calls `update_password_credential_in_realm` with
the realm used to select the user. The unscoped `store_password_credential`
upsert remains unchanged for setup/CLI and fixtures; it is not used by rehash.
The SQL cross-realm delete/recreate boundary depends on the existing credential
foreign key's `ON DELETE CASCADE`
(`qid-storage/migrations/20250101000001_initial_schema.sql:25`) and the immutable
incumbent realm in `update_user`. A rehash that updates before deletion is
removed with the old user; one that reaches the replacement cannot update its
credential with the old realm. File checks the same boundary under its write
lock. This is not general authentication linearizability or a same-realm
credential compare-and-swap: same-realm password replacement or ID reuse is
outside this guard. File/SQLite contract coverage is in
`qid-storage/tests/password_credential_scope.rs`; normal progressive rehash
remains covered in `qid-session/src/auth.rs`.


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
| `store_workload_certificate` - `WorkloadCertificate` | realm + workload (`realm_id`, `workload_id`); the referenced identity must exist and match | record `id`; the thumbprint `x5t_s256` is unique per realm (`qid-storage/migrations/20250618000034_workload_certificates.sql:17`) | serial number, CSR, certificate PEM, `revoked_at`, validity dates | File: a missing workload is `BadRequest` (`qid-storage/src/file/workload.rs:79`, `qid-storage/src/file/workload.rs:80`) and a workload of another realm or SPIFFE ID is `BadRequest` (`qid-storage/src/file/workload.rs:84`, `qid-storage/src/file/workload.rs:86`); an incumbent ID bound to another `(realm, workload, spiffe_id)` is `Conflict` (`qid-storage/src/file/workload.rs:90`); another certificate with the same thumbprint in the realm is `BadRequest` (`qid-storage/src/file/workload.rs:102`, `qid-storage/src/file/workload.rs:107`). SQL: the same identity checks produce `BadRequest` (`qid-storage/src/sql/workload.rs:92`, `qid-storage/src/sql/workload.rs:97`) and a repeated thumbprint is `BadRequest` (`qid-storage/src/sql/workload.rs:99`, `qid-storage/src/sql/workload.rs:111`); the upsert's `WHERE` predicate covers `(realm, workload, spiffe_id)`, so an ID bound to another identity updates no row and `ensure_upsert_applied` returns `Conflict` (`qid-storage/src/sql/workload.rs:115`, `qid-storage/src/sql/workload.rs:116`, `qid-storage/src/sql/workload.rs:136`). Both refuse the same cases with the same errors. | file `qid-storage/src/file/workload.rs:90`, `qid-storage/src/file/workload.rs:102`; sql `qid-storage/src/sql/workload.rs:99`, `qid-storage/src/sql/workload.rs:115`, `qid-storage/src/sql/workload.rs:136` |
| `revoke_workload_certificate` - `WorkloadCertificate` | realm (`realm_id`) | record `id` | `revoked_at` | Both backends: an unknown ID or a certificate in another realm is `NotFound` (file `qid-storage/src/file/workload.rs:147`, `qid-storage/src/file/workload.rs:149`; SQL `qid-storage/src/sql/workload.rs:176`, `qid-storage/src/sql/workload.rs:201`). A timestamp before `issued_at` returns the same `BadRequest` as model validation and leaves the incumbent unchanged (`qid-core/src/models/workload.rs:65`, `qid-core/src/models/workload.rs:70`). File validates a cloned candidate under the write lock before replacing the map entry (`qid-storage/src/file/workload.rs:143`, `qid-storage/src/file/workload.rs:152`, `qid-storage/src/file/workload.rs:154`). SQL uses a static unsigned-order predicate in the guarded `UPDATE`, then classifies zero-row results with a post-write lookup (`qid-storage/src/sql/workload.rs:172`, `qid-storage/src/sql/workload.rs:177`, `qid-storage/src/sql/workload.rs:188`, `qid-storage/src/sql/workload.rs:192`, `qid-storage/src/sql/workload.rs:205`). Valid timestamps continue to set or replace `revoked_at`; identical retries succeed. **Backends agree.** | file `qid-storage/src/file/workload.rs:143`, `qid-storage/src/file/workload.rs:152`; sql `qid-storage/src/sql/workload.rs:172`, `qid-storage/src/sql/workload.rs:177`; shared contract `qid-storage/tests/sql_repository.rs:224` |

Push login resend timestamps are strictly increasing within the original at-most
600-second lifetime, at least one second apart, and validated against immutable
initial admission metadata. Quota counting validates each matching lifecycle row
whose expiry can contain an in-window resend, counting its initial admission and
each resend timestamp separately. Login cleanup retains rows until immutable
`expires_at < now - 86400`; registration cleanup still uses original issuance
and pending expiry. This conservatively retains all possible resend evidence.

Device and CIBA grant creation also persists immutable `resource` and resolved
`audience` vectors with `scopes`, client and realm. File serialization and SQL
migration `20261026000001_grant_targets` default legacy target vectors to empty.
Approval, poll updates and consumption do not replace any target or scope field;
create-only conflicts cannot rewrite this authorization context.
