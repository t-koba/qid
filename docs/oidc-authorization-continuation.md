# OIDC authorization-continuation storage contract

This document describes the OIDC password-login push continuation and its
separate storage contract.

`OidcAuthorizationContinuation` is separate from push login challenges and OAuth
Device records. qid-session generates the unpredictable push transaction ID;
qid-oidc uses it as the continuation ID and serializes a **validated, versioned
authorization envelope** after resolving PAR/JAR. It must
preserve the validated client, redirect URI, PKCE, state, nonce, response mode and
other request semantics, but must not persist transient DPoP proofs. Stored JSON
is not authorization authority: storage checks a nonempty JSON object and a
64 KiB UTF-8 byte limit, not the protocol's fields, version or signatures.

`OidcContinuationRepository` is part of `Repository` and supports unique creation
and atomic consume only. Creation binds ID, realm, user, client, exact context
bytes, browser-binding SHA-256 verifier, and trusted creation/expiry timestamps.
IDs and owner labels are nonempty, at most 256 UTF-8 bytes, with no whitespace or
control characters. The caller generates an unpredictable browser secret, keeps
it in the browser binding, and passes only its SHA-256 verifier to storage. It
must never accept a caller-supplied verifier as proof of browser possession.
Debug output omits context and binding verifier.

Creation requires `created_at == now < expires_at <= i64::MAX` (Unix seconds).
qid-oidc supplies trusted server time and selects expiry under its continuation
lifetime policy; storage has no independent protocol lifetime policy. Invalid
shape/clock bounds produce `BadRequest`. An existing ID is always `Conflict`,
even for identical content, another owner, or an already consumed record.

Consume matches ID, realm, user, client and browser verifier atomically and
requires `created_at <= now < expires_at`. It returns the exact original record
once; missing, mismatched, expired or consumed records return `None` without
consuming anything. SQL uses a static conditional UPDATE; file storage persists
under its exclusive save/store locks before reporting success, with rollback on
write failure. The contract survives reopening both backends. Consumed records
remain ID tombstones until expiry. `qid-worker push-cleanup` deletes expired
continuation rows in bounded batches; configure an external scheduler to run it
repeatedly. QID does not schedule cleanup itself.

The OIDC caller must establish completed authentication, check current account
and client policy, decode/validate its envelope version, and resume the original
request without re-consuming PAR. Consuming this record alone does not establish
factor approval, session assurance, or permission to issue any token or code.
The owner strings are exact bindings, not an account/client existence check.

## OIDC push continuation

After password verification, qid-oidc calls the shared qid-session
`auth::push_factor_satisfied` evaluator. An active registration requires trusted
AMR `push`: disabling push delivery never falls back to password-only issuance.
The same evaluator gates existing browser sessions, so enrollment also prevents
reuse of an older password-only session. No registration preserves ordinary
password login. Existing `max_age`, login prompts and essential ACR checks still
gate session reuse; `prompt=none` returns `login_required` when reuse fails.

When push is required, the password endpoint returns HTTP 202 `push_required`,
with `challenge_id`, `realm_id`, `user_id`, `client_id`, `expires_at` and
`transaction_number`. It issues
no authorization code or browser session. It sets an independent random
`__Host-qid-oidc-push` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`),
whose lifetime is the realm's push `ttl_seconds`. This name must not also be a
configured browser-session cookie name; issuance fails closed on a collision.
An HTTPS public base URL, enabled push policy and configured notification
transport are required. Delivery uses the shared notification semaphore and
configured timeout; provider acceptance alone cannot complete authentication.

The registered device receives a notification with the challenge ID, exact
realm/user/authenticator/purpose, expiry and a fresh nonce. Neither its push
destination nor the nonce is returned to the browser. Only nonce and browser
secret verifiers are persisted in push storage. Issuance uses the realm's
`max_issuances_per_window` and `issuance_window_seconds`; proof and destination
sizes and signature attempts use the existing push policy limits.

Challenge admission, notification delivery, strict device-signature decisions and
atomic password-plus-push completion are owned by `qid_session::push`. OIDC calls
that service and retains only protocol context, browser-cookie handling and code
issuance. The service returns server-derived `pwd`, `push` AMR and password ACR;
the OIDC envelope does not store a second copy of those authentication methods.

Three POST JSON endpoints are derived from the configured authorize path:

- `<authorize>/push/decision` accepts `realm_id`, `user_id`, `challenge_id`,
  `nonce`, `decision` (`approve` or `deny`) and `proof` (unpadded base64url of
  strict ES256 COSE_Sign1 bytes). It uses `qid_mfa::push::verify_login`, then
  atomically records the signature attempt/decision against the current
  registration. Valid decisions return HTTP 204, not a code or session.
- `<authorize>/push/resend` accepts the same `realm_id`, `user_id`, `client_id`
  and `challenge_id` and separate OIDC browser cookie as completion. Client
  identity and the OIDC domain are included in the challenge's browser verifier,
  preventing request substitution or direct-login cookie reuse. It reserves and
  rotates through the shared factor service, never consumes or replaces the
  validated continuation and never resolves PAR/JAR again. HTTP 202 returns the
  same challenge IDs, expiry and stable six-digit `transaction_number` as the
  notification. See [number matching and resend](password-push-login.md#transaction-number-and-bounded-resend)
  for cooldown, unified quotas, nonce rotation and delivery-failure semantics.
- `<authorize>/push/complete` accepts only `realm_id`, `user_id`, `client_id`
  and `challenge_id`, plus the browser binding cookie. Unknown JSON fields are
  rejected. It requires signed approval and the exact same-browser binding,
  consumes the OIDC continuation once, rechecks the current client/user and
  protocol policy, and atomically redeems the still-current push challenge.
  Only then does it issue an authorization code with AMR `pwd`, `push`, using
  the existing response-mode owner. It preserves password ACR and password
  authentication time; it does not create a browser session (matching the
  existing OIDC password endpoint). Errors never fall back to code issuance.

The version-1 OIDC envelope retains resolved PAR/JAR parameters, including PKCE,
redirect, state, nonce, scope, resource, authorization details, response mode,
claims, prompt and max_age. It stores the derived original DPoP thumbprint for
JARM, not the transient proof JWT; a completion-request DPoP header cannot
replace it. The original PAR is already consumed before the push challenge
is issued and is never resolved/consumed again during completion. Query,
form_post and signed JARM responses use the existing OIDC response builders.

Browser substitution or a mismatched continuation owner cannot consume either
approval or context. Concurrent completion produces at most one code. Failure
after a valid continuation consume is fail-closed and may require a new login;
there is no rollback that makes an authorization request reusable.

Expired continuations cannot authorize a response; repeated external scheduling
of `qid-worker push-cleanup` is required to delete them and bound retained
storage. The cleanup command also deletes expired push challenges and pending
registrations while preserving the maximum quota-retention horizon.
