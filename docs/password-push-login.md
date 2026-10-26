# Direct password login with registered push MFA

This guide describes account-owned push-device enrollment, password-plus-push
authentication, and revocation. Push requirements apply to password-based session
and OIDC password flows; the separate email magic-link behavior is unchanged.
SMS recovery is not provided.

The configured `auth_password` path (by default
`/api/v1/:realm/auth/password`) still accepts `email` and `password`. Existing
password policy, lockout and shared password admission limits run first. With no
active push registration, the ordinary session response and protected session
cookie remain unchanged. With an active registration, password-only login never
creates a session, including when push is disabled or delivery is unavailable.

Push requires enabled realm `authentication.mfa.push`, an HTTPS public base URL,
configured shared notification transport and an HTTPS notification provider that accepts the `push` channel (SMTP providers are email-only). Destination
and proof sizes, challenge lifetime, signature attempts and durable issuance
quotas use the existing push configuration. No provider call can approve a login.
A delivery failure returns a generic error and sets no binding or session cookie;
provider diagnostics and delivered nonces are never returned to the browser.

After password verification and accepted delivery, HTTP 202 returns
`challenge: "push_required"`, `challenge_id`, `realm_id`, `user_id`, `expires_at`
and `transaction_number`.
It sets `__Host-qid-password-push` with `HttpOnly; Secure; SameSite=Strict; Path=/`
and a `Max-Age` equal to the challenge lifetime. This name must not collide with
any configured realm's browser-session cookie. Only the browser cookie contains
the random browser secret; only its domain-separated verifier is stored. The
nonce goes only to the account-owned registered push destination. Push records
contain no OIDC requests or envelopes. Challenge ID is the unique login
transaction ID; realm, account, device, purpose and browser binding are immutable.

Three POST JSON endpoints are derived from the configured `auth_password` path:

- `<auth_password>/push/decision` accepts `realm_id`, `user_id`, `challenge_id`,
  `nonce`, `decision` (`approve` or `deny`) and `proof` (unpadded base64url strict
  ES256 COSE_Sign1). The path realm must equal the body realm. The shared
  qid-session service uses the strict qid-mfa verifier and atomically spends
  bounded attempts/records a device decision. HTTP 204 means a decision was
  recorded, not that a browser session was established.
- `<auth_password>/push/resend` accepts only `user_id` and `challenge_id`, with
  the same binding cookie required by completion. It returns HTTP 202 with
  `challenge_id`, `realm_id`, `user_id`, `expires_at` and `transaction_number` on
  accepted delivery. It rechecks current policy, transport and cookie collisions,
  then atomically reserves a send before provider I/O. It creates no session.
- `<auth_password>/push/complete` accepts only `user_id` and `challenge_id`, with
  the binding cookie from the same browser. Unknown fields (including client AMR)
  are rejected. The shared factor service rechecks enabled policy and available
  delivery configuration, then atomically redeems the approved challenge while
  rechecking current registration, expiry, exact owner/transaction/browser binding
  and one use. Denied, expired, revoked, replayed or wrong-browser completions
  create no session. A direct-login browser verifier cannot be exchanged with
  the OIDC verifier, even by manually copying a cookie value.

## Transaction number and bounded resend

The browser and every login notification receive the same six ASCII decimal
`transaction_number` (including leading zeroes). It is the first big-endian
32 bits of SHA-256 of the random challenge ID, modulo 1,000,000, zero-padded to
six digits. It identifies context for comparison, is not globally unique and is
**not a credential**: entering or returning it can never approve or deny login.
Only the current registered device's signature over the exact bound challenge
and nonce can authorize a decision, followed by same-browser completion.

## Assurance boundary

qid's push flow combines a signature from a registered device key with a
six-digit transaction-number comparison. The number is display context, not
cryptographic proof; the signature proves possession of the enrolled key, but
not that a human compared the number. qid does not claim that this
comparison/secondary-channel approval is a NIST SP 800-63B-4-conforming
out-of-band (OOB) method, provides AAL2 assurance, or is phishing-resistant
authentication. WebAuthn/passkeys are separately available as a
phishing-resistant option; their availability alone does not establish that a
deployment meets AAL2. See the [official NIST SP 800-63B-4 publication](https://pages.nist.gov/800-63-4/sp800-63b.html).

Resend retains the challenge ID, owner, realm, purpose, authenticator, browser
binding, original creation/expiry, attempt cap/count and any OIDC continuation.
Every admitted resend rotates to a fresh random nonce, durably replacing only its
SHA-256 verifier and appending the trusted admission timestamp. An old prompt's
nonce/proof becomes invalid at admission, even if delivery fails or times out.
Delivery can arrive out of order; devices must use the newest prompt. There is
still only one redeemable approval, not one per notification. Resend cannot
extend expiry, restore attempts, clear a decision or revive a revoked device.

`resend_cooldown_seconds` defaults to 30 (valid 1..=600). Cooldown runs from the
last admitted send, including failed sends, not provider completion. Expired,
decided, consumed, attempt-exhausted, revoked, wrong-owner/browser/realm,
cooldown-limited or quota-limited requests are refused without admission. The
existing realm + user + purpose `max_issuances_per_window` budget counts both
initial sends and resends over `issuance_window_seconds`, across devices and
both login surfaces. Registration keeps its separate purpose budget. No provider
I/O holds a database lock. Failed/time-out delivery never refunds quota or
restores an old nonce; no nonce or provider diagnostics reach browser responses.

Only successful same-browser completion creates a session with server-derived
AMR `pwd`, `push` and the existing password ACR. Session authentication time is
server-side completion time, when the combined authentication finishes. The
ordinary session owner handles creation, old-session revocation/regeneration,
timeouts and configured secure cookie protections. Successful completion also
expires the temporary binding cookie. Responses carrying authentication results
or factor decisions use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
A failure after atomic redemption is fail-closed and requires a new login.

qid-session owns challenge issuance/delivery, signature verification and factor
completion for both password entry points. qid-oidc alone owns validated OIDC
continuation context, PAR/JAR semantics, protocol checks and authorization-code
issuance; see [the continuation contract](oidc-authorization-continuation.md).
This direct endpoint neither creates nor consumes OIDC continuations or codes.
OIDC continuation rows are deleted after expiry by `qid-worker push-cleanup`;
QID does not schedule the command. Configure an external scheduler to run it
repeatedly, as described in [operations](operations.md#push-challenge-and-oidc-continuation-cleanup).

## Account-owned enrollment and revocation

All registration operations are JSON POSTs below
`<auth_password>/push/registrations` (`auth_password` is configurable). They
resolve the account exclusively from its persisted, active, same-realm browser
session, never from a request user ID or OAuth Device record. Unknown request
fields, including claimed AMR, are rejected. Responses are `no-store` and
`no-referrer`; errors are generic and omit provider diagnostics and input values.

Enrollment requires `authentication.mfa.push` and the same configured delivery
prerequisites as push login. At **both start and finish**, the session's trusted
`auth_time` must not be in the future or older than `recent_reauth_seconds`
(default 300 seconds). Idle refresh does not refresh authentication time. A
password-authenticated session (`pwd`) can bootstrap its first device without
already having another MFA factor. If an enabled account TOTP credential or a
passkey exists, the recent session must instead prove a currently enrolled
stronger method: `totp` or `webauthn`, using the AMR issued by those existing
authentication endpoints. A matching credential must predate that authentication.
ACR labels or caller-supplied method names do not count. For password-based management, an already enrolled push factor must also be
satisfied (`push` in trusted session AMR); an existing stronger method suffices
without requiring an AMR combination the current endpoints cannot issue. There is no new
realm-wide or administrator `require_step_up` setting.

- `/start` accepts `destination` (an opaque provider destination, not a URL qid
  fetches), `device_name` and `device_platform` (non-secret display metadata,
  1..=64 Unicode scalar values each, no control characters or leading/trailing whitespace),
  and `public_jwk` (public P-256 EC JWK only). Blank/control-containing
  destinations, names or platforms and destinations exceeding
  `max_destination_bytes` are rejected. Invalid metadata is rejected.
  After concurrency admission, durable owner-wide issuance admission creates a
  pending registration, storing only the nonce's SHA-256 verifier and public key.
  The configured transport receives the nonce, purpose `registration`, realm,
  user, registration ID and expiry at the candidate destination. Transport calls
  hold the shared delivery semaphore and use the configured timeout. Provider
  acceptance does **not** enroll the device. HTTP 202 returns only
  `registration_id` and `expires_at`, never the nonce or destination.
- `/finish` accepts `registration_id`, `nonce` and base64url `proof`. The device
  supplies the nonce and COSE_Sign1 ES256 proof to the initiating browser; that
  **same session** must finish. The existing qid-mfa registration payload binds
  realm, user, registration/authenticator ID, purpose, nonce and destination
  digest. The device must know the destination it is registering. The opaque
  registration ID includes a random prefix and domain-separated digest binding
  the exact initiating session; no raw session cookie or additional protocol
  context is stored in generic factor records. Storage atomically enforces
  expiry, the fixed attempt budget and one-use activation. Invalid or oversized
  proofs spend an attempt after owner/session checks. Success is HTTP 204.
- `/revoke` accepts only `authenticator_id`. It requires a recent active owner
  session with the same current-factor assurance rules, so an old password-only
  session cannot remove push as a login bypass. It works even with push delivery
  disabled or unavailable. Success is HTTP 204. Revoked registrations cannot
  approve or redeem pending sign-ins; revoking the last active registration
  removes that account's push login requirement.
- `GET /` (the registrations base path) lists only the caller's enrolled
  devices as `{authenticators: [{registration_id, device_name,
  device_platform, created_at, status}]}` with `status` `active` or `revoked`.
  It requires only an authenticated same-realm account session, so it stays
  available when push delivery is disabled or unavailable. Pending
  (not-yet-activated) registrations are not listed. Destinations, public keys,
  verifiers and nonces are never returned.

The registration JSON body is bounded to 16 KiB, independently of the configured
proof/destination bounds. Delivery failure or timeout leaves only unactivated
pending state under the same durable issuance quota and expiry/cleanup rules;
retries cannot evade the quota. No route logs request bodies, proofs, destination,
nonce or provider diagnostics.
