# Auth capabilities plan (ports & adapters)

## Goal

Ten auth capabilities builders expect from a modern auth stack:
organizations, admin (ban, roles, impersonation), anonymous sessions,
phone number, magic link, email OTP, passkeys, generic OAuth/OIDC,
Google One Tap, and two-factor auth. This plan defines how to support
them **across both identity providers** (Better Auth and Auth.js)
without breaking the hexagonal design:

- Core stays framework-free and **provider-agnostic**. It learns new
  _facts_ about a session (how strongly it was proven, who is acting),
  never provider mechanics.
- Each provider adapter **maps its native mechanism to those facts**,
  or declares honestly that it can't.
- **Payload keeps owning users** (invariant 1): no second user store,
  no shadow session table.

The Better Auth names (`organization`, `admin`, …) are used as labels
for the capability, not as the design. Each capability is specified
once in core terms, then per adapter.

## Success Criteria

- The scope covers the ten originally requested capabilities plus
  seven found in the 2026-10-12 docs review (CAP-12 to CAP-18), with
  out-of-scope features listed explicitly under Non-goals.
- Every capability has a row in the support matrix with one honest
  status per provider: native (adapter maps it), recipe (documented,
  example-tested, builder-owned), or unsupported (fails fast at wiring
  with a typed error when a policy requires it).
- Core gains a small, versioned vocabulary (identity claims, assurance,
  actor, capabilities) that both adapters fill through one shared
  **provider conformance kit**, so behavior can't drift between
  providers.
- Each shipped capability is proven the way the rest of the project
  is: unit or integration tests in the adapter, plus e2e on both
  frameworks wherever a capability is user-facing. No live third-party
  service is needed in CI (local mock identity provider, captured
  mail/SMS, virtual authenticator).
- No invariant regresses: Payload owns users, core imports no
  framework or provider SDK, every new state-changing endpoint has
  CSRF + access checks, and the `SessionUser` wire contract only
  gains optional fields.

## Current state (evidence, 2026-10-12)

Measured on Better Auth 1.7.7 and `@auth/core` 0.41.3.

**Better Auth.** The adapter mirrors the BA schema strictly: a plugin's
extra tables and fields must be declared via `customFields` /
`customModels`, and anything undeclared fails at startup
(`UnsupportedSchemaError`). A probe generated each plugin's
declarations from BA's own `getAuthTables` and booted our real engine
with them. **All 10 passed schema validation, and every field maps to
a supported column type:**

| Plugin        | Declarations needed                                                           |
| ------------- | ----------------------------------------------------------------------------- |
| organization  | `session.activeOrganizationId`; models `organization`, `member`, `invitation` |
| admin         | `user.role`, `banned`, `banReason`, `banExpires`; `session.impersonatedBy`    |
| anonymous     | `user.isAnonymous`                                                            |
| phone-number  | `user.phoneNumber` (unique), `user.phoneNumberVerified`                       |
| magic-link    | none (core `verification` table)                                              |
| email-otp     | none                                                                          |
| passkey       | model `passkey` (`@better-auth/passkey`, separate package)                    |
| generic-oauth | none (core `account` table)                                                   |
| one-tap       | none                                                                          |
| two-factor    | `user.twoFactorEnabled`; model `twoFactor`                                    |

Only `organization` round-trips on real storage in a test
(`custom-schema.test.ts`). No plugin has e2e coverage; e2e covers only
email/password sign-in.

**Auth.js.** Our adapter already implements the full Auth.js adapter
surface, including verification tokens (needed by the Email provider)
and authenticators (needed by Passkey/WebAuthn), backed by
`aj-verification-tokens` and `aj-authenticators`. Only verification
round-trips and authenticator cascade-delete are tested. `@auth/core`
ships Email providers (Nodemailer, Resend, SendGrid, Postmark,
ForwardEmail), a Passkey/WebAuthn provider (behind
`experimental.enableWebAuthn`), and 100+ OAuth/OIDC providers.

**Gate interaction (SEC-2).** The plugin only links a Payload user
from a session whose email the provider verified. Source reading
shows:

- **Verified, so they work today:** BA magic-link and email-otp,
  BA one-tap and generic-oauth when the identity provider asserts
  `email_verified`, and the Auth.js Email provider (stamps
  `emailVerified: new Date()`).
- **Refused today (401):**
  - BA anonymous: placeholder email, `emailVerified: false`.
  - BA phone-number sign-up: placeholder email, unverified.
  - **Every Auth.js OAuth/OIDC sign-up.** `handle-login.js` creates
    OAuth users with `emailVerified: null`, whatever the identity
    provider asserts.
- **Security gap:** with BA admin impersonation, Payload sees the
  _target_ user with that user's rights, and `impersonatedBy` never
  reaches Payload, so actions can't be audited. Plugin logout doesn't
  clear BA's `admin_session` cookie.

### Provider landscape (verified 2026-10-12)

Both statements below were read on the providers' own sites, not
inferred:

- **Auth.js is now part of Better Auth.** authjs.dev states "The
  Auth.js project is now part of Better Auth" (footer: "© Better Auth
  Inc. - 2026"). Security fixes ship for the latest release only, and
  the `@auth/*` packages other than adapters are described as "not
  considered ready for production yet". No roadmap is published.
- **Auth.js WebAuthn is not production-ready upstream:** "The
  WebAuthn / Passkeys provider is experimental and not recommended for
  production use". It is supported only with `next-auth` ≥ 5.0.0-beta.8
  and `@auth/prisma-adapter` ≥ 1.3.0. Neither is our stack (we use
  `@auth/core` with a Payload adapter).
- **Consequence (D7, accepted):** Better Auth is the primary provider for new
  capabilities. Auth.js keeps parity for what it does well natively
  (email sign-in, OAuth/OIDC) plus correctness and security fixes; it
  gets no experimental features.

**Already in our favour:** the BA port reads sessions with
`disableCookieCache: true` (`port.ts`), so BA's documented caveat that
"revoked sessions may remain active … until the cookie cache expires"
does not apply to Payload: server-side revocation is immediate. Only
BA's own client-side reads can lag behind the cache.

### Phase 0 spike findings (2026-10-12)

All six spikes ran throwaway Vitest suites against the installed
Better Auth 1.7.7 / `@auth/core` 0.41.3 code and our real
engines/adapters on Payload/SQLite; the spike files were deleted
afterwards. Verdicts below revise several Phase 0 assumptions.

**S1 — Auth.js Email vs the JWT rule (CAP-1): premise refuted, gate clears.**
Email imposes no database-strategy requirement: upstream requires only
an adapter plus `emailMethods` (`@auth/core` `assert.ts:213-226,51-55`),
and both strategies are first-class in `handle-login.ts`.
Email+JWT already works end-to-end today (magic link, JWE cookie,
verified port session, single-use link, zero `aj-sessions` rows), as does
Email+database; our fail-fast never blocked it because it keys only on
`type === 'credentials'` (`provider-authjs/src/engine.ts:92-94,171-176`).
CAP-1 needs zero engine/adapter/callback changes — only a committed
regression test, guide docs, and example/e2e mail-sink wiring; the bullet
at CAP-1 must be rewritten and the Credentials+database fail-fast kept
(upstream's looser rule would issue JWT cookies a database read cannot
honour). Open policy notes: Email-only JWT silently gets Auth.js's
30-day `maxAge` (our 1h default is Credentials-only,
`engine.ts:193-196`), and adding Credentials later forces `jwt`, making
sessions unrevocable. Nodemailer itself was not exercised (`nodemailer`
is not installed); the shipped Resend provider was used instead.

**S2 — Auth.js email OTP (CAP-2): refuted as written, proven with one correction.**
A form POSTing `token`+`email` in the body fails with a `Configuration`
error: the email callback reads only the query string
(`@auth/core` `lib/actions/callback/index.ts:205-215`). The same 6-digit
code succeeds via `GET /callback/<id>?token=…&email=…` (or a POST whose
action URL carries the query): only `sha256(code+secret)` is stored
(`send-token.ts:78-82`), consumption is single-use, and sessions issue
normally on our adapter (`adapter.ts:491-523`). CAP-2's recipe text must
change accordingly. Rate limiting is genuinely builder-owned — a wrong
guess neither consumes nor counts against the code, so the recipe should
set a short `maxAge` (upstream default 24h) plus the verify-path limiter.
Duplicate codes collide: the hash excludes the identifier and our token
field is uniquely indexed alone (`collections.ts:78`), so two concurrent
identical codes throw `AdapterOperationError` — composite
`(identifier, token)` uniqueness is needed before OTP ships.

**S3 — BA 2FA trusted-device marking (CAP-6): BA marks nothing.**
The two-factor plugin adds no session field at all
(`better-auth` `plugins/two-factor/schema.mjs:2-7`); the only signal is
the user-level `user.twoFactorEnabled`. Freshly verified and
trusted-device sessions are indistinguishable in schema, rows, and
`getSession` output (spike-asserted key-set equality), and trusted-device
state exists only as a signed browser cookie plus a `verification` row.
CAP-6's "only if BA marks them so" clause must be deleted: mapping
`twoFactorEnabled` (absent → `'unknown'`, `false` → false, `true` → true)
gives trusted sessions `mfa: true` and makes `requireMfaForRoles` a
user-enrollment gate, not per-session proof — per-session proof is
unsupported on BA 1.7.7. Named false positives: enrollment-rotation
sessions (spike-proven), other-device pre-enrollment sessions, and
non-credential sign-ins outside the hook matcher (`index.mjs:245-246`;
latter two source-proven only). Confirmed: no session exists while 2FA
is pending, so a half-authenticated user can never be linked.

**S4 — BA sign-in method (PORT-1 `assurance.methods`): no per-session signal.**
BA core records no method on session or user
(`@better-auth/core` `session.d.mts:7-16`; `internal-adapter.mjs:247-285`),
and `account.providerId` is per-linked-account, not per-session. The only
signal is the opt-in `last-login-method` plugin, which is per-user: an
older password session reports `"magic-link"` after a later magic-link
sign-in rewrites the user row (spike-proven), so it cannot populate
per-session assurance. Without the plugin — or in its default
unsigned-cookie mode — every method is `'unknown'`. With
`lastLoginMethod({ storeInDatabase: true })` plus a `customFields`
declaration, password (`email` → `password`), magic-link, and email-otp
are reportable; OAuth and passkey are source-verified only
(`plugins/last-login-method/index.mjs:11,14`); one-tap, phone-otp,
username, and 2FA-created sessions resolve to `null` (→ `'unknown'`)
without a `customResolveMethod`. CAP-1's "where BA exposes the sign-in
method" should read "nowhere, per-session": true per-session methods
require new PORT-1 scope (a session additionalField stamped from a
`databaseHooks.session.create` hook), and `lastLoginMethod` must never
back `access.ts` policies.

**S6 — BA multi-session cookies and revoke (CAP-13b): feasible, by a different route.**
Multi-session cookie names are per-token dynamic —
`${sessionToken.name}_multi-${token.toLowerCase()}`
(`plugins/multi-session/index.mjs:170`) — so the static
`sessionCookieNames` list (`core/src/ports.ts:189`) can never contain
them, and the token must never be parsed from the lowercased suffix.
Today's logout sweep provably leaves other accounts' sessions alive
server-side after a 200 logout. BA's `revokeDeviceSession` is unusable in
our order: it requires a live active session (`index.mjs:123`) and
promotes the next account when the active one is revoked (:152-154).
The proven recipe is: enumerate with `auth.api.listDeviceSessions`
(signature-verified, no active session required, `index.mjs:38-54`),
revoke each returned token through our existing `provider.revokeSession`
(the same `deleteSession` primitive, `port.ts:138-145`), then expire every
presented `*_multi-*` cookie with the session-token clearing attributes.
CAP-13's "BA revoke per token" wording needs this correction, plus a port
enumeration capability and request headers in the expiry sweep.

**S7 — Official Auth.js adapter suite (Phase 1 conformance): adoptable, with harness work.**
The suite (`runBasicTests`, 22 cases) is not installed and cannot be
added as a dependency — it is monorepo-internal to next-auth, so a pinned
vendored copy is the only route. All 22 cases map onto methods our
adapter implements (`adapter.ts:259-591`) and an equivalent subset passes
13/13 on real Payload, so official conformance needs zero production
changes. Running it verbatim needs a ~60-line `db.*` mapping harness that
normalizes Payload docs (`auId`, numeric `id`, ISO-string dates,
`collections.ts:50,58`), `testWebAuthnMethods: true` (else `getAccount`
is silently skipped), `CUSTOM_MODEL` unset, sequential single-file
execution, and a no-`id` `db.session` workaround for one strict-equality
clash (`AdapterSession` has no `id`, `adapter.ts:117-123`). The spike
read floating upstream `main`; the vendored copy must be re-verified
against the `@auth/core` 0.41.3 tag. It independently confirms S2's
duplicate-code finding: verification tokens need composite
`(identifier, token)` uniqueness before CAP-2.

## Approach

### Three layers, three owners

The ten capabilities aren't one kind of thing. Each belongs to the
layer that owns the data it changes:

| Layer                     | Capabilities                                                                   | Owner                                 | Why                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------ | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A. Proving identity**   | magic link, email OTP, passkey, OAuth/OIDC, One Tap, phone OTP, anonymous, 2FA | Provider adapter                      | Credentials, challenges, tokens, and sessions are provider state. Core needs only the _result_: who, which identifiers are verified, and how strongly.            |
| **B. Account governance** | ban/suspend, roles, impersonation audit, MFA-required policy                   | Payload plugin (provider-agnostic)    | Payload owns users and reloads them on every request, so a ban or role there applies to every provider at once. Policies read session facts, never provider APIs. |
| **C. Tenancy**            | organizations, members, invitations                                            | **Decision D1** (Payload recommended) | Membership is a property of users, and Payload owns users. A provider-native store would be a second source of truth for authorization.                           |

### Invariants that shape the design

- **No shadow session state (invariant 1)** rules out a
  plugin-owned 2FA step-up: recording "this session passed MFA"
  needs per-session state, which belongs to the provider. So MFA
  stays provider-owned, and the plugin only _reads_ the assurance
  fact and enforces policy on it.
- **Core imports no provider SDK (invariant 2):** new vocabulary is
  plain types; each adapter maps its SDK.
- **Authorization goes through `access.ts` (invariant 5):** ban, MFA
  policy, and impersonation restrictions are new access helpers, not
  ad-hoc checks.

## Port changes (core)

Additive, versioned, and the same for every provider.

1. **`ProviderSession` gains claims, assurance, and actor** (keeping
   `email`/`emailVerified` as deprecated aliases for one minor):

   ```ts
   type VerifiedClaim<T> = { readonly value: T; readonly verified: boolean }
   type AuthMethod =
     | 'password'
     | 'magic-link'
     | 'email-otp'
     | 'oauth'
     | 'one-tap'
     | 'passkey'
     | 'phone-otp'
     | 'anonymous'
   type ProviderSession = {
     readonly sessionId: string
     readonly providerUserId: string
     readonly expiresAt: Date
     readonly identity: {
       readonly email: VerifiedClaim<Email> | null
       readonly phone: VerifiedClaim<PhoneNumber> | null // branded, E.164
       readonly anonymous: boolean
     }
     /** How the session was proven; `unknown` when the provider can't tell. */
     readonly assurance: {
       readonly methods: readonly AuthMethod[] | 'unknown'
       readonly mfa: boolean | 'unknown'
     }
     /** Set while an operator acts as this user (impersonation). */
     readonly actor: { readonly providerUserId: string } | null
     /** Provider-native active tenant, if any (D1 decides its use). */
     readonly organizationId: string | null
     /** How the credential was presented (CAP-13). */
     readonly channel: 'cookie' | 'bearer' | 'api-key' | 'device'
   }
   ```

2. **Capabilities are declared, not discovered.**
   `IdentityProviderPort` gains `capabilities: ReadonlySet<Capability>`
   (`'magic-link' | 'email-otp' | 'passkey' | 'oauth' | 'one-tap' |
'phone' | 'anonymous' | 'mfa' | 'impersonation' |
'revoke-user-sessions'`) and one optional operation:
   `revokeUserSessions?(providerUserId)`. Plugin options that _need_ a
   capability fail at wiring with a new `UnsupportedCapabilityError`.
   An example is `policies: { requireMfaForRoles: ['admin'] }` against
   a provider without `'mfa'`. Behavior never silently degrades.

3. **The linking policy generalizes** in `ensureLinkedUser`. Today it
   links only on a verified email. It becomes a declared policy:
   verified email (default, unchanged), plus an opt-in verified phone
   (D2). Anonymous identities never link (D3). Refusal reasons stay
   typed (`UnverifiedEmailError`, plus `UnverifiedIdentityError`).

4. **Plugin-level `Session` and the `SessionUser` wire contract** gain
   optional `assurance`, `actor`, and `organizationId`, so server
   components and access functions can read them. These are additive
   optional fields: a minor version, with a migration note in
   `docs/upgrading.md`.

5. **A provider conformance kit** lives in core (test-only export,
   like `stub-provider`). It is one shared suite that every adapter
   runs:
   - session-shape narrowing
   - declared capabilities match behavior
   - verified-claim semantics
   - actor propagation
   - revoke semantics

   Both adapters must pass the same suite, which is how parity is
   proven rather than asserted.

## Support matrix (target)

Status per provider: **native** (the adapter maps the provider's own
mechanism), **recipe** (builder-owned, documented, and exercised by an
example plus e2e), **—** (unsupported; fails fast if a policy needs
it).

| Capability           | Better Auth                                                                                 | Auth.js                                                               | Core / plugin work                                                      |
| -------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| magic link           | native (`magicLink`)                                                                        | native (Email provider)                                               | `assurance.methods`                                                     |
| email OTP            | native (`emailOTP`)                                                                         | recipe (Email provider with a short-code `generateVerificationToken`) | rate-limit guidance (codes are brute-forceable)                         |
| OAuth / OIDC         | native (`genericOAuth`)                                                                     | native (providers), plus a **verified-email trust policy** (gap fix)  | D6 trust policy, mock-IdP e2e                                           |
| One Tap              | native (`oneTap`)                                                                           | recipe (Credentials provider verifying the Google ID token)           | none                                                                    |
| passkey              | native (`@better-auth/passkey`)                                                             | — (D7: upstream says not for production; Prisma-only)                 | `methods: ['passkey']`                                                  |
| 2FA / MFA            | native (`twoFactor`)                                                                        | — in v1 (D4: recipe later)                                            | `assurance.mfa`, `requireMfaForRoles` policy                            |
| phone number         | native (`phoneNumber`)                                                                      | — in v1 (D4)                                                          | `identity.phone`, phone link policy (D2)                                |
| anonymous            | native (`anonymous`)                                                                        | — in v1 (D4)                                                          | guest principal, never a Payload user (D3)                              |
| ban / suspend        | via Payload (the plugin owns it)                                                            | via Payload                                                           | Payload `suspendedUntil`, enforced at verify, plus `revokeUserSessions` |
| impersonation        | native (`admin`), surfaced as `actor`                                                       | — in v1 (D4)                                                          | `actor` on Session, audit log, access restriction (D5)                  |
| roles                | Payload `roles` (BA `admin.role` is not authoritative)                                      | Payload `roles`                                                       | docs: one role system                                                   |
| organizations        | D1                                                                                          | D1                                                                    | D1                                                                      |
| trust & linking      | config validated (`trustedProviders`, `requireEmailVerification`, `disableImplicitLinking`) | config validated (`allowDangerousEmailAccountLinking`)                | CAP-12: the gate holds whatever the provider config says                |
| non-browser sessions | multi-session, bearer, API key, device authorization                                        | bearer via `getToken` only                                            | CAP-13: `channel` on sessions, per-channel policy (D8)                  |
| identity lifecycle   | database hooks (email change, delete, verify)                                               | events (`updateUser`, `linkAccount`, `signOut`)                       | CAP-14: sync to Payload through `UserRepository` (D9)                   |
| enterprise SSO       | native (`@better-auth/sso`, SAML/OIDC, domain verification)                                 | via OAuth path (BoxyHQ SAML)                                          | CAP-15: domain-verified linking only, org-scoped (D1)                   |
| username             | native (`username`)                                                                         | —                                                                     | CAP-16: optional identifier; Payload `loginWithUsername`                |
| wallet (SIWE)        | native (`siwe`)                                                                             | —                                                                     | CAP-17: never links (placeholder emails), guest at most                 |
| abuse protection     | captcha, HIBP, rate limit (DB/secondary storage)                                            | builder-owned                                                         | CAP-18: declarations, trusted-proxy IP, guides                          |

## Per-capability design

Each subsection names the core facts, each adapter's mapping, the
security notes, and the proof.

### CAP-1 Magic link

- **BA:** `magicLink({ sendMagicLink })`; sessions arrive verified.
  Set `methods: ['magic-link']` where BA exposes the sign-in method;
  otherwise `'unknown'` (the conformance kit pins which).
- **Auth.js:** the Email provider on our adapter's verification
  tokens. Its database-strategy requirement interacts with the
  engine's Credentials/JWT rule, so the engine must allow Email +
  JWT, verified in a spike.
- **Security:** single-use tokens (both providers), a short expiry,
  and the token kept out of logs.
- **Proof:** the e2e captures the link from a dev-only mailbox (the
  `send*` callback writes it to a test sink, the same pattern as the
  `dev-auto-verify` route), follows it, gets a 200 from the session
  endpoint, and the Payload user exists. Runs for both providers on
  both frameworks.

### CAP-2 Email OTP

- **BA:** `emailOTP({ sendVerificationOTP })`, native, verified.
- **Auth.js:** recipe. An Email provider whose
  `generateVerificationToken` returns a 6-digit code; the form posts
  the code to `/callback/email`. A spike is needed to confirm the
  callback flow with codes.
- **Security:** codes are brute-forceable. The examples' rate limiter
  covers the verify path, with attempt caps per identifier. Document
  that this is builder-owned, like SEC-13.
- **Proof:** e2e sign-in via a captured code; a wrong code 3× then
  throttles (429).

### CAP-3 OAuth / OIDC (generic)

- **BA:** `genericOAuth`; `emailVerified` comes from the identity
  provider's `email_verified`.
- **Auth.js:** providers already work for sign-in, but new users get
  `emailVerified: null`, so the plugin refuses them. **Fix (D6):** an
  engine option
  `trustProviderEmailVerification: ['google', 'acme-oidc']`. For
  allow-listed providers only, an `events.linkAccount` /
  `signIn`-callback hook stamps `emailVerified` when the profile
  asserts `email_verified === true`. Never by default. Never for
  providers that don't assert it. Don't combine it with
  `allowDangerousEmailAccountLinking`; the guide must explain why.
- **Proof:** a **local mock OIDC provider** (e.g. `oidc-provider` as
  a Playwright `webServer`) drives a real authorization-code flow on
  both providers. It also closes the long-standing "no OAuth e2e" gap
  (TST-7 used a cross-provider stand-in). Cases: a verified claim
  links; an unverified one 401s; a non-allow-listed Auth.js provider
  401s.

### CAP-4 Google One Tap

- **BA:** `oneTap()`, native. `email_verified` comes from the Google
  ID token.
- **Auth.js:** recipe. A Credentials provider that verifies the Google
  ID token (JWKS, audience, issuer, expiry) and upserts the provider
  user. Credentials sessions are JWT-only, which the engine already
  enforces.
- **Proof:** unit tests with a locally signed ID token against a stub
  JWKS (no Google in CI). One Tap's browser UI isn't e2e-tested;
  that's documented as a limit.

### CAP-5 Passkeys

- **BA:** `passkey()` from `@better-auth/passkey` (a new optional
  dependency of the BA adapter), with a declared `passkey` model.
- **Auth.js:** unsupported (D7). Upstream calls its WebAuthn provider
  "experimental and not recommended for production use" and supports
  it only with `next-auth` and the Prisma adapter. Our adapter's
  authenticator methods stay (they're tested and harmless), but no
  passkey support ships for Auth.js until upstream declares it stable
  (risk R2).
- **Proof:** Playwright's **virtual authenticator** (CDP
  `WebAuthn.addVirtualAuthenticator`, Chromium only) covers register
  then sign in, with `methods: ['passkey']` on the session. Firefox
  and WebKit skip with a stated reason.

### CAP-6 Two-factor / MFA

- **BA:** `twoFactor()`. BA issues no session until the second factor
  passes, so `mfa` is true when the user has 2FA enabled
  (`twoFactorEnabled`). Trusted-device bypass sessions must still map
  to `mfa: true` only if BA marks them so; the spike verifies this.
- **Auth.js:** no native primitive. v1: unsupported (D4); a policy
  requiring MFA fails at wiring.
- **Plugin policy:** `policies.requireMfaForRoles: Role[]`, enforced
  in `access.ts` (admin panel and role-gated access). A session
  without `mfa: true` is treated as missing those roles, and the UI
  gets a typed `MfaRequiredError`.
- **Proof:** e2e enrolls TOTP (the secret is generated in the test
  from the enrollment response), signs in with the computed code, and
  the admin route is allowed; without MFA the admin route is denied.
  Wiring test: policy plus Auth.js throws `UnsupportedCapabilityError`.

### CAP-7 Ban / suspend (governance, provider-agnostic)

- **Plugin:** Payload `users.suspendedUntil` (or `suspended: true`)
  and `suspendReason`. The session service already reloads the
  Payload user on every request, so verify refuses suspended users
  for **every provider and every session strategy, including
  stateless JWTs**. That's stronger than provider-native bans.
- **Port:** optional `revokeUserSessions(providerUserId)`.
  - BA: delete the user's sessions via the internal adapter.
  - Auth.js database strategy: delete `aj-sessions` by user.
  - Auth.js JWT: none, and the Payload check covers it.

  A suspend hook (Payload `afterChange`) calls it best-effort and logs
  failures.

- **BA's `admin.banned`** is documented as optional and
  non-authoritative. If used, a BA ban also stops sessions, which is
  harmless redundancy.
- **Proof:** an integration test (suspend → next verify returns 401
  for both providers, including a JWT session), and e2e (an admin
  suspends a user in Payload; their next page load bounces).

### CAP-8 Impersonation (BA native, Payload-governed)

- **BA adapter:** maps `session.impersonatedBy` to
  `actor.providerUserId`. **Logout** also clears `admin_session`
  (added to `sessionCookieClearOptions` handling).
- **Plugin:** `Session.actor` is resolved to the actor's Payload user
  id. Every authenticated Payload operation while an actor is present
  is written to an audit log through `LoggerPort` (actor, target,
  operation, collection, id).
- **Access (D5):** `access.ts` gets
  `denyWhileImpersonating(ops)`. Default policy: the admin panel and
  role changes are denied while impersonating; reads are allowed.
- **Auth.js:** unsupported in v1 (D4).
- **Proof:** an integration test (BA impersonation → `actor` set → the
  role escalation attempt is denied → the audit log called), and e2e
  (stop impersonating restores the admin; logout clears both
  cookies).

### CAP-9 Phone number (BA native; identity extension)

- **Core:** `identity.phone`, a branded E.164 `PhoneNumber` via
  a smart constructor.
- **Linking (D2), recommended v1:** phone is a verified identifier
  that can _link_ to an existing Payload user whose phone matches, but
  Payload users still require an email. A phone-only BA sign-up stays
  refused with a typed `UnverifiedIdentityError` explaining why. This
  keeps Payload's auth collection valid (it needs an email unless the
  host enables `loginWithUsername`).
- **Auth.js:** unsupported in v1 (D4).
- **Proof:** a unit test of the linking policy; integration (BA
  phone OTP for a user with an email links; phone-only is refused with
  the typed error).

### CAP-10 Anonymous (BA native; guest principal)

- **Recommended (D3):** anonymous sessions are recognized as **guest
  principals**. The session endpoint returns
  `{ user: null, guest: { id } }`, and Payload authentication never
  happens (no Payload document, no Payload access). Upgrading to a
  real account goes through BA's `onLinkAccount`. The resulting
  verified session links normally.
- **Auth.js:** unsupported in v1 (D4).
- **Proof:** integration (an anonymous session returns guest, a
  Payload strategy returns null, and no user document is created),
  and e2e (guest → sign up → linked user).

### CAP-11 Organizations (decision D1)

- **Option A, recommended: Payload-owned tenancy.** The plugin adds
  optional `organizations` and `memberships` collections (role per
  org), plus `access.ts` helpers (`requireOrgRole`). It works with
  **both** providers. The active org is chosen in-app; the plugin
  stores no session state (invariant 1), so it travels as a request
  parameter or cookie the host owns. Invitations reuse the email
  capability (CAP-1).
- **Option B: BA-native.** The BA `organization` plugin stays the
  source of truth, and an `OrganizationPort` read model (BA adapter
  only) exposes membership to `access.ts`. It's BA-only and adds a
  second authorization source.
- **Today:** BA's organization plugin is storage-compatible but
  disconnected from Payload access. That stays documented as
  "provider feature, not Payload authorization" under either option.

### CAP-12 Trust & linking policy (cross-provider, security)

Both providers can link accounts by email on their own, and each has
settings that loosen it:

- **BA** links same-email OAuth sign-ins automatically when the
  provider says the email is verified **or** the provider is in
  `trustedProviders`. The docs warn this "may increase the risk of
  account takeover". Related settings: `allowDifferentEmails`,
  per-provider `requireEmailVerification` (off by default), and
  `disableImplicitLinking`.
- **Auth.js** links automatically only when the user is already
  signed in, unless `allowDangerousEmailAccountLinking` is set per
  provider. The docs say "Automatic account linking on sign in is not
  secure between arbitrary providers".

**Design:** the plugin's verified-email gate is the only authority for
_Payload_ linking, whatever the provider links internally. Both
engines validate their own config at wiring:

- Combinations that let an unverified email reach a session trip a
  loud `LoggerPort` warning naming the setting. Examples: BA
  `trustedProviders` without per-provider `requireEmailVerification`,
  and Auth.js `allowDangerousEmailAccountLinking`.
- An opt-in `strictLinking: true` turns those warnings into
  `InvalidConfigError`.
- BA's `updateUserInfoOnLink` never changes `email` or
  `emailVerified` (documented), so our gate keeps reading the true
  value.

**Proof:** engine unit tests per risky setting (warn by default, throw
under `strictLinking`), and an integration test where a
trusted-but-unverified provider session still 401s at the Payload
session endpoint.

### CAP-13 Sessions without a browser (channels)

Several provider features produce sessions that aren't a first-party
browser cookie:

- **BA multi-session:** several accounts per browser, with one
  `session_token_multi-*` cookie per login.
- **Bearer tokens:** BA `bearer`, Auth.js `getToken` on a Bearer
  header.
- **BA API-key mock sessions** (`enableSessionForAPIKeys`, user-owned
  keys only).
- **BA device-authorization tokens** (CLI or TV).
- **One-time tokens** (cross-domain hand-off).

Each breaks an assumption: CSRF-by-origin doesn't apply to bearer,
the "one session per browser" logout sweep misses multi-session
cookies, and an API key isn't a person.

**Design:**

- Adapters report the presentation as `channel` on `ProviderSession`.
- The plugin admits channels by policy:
  `admitChannels: ['cookie']` is the default. Opting in to `bearer` or
  `device` is explicit; `api-key` stays off unless D8 changes.
- BA multi-session: the logout sweep revokes every multi-session token
  presented (BA `revoke` per token) and expires its cookies. Precedence
  stays "the active session".

**Proof:** integration tests per channel (default-denied, then admitted
by policy), a multi-session logout test (every token revoked, every
cookie expired), and a CSRF unit test showing bearer requests skip the
origin check only when the channel is admitted.

### CAP-14 Identity lifecycle sync

Provider-side identity changes must reach Payload, or Payload drifts:

- **BA:** `changeEmail` (verification goes to the new address),
  `deleteUser`, and `emailVerified` flips. Since 1.7, a magic-link or
  OTP sign-in on an account whose email was never verified **deletes
  the unproven password and linked accounts and revokes sessions**.
  The password-reset default does _not_ revoke sessions
  (`revokeSessionsOnPasswordReset`).
- **Auth.js:** `updateUser` and `linkAccount` events. `unlinkAccount`
  and `deleteUser` are documented as "not invoked yet".

**Design:**

- Adapters translate provider hooks into one core
  **`IdentityEvent`** stream (`email-changed`, `email-verified`,
  `identity-unlinked`, `user-deleted`): BA `databaseHooks`,
  Auth.js `events`.
- The plugin applies events through `UserRepository` (`setEmail`
  already exists), so Payload stays the single user store
  (invariant 1).
- A deleted provider user unlinks the identity row. The Payload user
  remains, because Payload owns it (D9).
- The engines default `revokeSessionsOnPasswordReset: true` (BA),
  overridable and documented.

**Proof:** integration tests per event on real Payload, plus e2e for a
change of email (new address verified, then the Payload email
updated).

### CAP-15 Enterprise SSO (SAML / OIDC)

- **BA:** `@better-auth/sso` adds an `ssoProvider` table, plus domain
  verification. A provider is "trusted for automatic account linking"
  for its verified domain. With the organization plugin, org owners
  and admins can register IdPs at runtime. IdP-initiated SAML is off
  by default in 1.7.
- **Auth.js:** SAML only as OAuth via BoxyHQ, through the CAP-3 path.
- **Security:** a tenant-registered IdP can assert verified emails for
  anyone. **The plugin links SSO identities only for the IdP's
  verified domain**, and SSO registration is scoped to the D1
  Payload organization that owns the domain.
- **Proof:** the mock OIDC provider (CAP-3) registered as an SSO
  provider. A matching verified domain links; any other domain 401s.
- **Phase:** with tenancy (Phase 7), because it depends on D1.

### CAP-16 Username

- **BA:** `username` adds `user.username` and `user.displayUsername`
  (declared), and sign-in by username. Sign-up still requires an
  email, so the verified-email gate is unaffected.
- **Plugin:** an optional mapping to Payload's `loginWithUsername`,
  keeping one username source of truth (Payload), synced via CAP-14.
  Auth.js: unsupported.

### CAP-17 Wallet sign-in (SIWE)

- **BA:** `siwe` adds `walletAddress`. Users are anonymous by default
  with placeholder emails (`…@siwe.placeholder.invalid`), and a
  user-supplied email is stored **unverified**.
- **Plugin:** these sessions never link (the existing gate). The BA
  adapter also recognizes the placeholder domain and reports
  `identity.email: null`, so they are treated like anonymous
  (D3: a guest principal). Linking a wallet to an existing verified
  user waits for demand.

### CAP-18 Abuse protection

- **BA:** `captcha` (email/password routes unless more are listed),
  `haveIBeenPwned`, and built-in rate limiting with database-backed
  counters (a `rateLimit` table, which the adapter already supports) or
  secondary storage. IP comes from `X-Forwarded-For` unless
  `ipAddressHeaders` or `trustedProxies` is set (spoofable otherwise).
- **Auth.js:** no rate-limiting guidance in its docs. Builder-owned
  (SEC-13 precedent).
- **Plugin:** the examples' limiter and BA config share one
  trusted-proxy rule. The guides state the spoofing risk. The OTP and
  magic-link verify routes get per-identifier attempt caps.

## Steps

Each phase leaves `bun run check`, `release:check`, and all six e2e
suites green. Every item lands with its proof. Ordering puts security
and correctness first, then the core vocabulary everything else
needs, then capabilities by user value.

### Phase 0: Decisions + spikes

- ~~Resolve D1–D9~~ ✅ accepted 2026-10-12 (see Decisions).
- Spikes, each a throwaway branch with written findings:
  - S1: Auth.js Email provider under the engine's JWT rule.
  - S2: Auth.js email OTP via `generateVerificationToken` and
    `/callback/email`.
  - S3: how BA marks 2FA trusted-device sessions.
  - S4: whether BA exposes the sign-in method on a session.
  - ~~S5: Auth.js Passkey provider~~ dropped: upstream marks it not
    for production (see Provider landscape and D7).
  - S6: BA multi-session cookie names and per-token revoke from our
    logout path.
  - S7: whether the official Auth.js adapter test suite
    (`packages/utils/adapter.ts` in the next-auth repo) runs against
    our Payload adapter, and what fails.
- Exit: spike findings appended under Current state.

### Phase 1: Security gaps first

- **CAP-8 (actor surfacing + `admin_session` logout):** closes the
  impersonation audit hole even before the full vocabulary lands. This
  is the minimal `actor` field and the audit log.
- **CAP-3 Auth.js trust policy:** fixes the Auth.js OAuth refusal
  (correctness, not just a feature).
- **Commit the schema probe as a test:** every BA plugin in this plan
  (now including `username`, `siwe`, `sso`, `api-key`, `multi-session`
  and teams) has its declarations generated from `getAuthTables` and
  booted. A BA upgrade that changes any plugin schema fails CI.
- **CAP-12 trust & linking validation:** warnings, `strictLinking`,
  and the trusted-but-unverified 401 test.
- **Adapter conformance:** run the official Auth.js adapter suite
  (S7) and fix what it finds.

### Phase 2: Core vocabulary + conformance kit

- The `ProviderSession` claims/assurance/actor fields, `capabilities`,
  `UnsupportedCapabilityError`, and the generalized linking policy.
- The conformance kit, adopted by both adapters (existing behavior
  only).
- Wire contract: optional `assurance` / `actor` on `SessionUser`.
- `channel` with `admitChannels: ['cookie']` (CAP-13). Existing
  behaviour is unchanged, because both adapters already report only
  cookies.
- Exit: both adapters pass the kit; minor-version changeset; upgrade
  note.

### Phase 2b: Identity lifecycle (CAP-14)

- The `IdentityEvent` stream, BA `databaseHooks` and Auth.js `events`
  mapped, applied through `UserRepository`, and the
  `revokeSessionsOnPasswordReset` default.

### Phase 3: Passwordless (both providers) ✅ done

- CAP-1 magic link and CAP-2 email OTP, with the dev mailbox and
  e2e on both frameworks, plus CAP-18 attempt caps on their verify
  routes.

### Phase 4: Federation ✅ done

- CAP-3 generic OAuth with the mock OIDC provider (both providers),
  and CAP-4 One Tap (BA native, Auth.js recipe).

### Phase 5: Strong auth + governance ✅ done

- CAP-5 passkeys (BA; virtual authenticator), CAP-6 2FA with the
  `requireMfaForRoles` policy, CAP-7 ban/suspend, and CAP-13
  non-browser channels (multi-session logout, bearer and device
  opt-in).

### Phase 6: Identity extensions (decision-gated) ✅ done

- CAP-9 phone (D2), CAP-10 anonymous (D3), CAP-16 username, and
  CAP-17 SIWE as a guest principal.

### Phase 7: Tenancy (D1) ✅ done

- CAP-11 Payload-owned organizations (D1), then CAP-15 enterprise SSO
  scoped to verified org domains.

> **Status (Phases 3–7 landed):** wiring is documented in
> [guide-capabilities.md](guide-capabilities.md). Proofs: BA
> `capabilities.test.ts` / `oauth.test.ts` / `multi-session.test.ts`
> integration suites, Auth.js `oauth.test.ts` + `recipes.test.ts`,
> plugin `integration-organizations.test.ts`, and
> `e2e/passwordless.spec.ts` + `e2e/security.spec.ts` green on Next
> and TanStack Start. MFA mapped value is enrollment (S3); username
> stays provider-side with CAP-14 propagation; SIWE placeholder
> identities map to no email claim (guest at most).

## Validation Plan

- **Per adapter:** the conformance kit, plus each capability's
  integration tests on real Payload (SQLite in memory), as in
  `integration.test.ts`.
- **Per framework:** e2e for every user-facing capability on Next
  and TanStack Start, using local doubles only:
  - a mock OIDC provider
  - a dev mailbox / SMS sink (dev-only routes, gated like
    `dev-auto-verify`)
  - Playwright's virtual authenticator
  - TOTP computed in-test
- **Schema drift:** the committed probe (Phase 1) fails CI on any BA
  plugin schema change.
- **Release:** `release:check` and
  `verify:published --expect-provenance` on the minor that ships the
  vocabulary.

## Decisions (accepted 2026-10-12)

The builder accepted every recommendation (D1–D6, then D7–D9 after the docs review). These are now binding for
the phases below; changing one means a new dated entry here, not a
silent edit.

| ID  | Question                                                                          | Decision                                                                                                                                                                                                                                                                                                    |
| --- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | Who owns organizations?                                                           | **Payload collections** (`organizations`, `memberships`), working with both providers. One authorization source. BA's `organization` plugin stays a provider feature, never Payload authorization.                                                                                                          |
| D2  | Can phone-only identities become Payload users?                                   | **No, in v1.** A verified phone links to existing Payload users only; phone-only sign-ups are refused with `UnverifiedIdentityError`. Revisit with Payload `loginWithUsername`.                                                                                                                             |
| D3  | What is an anonymous session in Payload?                                          | **A guest principal**, never a Payload user and never Payload access. It links normally once upgraded to a verified identity.                                                                                                                                                                               |
| D4  | Auth.js parity for 2FA, phone, anonymous, impersonation                           | **Unsupported in v1.** A policy that needs one fails at wiring with `UnsupportedCapabilityError`. Recipes come later, only on demand.                                                                                                                                                                       |
| D5  | What may an impersonator do in Payload?                                           | **Configurable, default read-mostly.** The admin panel and role changes are denied while an actor is present; every operation is audited.                                                                                                                                                                   |
| D6  | Trust identity-provider `email_verified` in Auth.js?                              | **A per-provider allowlist**, off by default, explicit and auditable. An allow-listed provider asserting `email_verified: false` still 401s.                                                                                                                                                                |
| D7  | How much to invest in the Auth.js adapter now that Auth.js is part of Better Auth | **Maintenance tier** (accepted with D8–D9 on 2026-10-12). Email sign-in and OAuth/OIDC stay first-class with every correctness and security fix (CAP-3 trust policy, CAP-12, CAP-14 events). New and experimental capabilities (passkeys, …) are Better Auth-only. Revisit if upstream publishes a roadmap. |
| D8  | Which non-browser channels may reach Payload?                                     | **Opt-in per channel.** `cookie` by default; `bearer` and `device` explicit. `api-key` stays off until there's an API-principal design (keys aren't people).                                                                                                                                                |
| D9  | Who owns a user's email when the provider changes it?                             | **The provider, for verified changes only.** A verified change syncs to Payload via CAP-14. Provider deletion unlinks the identity; it never deletes the Payload user.                                                                                                                                      |

## Risks / Open Questions

- **R1 · BA plugin drift:** plugin schemas change across BA minors.
  Mitigation: the committed probe test (Phase 1) plus the strict
  adapter.
- **R2 · Auth.js WebAuthn is experimental:** upstream says "not
  recommended for production use", Prisma-only. Mitigation: no Auth.js
  passkeys (D7). Re-check the status on each `@auth/core` bump; the
  adapter's authenticator methods stay ready.
- **R3 · Assurance accuracy:** neither provider reliably records the
  sign-in method on every session. Mitigation: `'unknown'` is a
  first-class value, and policies treat unknown as not satisfied
  (fail closed).
- **R4 · Wire-contract growth:** new `SessionUser` fields must stay
  optional and versioned (pre-1.0 policy in `docs/upgrading.md`).
- **R5 · Brute force on codes (OTP, phone):** library-level throttling
  is builder-owned (SEC-13 precedent). The examples ship the limiter,
  and the guides state the requirement.
- **R6 · The security posture of Auth.js email trust:** a
  mis-allow-listed provider that doesn't verify emails enables account
  takeover via linking. Mitigation: off by default, an explicit
  per-provider list, and a guide warning, plus a test where an
  allow-listed provider with `email_verified: false` still 401s.

- **R7 · Auth.js upstream status:** Auth.js is now part of Better
  Auth, with fixes on latest only and no published roadmap.
  Mitigation: D7 maintenance tier, Better Auth as primary, pin
  `@auth/core`, and watch for a deprecation notice.
- **R8 · Better Auth minor-version behaviour changes:** 1.7 changed
  magic-link/OTP behaviour on unverified accounts (deletes the
  unproven password and accounts, revokes sessions). Some 1.7.0–1.7.2
  databases also have an `account.issuer` column needing relaxation.
  Mitigation: the committed schema probe, CAP-14 events, and reading
  BA upgrade guides before each bump.
- **R9 · Email-scanner prefetch of magic links:** Auth.js docs say
  nothing about link prefetching by mail scanners. Mitigation: a
  confirm-page pattern (GET shows a button, POST consumes the token),
  tested in CAP-1.

## Non-goals

- Building auth primitives the chosen provider lacks (no homemade
  TOTP or WebAuthn ceremony in the plugin). Provider-owned or
  unsupported.
- A plugin-owned session store of any kind (invariant 1).
- SMS or email delivery: senders stay builder callbacks; the examples
  use dev sinks.
- WorkOS / Clerk adapters: their ids stay reserved, and they adopt the
  same vocabulary when they land.
- **Better Auth as an identity provider:** OAuth 2.1 Provider, MCP,
  CIMD, and Agent Auth make the _app_ an IdP for others. That's a
  different product.
- **SCIM directory provisioning:** it writes users from a directory,
  which conflicts with "Payload owns the users" unless it is
  re-designed to write through Payload.
- **Payments and infrastructure plugins** (Stripe, Polar, Autumn,
  Dodo, Creem, Chargebee, Commet, Dub, `@better-auth/infra`), i18n,
  OpenAPI, and telemetry: no identity impact.
- **BA `test-utils` in production:** test-only privileged helpers.
  They may be useful in our own suites, never shipped.

## Sources

- Better Auth plugin docs: organization, admin, anonymous,
  phone-number, magic-link, email-otp, passkey, generic-oauth,
  one-tap, 2fa (better-auth.com/docs/plugins/\*).
- Better Auth 1.7.7 source: `plugins/anonymous` (`emailVerified:
false`, `isAnonymous`), `plugins/phone-number/routes`
  (`getTempEmail` sign-up), `plugins/admin` (`impersonatedBy`,
  `admin_session`), `plugins/two-factor`, `plugins/generic-oauth`
  (`email_verified`), `plugins/one-tap`.
- `@auth/core` 0.41.3 source: `lib/actions/callback/handle-login.js`
  (Email sign-in stamps `emailVerified`; new OAuth users get `null`),
  `providers/` (Email family, `passkey`, `webauthn`, OIDC),
  `lib/utils/assert.js` (`enableWebAuthn`).
- Docs review 2026-10-12, Better Auth: concepts/users-accounts
  (account linking, `trustedProviders`), concepts/oauth
  (`requireEmailVerification`), concepts/session-management (cookie
  cache, `freshAge`), concepts/email, plugins/{multi-session, bearer,
  api-key, sso, username, siwe, jwt, one-time-token,
  device-authorization, captcha, have-i-been-pwned,
  last-login-method}, concepts/rate-limit, reference/security,
  guides/1-7-upgrade-guide.
- Docs review 2026-10-12, Auth.js: authjs.dev (home: "now part of
  Better Auth"), getting-started/authentication/webauthn
  ("experimental and not recommended for production use"),
  concepts/session-strategies, concepts/database-models (account
  linking), reference/core (callbacks, events), reference/core/providers
  (`checks`, `profile()`, `allowDangerousEmailAccountLinking`),
  reference/core/providers/email, guides/creating-a-database-adapter
  (adapter test suite), guides/refresh-token-rotation,
  guides/edge-compatibility, guides/debugging, guides/testing,
  getting-started/deployment (`trustHost`, `AUTH_SECRET` rotation).
- In-repo: `packages/provider-better-auth/src/adapter.ts`
  (`validateSchema`), `packages/provider-authjs/src/adapter.ts`
  (verification tokens, authenticators), `packages/core/src/ports.ts`
  (`ProviderSession`), `packages/core/src/http.ts` (`SessionUser`),
  `docs/SPRINT.md` (SEC-2, SEC-13, TST-7).
