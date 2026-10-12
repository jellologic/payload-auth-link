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
ForwardEmail), an experimental Passkey/WebAuthn provider (behind
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

| Capability    | Better Auth                                            | Auth.js                                                               | Core / plugin work                                                      |
| ------------- | ------------------------------------------------------ | --------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| magic link    | native (`magicLink`)                                   | native (Email provider)                                               | `assurance.methods`                                                     |
| email OTP     | native (`emailOTP`)                                    | recipe (Email provider with a short-code `generateVerificationToken`) | rate-limit guidance (codes are brute-forceable)                         |
| OAuth / OIDC  | native (`genericOAuth`)                                | native (providers), plus a **verified-email trust policy** (gap fix)  | D6 trust policy, mock-IdP e2e                                           |
| One Tap       | native (`oneTap`)                                      | recipe (Credentials provider verifying the Google ID token)           | none                                                                    |
| passkey       | native (`@better-auth/passkey`)                        | native, experimental (Passkey provider, `enableWebAuthn`)             | `methods: ['passkey']`                                                  |
| 2FA / MFA     | native (`twoFactor`)                                   | — in v1 (D4: recipe later)                                            | `assurance.mfa`, `requireMfaForRoles` policy                            |
| phone number  | native (`phoneNumber`)                                 | — in v1 (D4)                                                          | `identity.phone`, phone link policy (D2)                                |
| anonymous     | native (`anonymous`)                                   | — in v1 (D4)                                                          | guest principal, never a Payload user (D3)                              |
| ban / suspend | via Payload (the plugin owns it)                       | via Payload                                                           | Payload `suspendedUntil`, enforced at verify, plus `revokeUserSessions` |
| impersonation | native (`admin`), surfaced as `actor`                  | — in v1 (D4)                                                          | `actor` on Session, audit log, access restriction (D5)                  |
| roles         | Payload `roles` (BA `admin.role` is not authoritative) | Payload `roles`                                                       | docs: one role system                                                   |
| organizations | D1                                                     | D1                                                                    | D1                                                                      |

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
- **Auth.js:** the Passkey provider with
  `experimental.enableWebAuthn`, using our adapter's existing
  authenticator methods. The plan must track Auth.js's experimental
  status (risk R2).
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

## Steps

Each phase leaves `bun run check`, `release:check`, and all six e2e
suites green. Every item lands with its proof. Ordering puts security
and correctness first, then the core vocabulary everything else
needs, then capabilities by user value.

### Phase 0: Decisions + spikes

- Resolve D1–D6 below (the builder's call).
- Spikes, each a throwaway branch with written findings:
  - S1: Auth.js Email provider under the engine's JWT rule.
  - S2: Auth.js email OTP via `generateVerificationToken` and
    `/callback/email`.
  - S3: how BA marks 2FA trusted-device sessions.
  - S4: whether BA exposes the sign-in method on a session.
  - S5: Auth.js Passkey provider on our adapter (experimental flag,
    authenticator round-trip).
- Exit: decisions recorded here; spike findings appended under
  Evidence.

### Phase 1: Security gaps first

- **CAP-8 (actor surfacing + `admin_session` logout):** closes the
  impersonation audit hole even before the full vocabulary lands. This
  is the minimal `actor` field and the audit log.
- **CAP-3 Auth.js trust policy:** fixes the Auth.js OAuth refusal
  (correctness, not just a feature).
- **Commit the schema probe as a test:** all 10 BA plugins'
  declarations are generated from `getAuthTables` and booted. A BA
  upgrade that changes any plugin schema fails CI.

### Phase 2: Core vocabulary + conformance kit

- The `ProviderSession` claims/assurance/actor fields, `capabilities`,
  `UnsupportedCapabilityError`, and the generalized linking policy.
- The conformance kit, adopted by both adapters (existing behavior
  only).
- Wire contract: optional `assurance` / `actor` on `SessionUser`.
- Exit: both adapters pass the kit; minor-version changeset; upgrade
  note.

### Phase 3: Passwordless (both providers)

- CAP-1 magic link and CAP-2 email OTP, with the dev mailbox and
  e2e on both frameworks.

### Phase 4: Federation

- CAP-3 generic OAuth with the mock OIDC provider (both providers),
  and CAP-4 One Tap (BA native, Auth.js recipe).

### Phase 5: Strong auth + governance

- CAP-5 passkeys (virtual authenticator), CAP-6 2FA with the
  `requireMfaForRoles` policy, and CAP-7 ban/suspend.

### Phase 6: Identity extensions (decision-gated)

- CAP-9 phone (D2) and CAP-10 anonymous (D3).

### Phase 7: Tenancy (D1)

- CAP-11 per the chosen option.

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

## Decisions needed

| ID  | Question                                                | Options                                                                               | Recommendation                                                                                                                                                            |
| --- | ------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | Who owns organizations?                                 | A: Payload collections (both providers) · B: BA plugin + `OrganizationPort` (BA only) | **A**: Payload owns users, so it owns membership; one authorization source                                                                                                |
| D2  | Can phone-only identities become Payload users?         | Yes (Payload users without email) · No (phone links to existing users only)           | **No** in v1: keeps Payload's auth collection valid; revisit with `loginWithUsername`                                                                                     |
| D3  | What is an anonymous session in Payload?                | A guest principal (no Payload user) · A real Payload user                             | **Guest principal**: no unverified identities in Payload                                                                                                                  |
| D4  | Auth.js parity for 2FA, phone, anonymous, impersonation | Native (build our own on Auth.js) · Recipe · Unsupported in v1                        | **Unsupported in v1** with fail-fast wiring; recipes later if demand appears. Auth.js has no primitives for these, and building them means owning security-critical state |
| D5  | What may an impersonator do in Payload?                 | Everything (audited) · Read-mostly (deny admin panel and role changes) · Configurable | **Configurable, default read-mostly**                                                                                                                                     |
| D6  | Trust identity-provider `email_verified` in Auth.js?    | Never · Per-provider allowlist · Always                                               | **Per-provider allowlist**: explicit, auditable, off by default                                                                                                           |

## Risks / Open Questions

- **R1 · BA plugin drift:** plugin schemas change across BA minors.
  Mitigation: the committed probe test (Phase 1) plus the strict
  adapter.
- **R2 · Auth.js WebAuthn is experimental:** the API may change.
  Mitigation: pin, gate behind the flag, and keep passkeys documented
  as experimental on Auth.js.
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

## Non-goals

- Building auth primitives the chosen provider lacks (no homemade
  TOTP or WebAuthn ceremony in the plugin). Provider-owned or
  unsupported.
- A plugin-owned session store of any kind (invariant 1).
- SMS or email delivery: senders stay builder callbacks; the examples
  use dev sinks.
- WorkOS / Clerk adapters: their ids stay reserved, and they adopt the
  same vocabulary when they land.

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
- In-repo: `packages/provider-better-auth/src/adapter.ts`
  (`validateSchema`), `packages/provider-authjs/src/adapter.ts`
  (verification tokens, authenticators), `packages/core/src/ports.ts`
  (`ProviderSession`), `packages/core/src/http.ts` (`SessionUser`),
  `docs/SPRINT.md` (SEC-2, SEC-13, TST-7).
