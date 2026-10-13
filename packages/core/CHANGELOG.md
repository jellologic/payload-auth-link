# @payload-auth-link/core

## 0.4.0

### Minor Changes

- [#28](https://github.com/jellologic/payload-auth-link/pull/28) [`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008) Thanks [@jellologic](https://github.com/jellologic)! - The plugin is audible by default (issue [#15](https://github.com/jellologic/payload-auth-link/issues/15)): `authLink({ logger })`
  now defaults to a **console logger** instead of the silent one, so
  session refusals (expired, channel not admitted, suspended,
  provider errors, a session-shaped cookie that resolves to nothing)
  and the impersonation audit actually land somewhere without
  configuration. `nullLogger()` remains the explicit opt-out.

  - Core adds `consoleLogger()` (info/warn/error to the matching
    console level, fields as a JSON suffix, debug stays silent) and
    `isSilentLogger()`.
  - New `onAudit` option: a durable sink called with every
    impersonation audit event, in addition to the logger — "audited"
    should survive log rotation. With an impersonation-capable
    provider, a silent logger, and no `onAudit`, the plugin warns once
    at startup through the console that audit events are being
    dropped.
  - The per-request "verification failed: invalid session" residue
    (every anonymous request) moved to debug level; every actionable
    refusal keeps its warning with reason, provider, and channel.
  - README's impersonation row now says what auditing means.

  Upgrade impact: default-behaviour change — servers will print
  warnings for refused sessions by default. Pass
  `logger: nullLogger()` to restore silence; pass `onAudit` to make
  the impersonation audit durable.

## 0.3.0

### Minor Changes

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Version-range honesty (upgrade-resilience Phase 1): declared ranges
  now equal the CI-tested bands, and unvalidated upstreams fail at
  boot, typed, before any database write.

  - **`better-auth` and `@auth/core` are peer dependencies.** The
    providers no longer install them transitively; install the version
    you configure (validated bands: `better-auth >=1.7.6 <1.8.0`,
    `@auth/core >=0.41.0 <0.42.0`). Floors are bisected: BA 1.7.6
    (adapter `modelKey` types), @auth/core 0.41.0.
  - **`payload` peers tighten to `^3.83.0 || 4.0.0-beta.0`** (3.83.0
    is the named-plugin/global-hook floor; the v4 entry is the exact
    tested beta — canaries were silently inside the old caret). The
    plugin's runtime band matches the manifest.
  - **Framework peers get honest floors**: `next` `^15.0.0 || ^16.0.0`
    (both majors typechecked, 16.4 e2e-tested), TanStack Start
    `^1.140.2` (first `createMiddleware` types) with react-router
    `^1.170.0`.
  - **Runtime assertions at wiring time**: the providers check their
    upstream's installed version (`supportedBetterAuthBand`,
    `supportedAuthJsBand`, `assertBetterAuthVersion`,
    `assertAuthJsCoreVersion` exported; core adds
    `readInstalledVersion`) and throw `UnsupportedVersionError`
    before any collection write; unreadable manifests warn once and
    skip, never guess.
  - CI: a scheduled/dispatchable `compat` workflow proves
    {floor, latest} per upstream plus the golden Postgres/Mongo
    upgrade tests, with a non-blocking canary for drift; dependabot
    keeps installed versions moving as reviewed PRs.

  Upgrade impact: none for the database. Install-level: add explicit
  `better-auth` / `@auth/core` installs when adopting the providers
  (the READMEs show the lines); payload below 3.83.0 and prerelease
  payload canaries are no longer accepted. See docs/upgrading.md
  § 0.2.x → 0.3.0.

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Type-safe upgrade alarms and schema interoperability (upgrade-resilience Phase 3b):

  - Core: `authMethods` exported as the single source for `AuthMethod` and the session wire enum; `sessionChannels` is now a const tuple with `SessionChannel` derived from it; `LinkingPolicy` derives from `linkingPolicySchema`. Union/schema drift now fails typecheck instead of degrading sessions at runtime.
  - Core: `parseSessionUser` accepts `ParseSessionUserOptions.onDegrade` with a typed `SessionUserDegradeReason`, so producer/consumer version skew (e.g. an unknown auth method from a newer server) is observable instead of silent. Default behavior is unchanged.
  - Core: every exported Zod schema is pinned as a Standard Schema v1 (`@standard-schema/spec` added); Zod and Effect Schema compose through `~standard`. Effect interop is covered by a CI test with `effect` as a devDependency only. The `zod: ^4.0.0` floor and a consumer TypeScript floor of 5.5 are now probe-proven and documented.
  - Plugin: stored-row mapping warnings aggregate once per kind per logger instead of once per corrupt row.
  - Better Auth provider: exhaustive `assertNever` guards on custom-field types and where operators, so new upstream variants fail CI typecheck.
  - Repo gates: public-API `.d.ts` snapshots (`bun run api:check`) and a `skipLibCheck: false` consumer fixture (`bun run consumer:check`) now run in `bun run check`.

## 0.2.0

### Minor Changes

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Channel admission (CAP-13a) and impersonation completion (CAP-8b).

  - The plugin gains `admitChannels` (default `['cookie']`): a live
    provider session presented on a non-admitted channel (`bearer`,
    `api-key`, `device`) is refused at verification with the new typed
    `ChannelNotAdmittedError` (401) before any linking, and
    verification stops at the presenting provider. Channels are
    observed, not asserted: Better Auth reports `'bearer'` when the
    session arrives via an `Authorization: Bearer [REDACTED]` header without
    the session cookie (denied by the default policy), and Auth.js
    reports `'cookie'` because it only reads cookie-presented
    sessions. CSRF is unchanged in this phase.
  - `Session.actor` / `SessionUser.actor` are now the resolved
    `ResolvedSessionActor` discriminated union: `payload-user` (with
    the operator's Payload `userId`, resolved through
    `UserRepository.findByProviderIdentity`) or `provider-only` (no
    linked Payload user — fail-closed: still audited and restricted,
    never presented as a Payload id, logged as a warning).
    `parseSessionUser` accepts the legacy `{ providerUserId }` form
    and normalizes it to `provider-only`; `ProviderSession.actor`
    keeps the provider form.
  - Every authenticated Payload collection/global operation performed
    while impersonating is audit-logged through `LoggerPort`
    (`impersonated operation`: actor, target, operation,
    collection/global, document id) via plugin-installed
    `beforeOperation` hooks, so denied attempts are audited too.
  - Default impersonation restrictions (D5): the plugin denies
    admin-panel access and roles-field writes on the users collection
    while an actor is present (reads allowed), and exports
    `denyWhileImpersonating(ops?)`, the fail-closed
    `isImpersonating(req)` / `impersonationStateFromRequest(req)`
    server extraction (a present-but-malformed `actor` still denies
    and audits; authorization never routes through the client wire
    parser), plus `impersonationActorFromRequest` for attribution, so
    builders can apply the same default — deny admin and writes,
    allow reads — to their own collections.

  See `docs/upgrading.md`.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - CAP-14 identity lifecycle foundation: core `IdentityEvent` union and
  `applyIdentityEvent` use-case. Verified provider email changes sync to
  Payload (D9); unverified changes are ignored. Provider unlink/delete
  removes only the identity row via the new required
  `UserRepository.unlinkIdentity` — the Payload user always remains.
  Adapters may expose `IdentityProviderPort.onIdentityEvent`; the plugin
  subscribes at `onInit`. Custom `UserRepository` implementations must
  add `unlinkIdentity` (pre-1.0 minor break for port implementers).

  Both provider adapters now translate lifecycle hooks: Better Auth
  `databaseHooks` (user update/delete, account delete; builder hooks
  preserved, plus `revokeSessionsOnPasswordReset` defaults on) and
  Auth.js `events` (`updateUser`, `linkAccount` — upstream never fires
  unlink/delete events, so Auth.js emits no unlink/delete facts).

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Impersonation audit hole closed (CAP-8a): Better Auth's
  `session.impersonatedBy` now reaches the port as the new optional
  `ProviderSession.actor` (`{ providerUserId }`, `null` for plain
  sessions; Auth.js always reports `null`), the plugin audit-logs every
  verified use of an impersonated session through `LoggerPort` with the
  operator and target ids, and plugin logout also expires Better Auth's
  `admin_session` cookie via the new optional `logoutCookieNames` port
  field (`getBetterAuthLogoutCookieNames`). All additions are optional
  and backward compatible.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Capabilities Phases 3–7 (PLAN-CAPABILITIES): passwordless, OAuth,
  passkeys, MFA policy, suspend, phone, guests, organizations, SSO.

  Core: session-policy primitives (`effectiveRoles`, `mfaSatisfied`,
  `isSuspendedAt`, `emailDomainAllowed`), `UserSuspendedError`,
  `UserRecord.phone`/`suspendedUntil`, guest principals and their wire
  envelope (`SessionGuest`), verified-phone linking fallback for
  placeholder-email sign-ups, and optional multi-session port methods.

  Plugin: `policies.requireMfaForRoles` (roles withheld without MFA
  proof, `mfaRequired` on the wire), governance fields (`phone`,
  `suspendedUntil`, `suspendReason`) with verify-time suspension and
  best-effort provider revocation, `verified-email-or-phone` linking
  wired end to end (`findByPhone`/`setPhone`), guest sessions on the
  session endpoint, Payload-owned organizations (`organizations:
{ enabled: true }` — collections, manager access, invite/accept
  endpoints, `requireOrgRole`), SSO verified-domain enforcement
  (`organizations.ssoProviders`), multi-session logout sweep, and
  channel-aware CSRF (admitted bearer skips the origin check).

  Better Auth: capabilities derived from installed plugins
  (magic-link, email-otp, oauth, one-tap, passkey, mfa, phone,
  anonymous), phone and placeholder-email claim mapping (SIWE and
  anonymous identities are guests, never email claims),
  `revokeUserSessions`, multi-session enumeration for logout, and a
  fix: `ba-users.name` no longer rejects the empty-string names
  Better Auth's passwordless flows create.

  Auth.js: capabilities derived from configured providers (email →
  magic-link, oauth/oidc → oauth, database sessions →
  revoke-user-sessions, implemented for the database strategy), plus
  CAP-2/CAP-4 recipes — `generateEmailOtpCode`,
  `buildEmailOtpCallbackUrl`, `verifyGoogleIdToken`, and
  `createGoogleOneTapAuthorize`.

  React/web: `guest` on the auth context with `fetchSession`,
  `requireRoles({ requireMfa: true })` throwing typed
  `MfaRequiredError` (including for withheld-role step-ups).

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Core session vocabulary and declared capabilities (PORT-1/PORT-2):
  `ProviderSession` now carries `identity` claims
  (`VerifiedClaim<Email>`/`VerifiedClaim<PhoneNumber>` plus `anonymous`),
  `assurance` (`methods`/`mfa`, `'unknown'` when the provider cannot
  tell), a required `actor`, `organizationId`, and a `channel`
  (`'cookie' | 'bearer' | 'api-key' | 'device'`; one-time tokens present
  as `bearer`, there is no `'one-time'` channel). The flat
  `email`/`emailVerified` fields remain as deprecated aliases of the
  email claim for one minor, and linking now reads the claim. Core adds
  the branded E.164 `PhoneNumber` with `parsePhoneNumber`, plus
  `UnsupportedCapabilityError`, `UnverifiedIdentityError`, and
  `MfaRequiredError`. `IdentityProviderPort` gains a required
  `capabilities: ReadonlySet<Capability>` and an optional
  `revokeUserSessions`. **Breaking for custom adapters (compile
  time):** existing `IdentityProviderPort`/`ProviderSession`
  implementations will not compile until they declare `capabilities`
  and return the new required session fields (`identity`,
  `assurance`, `actor`, `organizationId`, `channel`). This ships as a
  minor under the pre-1.0 policy in `docs/upgrading.md` (minors may
  break option shapes and internal ports; the wire contract is the
  stability anchor). Core also adds `assertCapabilities(provider,
required)`, which throws `UnsupportedCapabilityError` at wiring when
  a capability a policy needs is undeclared, and the plugin enforces
  it (e.g. a phone linking policy requires `'phone'`). Better
  Auth fills the email claim, `mfa` from `user.twoFactorEnabled` when
  declared (else `'unknown'`), `organizationId` from
  `session.activeOrganizationId` when declared (else `null`), declares
  `'impersonation'` only when the Better Auth admin plugin is
  actually installed (observed `channel`: `'bearer'` for
  Authorization-header presentation without the session cookie, else
  `'cookie'`), and reports `methods: 'unknown'` (no per-session
  method upstream). Auth.js fills the email claim with `methods`/`mfa`
  `'unknown'` and declares no capabilities yet.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Generalized linking policy (PORT-3): core adds a declared
  `LinkingPolicy` discriminated union (`verified-email`, the default,
  plus opt-in `verified-email-or-phone`) with `defaultLinkingPolicy`, a
  strict `linkingPolicySchema`, and `parseLinkingPolicy`.
  `ensureLinkedUser` accepts an optional `linkingPolicy`; omitted or
  `verified-email` preserves the previous verified-email behavior
  exactly. The opt-in branch links a phone-only identity carrying a
  verified phone claim to an _existing_ user resolved through the new
  optional `UserRepository.findByPhone` port method — it never
  provisions, and every phone-only refusal is
  `UnverifiedIdentityError`. Anonymous identities never link under any
  policy — intentionally including when the identity was previously
  linked (D3): the anonymous gate runs before the already-linked fast
  path, so an anonymous session for a linked identity is refused, not
  verified. The plugin accepts a validated `linkingPolicy` option and
  passes it through to the session service; `verified-email-or-phone`
  additionally requires every registered provider to declare the
  `'phone'` capability (PORT-2 `assertCapabilities`, enforced at
  wiring) and currently fails fast at wiring because the Payload users
  collection has no phone field (and the repository no `findByPhone`)
  until CAP-9.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Session wire contract gains optional facts (PORT-4): plugin-level
  `Session` and the `SessionUser` wire shape now carry optional
  `assurance` (`methods`/`mfa`), `actor` (`{ providerUserId }`, only
  while impersonating), and `organizationId` (only when a
  provider-native tenant is active). The plugin projects them from the
  provider session onto the session endpoint response and the Payload
  auth strategy user; the web verifier and `require*` helpers and the
  React provider pass them through. Back-compatible by construction:
  payloads without the fields still parse, producers omit a field
  unless it is known, and a reported `assurance` serializes even when
  its values are `'unknown'` — consumers must treat absent and
  `'unknown'` alike as not satisfied (fail closed). The client wire
  parser is forward-compatible: unknown keys inside
  `assurance`/`actor` are ignored and a present-but-malformed
  optional degrades fail-closed-for-policy (`assurance` to
  `'unknown'`, `actor`/`organizationId` to absent) instead of failing
  the whole user, while core identity fields stay strict. Server-side
  authorization/audit never use that parser: the plugin's fail-closed
  server extraction treats a present-but-malformed `actor` on
  `req.user` as impersonating (deny + audit). See `docs/upgrading.md`.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Add the provider conformance kit at the new test-only subpath export `@payload-auth-link/core/testing` (PORT-5): `assertProviderConformance` / `checkProviderConformance` take a port factory plus scenario drivers and assert session-shape narrowing and verified-claim semantics (including the deprecated `email`/`emailVerified` aliases matching the claim), declared capabilities matching behavior (`revokeUserSessions` exists iff `'revoke-user-sessions'` is declared, declared `'impersonation'`/`'mfa'` must be observable), actor propagation, channel reporting, and revoke semantics — with an explicit `best-effort` revoke mode for stateless JWT transports. It is framework- and test-framework-free, re-validates sessions at runtime, and both provider adapters now run it in their test suites. No runtime behavior changes.

## 0.1.1

### Patch Changes

- [#4](https://github.com/jellologic/payload-auth-link/pull/4) [`04f8e49`](https://github.com/jellologic/payload-auth-link/commit/04f8e49d79567d3e85b7d34cb91e840f7d9efd74) Thanks [@jellologic](https://github.com/jellologic)! - Packaging fixes found by verifying 0.1.0 from a clean consumer install:

  - next: `dist` imported `next/headers`, `next/navigation` and
    `next/server` without `.js`, so the adapter crashed under plain
    Node ESM (`ERR_MODULE_NOT_FOUND`). The imports now carry `.js`, and
    lint enforces it.
  - plugin: `@payload-auth-link/plugin/admin` imports `@payloadcms/ui`
    but never declared it. It is now an optional peer dependency (only
    the `/admin` subpath needs it, and Payload apps already have it).
  - all: compiled tests (`dist/**/__tests__`) no longer ship in the
    tarballs (0.1.0 `core` carried 56 test files).
  - all: every package now ships a README, so its npm page explains the
    package, install line with peers, exports, and guides instead of
    "No README data found!".

  This is the first release CI publishes through npm trusted publishing,
  with provenance.

## 0.1.0

### Minor Changes

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8) Thanks [@jellologic](https://github.com/jellologic)! - Close the low-severity review backlog. Every change fails closed; see
  docs/upgrading.md.

  - core: `safeRedirectPath` moves to core with a destination policy
    that refuses the sign-in page and `/api` (`SafeRedirectOptions`).
    New exports: `isCookieName` and `SafeRedirectOptions`. Cookie
    `Domain`/`Path` values that could inject attributes or split
    headers throw. Provider registration rejects illegal session cookie
    names. `validateStartupConfig` drops the unused `secret`.
  - plugin: `secret` is deprecated and ignored. An empty provider
    session id is a 401, not a 500. Logout already sweeps every
    provider (PAR-7).
  - web: `requireRoles` validates its roles (`InvalidRoleError`, and
    `InvalidConfigError` for an empty list). It re-exports
    `SafeRedirectOptions`.
  - react: `SignOutButton` narrows `redirectTo`. `AuthLinkProvider`
    syncs a changed `initialUser` (value-compared, so a client sign-out
    is never undone by an equal snapshot).
  - next, tanstack-start: re-export the whole web surface through one
    shared statement, so adapters cannot drift (now includes
    `SafeRedirectOptions`).
  - provider-authjs: `authorize` lowercases the email. A corrupt
    `emailVerified` throws `AdapterMappingError`. Gapped session chunk
    sets are malformed.
  - provider-better-auth: adapter rows assert `baId` and date fields,
    and throw `AdapterOperationError` on storage drift.

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085) Thanks [@jellologic](https://github.com/jellologic)! - Enterprise review hardening.

  Security fixes:

  - Logout now expires session cookies with their live attributes
    (`Secure`, `Domain`, `Path`) reported by each provider through the
    new optional `IdentityProviderPort.sessionCookieClearOptions` hook,
    so `__Secure-` and custom-domain cookies actually die. Providers
    that predate the hook fall back to prefix-derived attributes
    (`expiringCookieOptions`).
  - New `safeRedirectPath` guard in `@payload-auth-link/next`: the
    post-login `redirect` param is attacker-controlled input and must
    never reach the router unvalidated (open redirect).
  - New server authorization helpers `requireSessionUser` /
    `requireRoles` in `@payload-auth-link/next` (throw
    `SessionInvalidError` / `ForbiddenError` by default; pass
    `redirect()` / `notFound()` as handlers). `RequireRoles` is
    UI-hiding only and must never gate content.
  - Auth.js credentials `authorize` burns a dummy scrypt verification
    for unknown emails and hashless rows, closing the
    user-enumeration timing oracle.
  - Session reads anchor to the configured `baseUrl`/`AUTH_URL` origin
    whenever set; the request-host fallback is local-development only
    (host headers are client-spoofable and session cookies are
    forwarded to that origin).

  Strictness and consistency:

  - Better Auth `AdapterOperationError` now extends `AuthLinkError`
    (code `ADAPTER_OPERATION_FAILED`) like its Auth.js twin; it moved
    from `adapter.js` to `errors.js` (barrel import unchanged).
  - Slug overrides validate at wiring time in both providers
    (`resolveSlugs`: non-empty, known models) and collections reject
    slug collisions (`assertUniqueSlugs`), including custom-model
    slugs against core slugs; new `customModelSlug` helper.
  - Shared core building blocks replace nine local copies:
    `isRecord` / `isNonEmptyString` / `toDate` guards,
    `runProviderOperation` port-call wrapper, `denyAllAccess` system
    collection default, `secureCookiePrefix` / `hostCookiePrefix`
    constants. The Edge-safe `/cookies` subpaths keep local literals
    (runtime-import-free) pinned to core by tests.
  - `CookieOptions` gains `partitioned`; `SessionVerifier` is now a
    named export.
