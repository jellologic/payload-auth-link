# @payload-auth-link/react

## 0.2.2

### Patch Changes

- Updated dependencies [[`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008)]:
  - @payload-auth-link/core@0.4.0

## 0.2.1

### Patch Changes

- Updated dependencies [[`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd), [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd)]:
  - @payload-auth-link/core@0.3.0

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

### Patch Changes

- Updated dependencies [[`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4)]:
  - @payload-auth-link/core@0.2.0

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

- Updated dependencies [[`04f8e49`](https://github.com/jellologic/payload-auth-link/commit/04f8e49d79567d3e85b7d34cb91e840f7d9efd74)]:
  - @payload-auth-link/core@0.1.1

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

### Patch Changes

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

- Updated dependencies [[`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085)]:
  - @payload-auth-link/core@0.1.0
