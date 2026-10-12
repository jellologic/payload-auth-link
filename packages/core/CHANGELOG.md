# @payload-auth-link/core

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
