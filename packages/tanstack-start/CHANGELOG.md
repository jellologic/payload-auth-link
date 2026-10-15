# @payload-auth-link/tanstack-start

## 0.2.2

### Patch Changes

- Updated dependencies [[`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c)]:
  - @payload-auth-link/core@0.5.0
  - @payload-auth-link/react@0.2.3
  - @payload-auth-link/web@0.2.3

## 0.2.1

### Patch Changes

- Updated dependencies [[`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008)]:
  - @payload-auth-link/core@0.4.0
  - @payload-auth-link/react@0.2.2
  - @payload-auth-link/web@0.2.2

## 0.2.0

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

### Patch Changes

- Updated dependencies [[`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd), [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd)]:
  - @payload-auth-link/core@0.3.0
  - @payload-auth-link/react@0.2.1
  - @payload-auth-link/web@0.2.1

## 0.1.2

### Patch Changes

- Updated dependencies [[`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4)]:
  - @payload-auth-link/core@0.2.0
  - @payload-auth-link/web@0.2.0
  - @payload-auth-link/react@0.2.0

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
  - @payload-auth-link/web@0.1.1
  - @payload-auth-link/react@0.1.1

## 0.1.0

### Minor Changes

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085) Thanks [@jellologic](https://github.com/jellologic)! - TanStack Start as a first-class citizen alongside Next.js.

  New packages:

  - `@payload-auth-link/web`: the framework-free web surface
    (`createRouteHandlers`, `createSessionVerifier`, `requireRoles` /
    `requireSessionUser`, `safeRedirectPath`), moved verbatim from
    `next`. No behavior change; `next` re-exports it so existing
    imports keep working.
  - `@payload-auth-link/tanstack-start` (Payload v4):
    `createServerRouteHandlers` for `server.handlers`,
    `createAuthRequestMiddleware` (over the shared `decideAuthRedirect`)
    for `src/start.ts`, `getSessionUserFromRequest` /
    `createSessionLoader` for server functions and hydration,
    `useAuthLinkRefreshStart` for post-auth refresh, and a
    `beforeLoad` guard recipe over shared `requireRoles`. Re-exports
    `web` for the same one-import DX as `next`.

  - Better Auth engine passes `options.plugins` through verbatim:
    builders declare the framework cookie plugin themselves
    (`nextCookies()` on Next.js, `tanstackStartCookies()` on
    TanStack Start) exactly as Better Auth documents. The engine
    never appends framework plugins and owns no cookie flags.

### Patch Changes

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

- Updated dependencies [[`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085)]:
  - @payload-auth-link/core@0.1.0
  - @payload-auth-link/web@0.1.0
  - @payload-auth-link/react@0.1.0
