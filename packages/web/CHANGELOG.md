# @payload-auth-link/web

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

- Updated dependencies [[`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085)]:
  - @payload-auth-link/core@0.1.0
