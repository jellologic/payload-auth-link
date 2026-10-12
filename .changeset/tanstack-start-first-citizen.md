---
'@payload-auth-link/web': minor
'@payload-auth-link/tanstack-start': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/next': patch
---

TanStack Start as a first-class citizen alongside Next.js.

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
