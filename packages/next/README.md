# @payload-auth-link/next

The Next.js adapter: Edge-safe middleware, a server-to-client provider bridge, and a client refresh hook. It re-exports the whole framework-free `@payload-auth-link/web` surface, so one import covers verification, authorization, and redirect safety.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/next
```

Peer dependencies: `next` ^15.0.0 || ^16.0.0, `react` ^19.0.0.

ESM-only, Node 20.9 or later.

## What it provides

- `createAuthMiddleware`: an optimistic, Edge-safe bounce to sign-in (UX only, never authorization)
- `AuthLinkServerProvider`: validates on the server and hydrates the React context
- `useAuthLinkRefresh`: re-reads the session and refreshes the router after sign-in or sign-out
- Everything from `@payload-auth-link/web` (`createSessionVerifier`, `requireRoles`, `safeRedirectPath`, …)

## Usage

```ts
// middleware.ts
import { createAuthMiddleware } from '@payload-auth-link/next'
// Edge-safe subpath: resolves the names Better Auth actually sets,
// including the `__Secure-` prefix on https (a hard-coded
// 'better-auth.session_token' never matches there).
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

export default createAuthMiddleware({
  sessionCookieNames: getBetterAuthSessionCookieNames({
    baseURL: process.env.BETTER_AUTH_URL ?? 'http://localhost:3000',
  }),
  publicPaths: ['/', '/sign-in'],
})

export const config = {
  // Keep the bounce off assets, API routes, and the admin panel.
  // Segment-anchored: bare `api`/`admin` prefixes would also exempt
  // frontend routes like `/admin-only`.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api(?:/|$)|admin(?:/|$)).*)'],
}
```

Pass the same Better Auth options your engine uses (`baseURL`,
`advanced.cookiePrefix`, `advanced.useSecureCookies`, …) so the names
match. See [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
for the dual-provider (Auth.js) form.

## Docs

- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
