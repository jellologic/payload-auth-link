# @payload-auth-link/next

The Next.js adapter: Edge-safe middleware, a server-to-client provider bridge, and a client refresh hook. It re-exports the whole framework-free `@payload-auth-link/web` surface, so one import covers verification, authorization, and redirect safety.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/next
```

Peer dependencies: `next` >=15.0.0, `react` ^19.0.0.

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

export default createAuthMiddleware({
  sessionCookieNames: ['better-auth.session_token'],
  publicPaths: ['/', /^\/api\//],
})
```

## Docs

- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
