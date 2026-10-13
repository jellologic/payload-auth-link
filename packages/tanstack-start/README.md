# @payload-auth-link/tanstack-start

The TanStack Start adapter (Payload v4): server-route handlers, request middleware, session server-function helpers, route-loader hydration, and a client refresh hook. It re-exports the whole framework-free `@payload-auth-link/web` surface.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/tanstack-start
```

Peer dependencies: `@tanstack/react-router` ^1.170.0, `@tanstack/react-start` ^1.140.2, `react` ^19.0.0.

ESM-only, Node 20.9 or later.

## What it provides

- `createServerRouteHandlers`: mount the identity provider's routes in `server.handlers`
- `createAuthRequestMiddleware`: the optimistic bounce for `src/start.ts` (exempts server functions by default)
- `getSessionUserFromRequest`, `createSessionLoader`: server-side reads and root-loader hydration
- `useAuthLinkRefreshStart`: re-reads the session and invalidates loaders after auth changes
- Everything from `@payload-auth-link/web`

## Usage

```ts
// src/start.ts
import { createAuthRequestMiddleware } from '@payload-auth-link/tanstack-start'

export const authMiddleware = createAuthRequestMiddleware({
  sessionCookieNames: ['better-auth.session_token'],
})
```

## Docs

- [TanStack Start guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-tanstack-start.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
