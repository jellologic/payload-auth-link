# @payload-auth-link/web

The framework-free web layer shared by the Next.js and TanStack Start adapters: auth route handlers, server-side session verification, server authorization, and redirect safety, all on the standard `Request` and `Headers`. Both adapters re-export it in full, so import from your framework adapter unless you're building one.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/web
```

ESM-only, Node 20.9 or later.

## What it provides

- `createSessionVerifier`: full session validation against the plugin's session endpoint, anchored to your `baseUrl`
- `requireSessionUser`, `requireRoles`: server-side enforcement that runs before protected content renders
- `createRouteHandlers`: mount the identity provider's routes
- `decideAuthRedirect`, `safeRedirectPath`: the optimistic bounce and post-login destination safety

## Usage

```ts
import { createSessionVerifier, requireRoles } from '@payload-auth-link/web'

const verify = createSessionVerifier({ baseUrl: 'https://example.com' })
const admin = await requireRoles(request.headers, verify, { roles: ['admin'] })
```

## Docs

- [Concepts](https://github.com/jellologic/payload-auth-link/blob/main/docs/concepts.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
