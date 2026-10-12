# @payload-auth-link/core

The framework-free heart of payload-auth-link: the auth domain (roles, emails, sessions, typed errors), the port interfaces every adapter implements, and the use-cases that link provider identities to Payload users. It has no framework, Payload, or provider-SDK imports. You rarely install it directly, because every other package depends on it.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/core
```

ESM-only, Node 20.9 or later.

## What it provides

- `IdentityProviderPort`, `UserRepository`, `SessionPort`: the hexagonal seams
- `ensureLinkedUser`, `registerWithStore`: linking and registration use-cases returning `Result` values
- `parseRole`, `parseEmail`: smart constructors for the branded `Role` and `Email` types
- `safeRedirectPath`: open-redirect-safe post-login destinations
- `createProviderRegistry`, `serializeCookie`, `isCookieName`, and the typed error classes

## Usage

```ts
import { parseRole, safeRedirectPath } from '@payload-auth-link/core'

parseRole('admin').isOk() // true — roles are lowercase slugs
safeRedirectPath('https://evil.example') // '/account' — off-site falls back
```

## Docs

- [Concepts](https://github.com/jellologic/payload-auth-link/blob/main/docs/concepts.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
