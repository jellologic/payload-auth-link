# @payload-auth-link/provider-better-auth

The [Better Auth](https://www.better-auth.com) identity-provider adapter. It provides a Payload-backed Better Auth database adapter (Better Auth's tables become `ba-*` Payload collections) and an engine that wires Better Auth, the provider port, and its collections in one call.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/provider-better-auth
```

Peer dependencies: `payload` ^3.0.0 || ^4.0.0-beta.0.

ESM-only, Node 20.9 or later.

## What it provides

- `createBetterAuthEngine`: returns `{ auth, provider, collections, sessionCookieNames }`
- `createPayloadDatabaseAdapter`: Better Auth's database layer over the Payload Local API
- `@payload-auth-link/provider-better-auth/cookies`: an Edge-safe cookie-name helper for middleware

## Docs

- [Better Auth guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-better-auth.md)
- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
