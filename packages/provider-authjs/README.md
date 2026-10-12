# @payload-auth-link/provider-authjs

The [Auth.js](https://authjs.dev) identity-provider adapter. It provides a Payload-backed Auth.js database adapter (`aj-*` collections), a credentials service with salted scrypt hashing and a timing-safe `authorize`, and an engine that wires Auth.js, the provider port, and its collections.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/provider-authjs
```

Peer dependencies: `payload` ^3.0.0 || ^4.0.0-beta.0.

ESM-only, Node 20.9 or later.

## What it provides

- `createAuthJsEngine`: returns `{ handleRequest, provider, collections, sessionCookieNames, … }`
- `createAuthJsCredentials`: `authorize` and `register`, which return `Result` values
- `@payload-auth-link/provider-authjs/cookies`: an Edge-safe cookie-name helper for middleware

## Docs

- [Auth.js guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-authjs.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
