# @payload-auth-link/provider-authjs

The [Auth.js](https://authjs.dev) identity-provider adapter. It provides a Payload-backed Auth.js database adapter (`aj-*` collections), a credentials service with salted scrypt hashing and a timing-safe `authorize`, and an engine that wires Auth.js, the provider port, and its collections.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/provider-authjs @auth/core@0.41
```

Peer dependencies: `@auth/core` (validated band `>=0.41.0 <0.42.0`) and `payload` `^3.83.0 || 4.0.0-beta.0`. Install `@auth/core` yourself — the raw core, not the `next-auth` wrapper. The engine asserts the installed version at wiring time (`UnsupportedVersionError` before any database write); 0.x minors add `Adapter` methods, so an unvalidated one must not float in. See the [compatibility matrix](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md).

ESM-only, Node 20.9 or later.

## What it provides

- `createAuthJsEngine`: returns `{ handleRequest, provider, collections, sessionCookieNames, … }`
- `createAuthJsCredentials`: `authorize` and `register`, which return `Result` values
- Email OTP + Google One Tap recipes (`emailOtpVerificationToken`,
  `buildEmailOtpCallbackUrl`, `verifyGoogleIdToken`,
  `createGoogleOneTapAuthorize`)
- `@payload-auth-link/provider-authjs/cookies`: an Edge-safe cookie-name helper for middleware

Declared capabilities follow your configured providers (Email →
magic link, OAuth/OIDC → oauth, database sessions →
revoke-user-sessions); OAuth email trust is an explicit allow-list
(`trustProviderEmailVerification`). See the
[capabilities guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-capabilities.md).

## Docs

- [Auth.js guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-authjs.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
