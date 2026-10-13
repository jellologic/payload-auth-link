# @payload-auth-link/provider-better-auth

The [Better Auth](https://www.better-auth.com) identity-provider adapter. It provides a Payload-backed Better Auth database adapter (Better Auth's tables become `ba-*` Payload collections) and an engine that wires Better Auth, the provider port, and its collections in one call.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/provider-better-auth better-auth@1.7
```

Peer dependencies: `better-auth` (validated band `>=1.7.6 <1.8.0`) and `payload` `^3.83.0 || 4.0.0-beta.0`. Install `better-auth` yourself — you configure its server, so you already import it.

**Better Auth lockstep:** `better-auth` and every `@better-auth/*` satellite you enable (e.g. `@better-auth/passkey`) move together, and only within the validated band — satellites peer-lock to exact BA minors and will otherwise force an unvalidated core under you. The engine asserts the installed version at wiring time (`UnsupportedVersionError` before any database write); see the [compatibility matrix](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md).

ESM-only, Node 20.9 or later.

## What it provides

- `createBetterAuthEngine`: returns `{ auth, provider, collections, sessionCookieNames }`
- `createPayloadDatabaseAdapter`: Better Auth's database layer over the Payload Local API
- `@payload-auth-link/provider-better-auth/cookies`: an Edge-safe cookie-name helper for middleware

Declared capabilities are derived from the plugins you install:
magic link, email OTP, OAuth, One Tap, passkeys, two-factor MFA,
phone sign-in, anonymous guests, audited impersonation, and
multi-session revocation — see the
[capabilities guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-capabilities.md)
and the [compatibility matrix](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md).

## Docs

- [Better Auth guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-better-auth.md)
- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
