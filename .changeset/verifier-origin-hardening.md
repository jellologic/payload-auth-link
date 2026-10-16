---
'@payload-auth-link/core': minor
'@payload-auth-link/web': minor
'@payload-auth-link/next': minor
'@payload-auth-link/provider-authjs': minor
---

Harden the server-side session verifier's origin resolution.

- `createSessionVerifier` now requires `baseUrl` (or an absolute `sessionEndpoint`) unless `NODE_ENV` is exactly `'development'`; unset, `test`, `staging`, `preview`, and `production` all throw `InvalidConfigError` at construction.
- In development, the host fallback ignores `X-Forwarded-Host`/`X-Forwarded-Proto` unless the new `trustProxy` option is set, accepts only `http`/`https`, and only resolves to hosts in `allowedDevelopmentHosts` (default `localhost`, `127.0.0.1`, `[::1]`). Rejections fail closed and are reported through `onError`.
- Protocol-relative and non-http `sessionEndpoint` values throw at construction (new `validateSessionEndpoint` export).
- The verifier fetch aborts after `timeoutMs` (default 5000, new `defaultSessionVerifierTimeoutMs` export) and does not follow redirects; both fail closed.
- `resolveSessionUrl`'s host fallback now defaults to off and takes a host policy; core's `resolveOrigin` gains `trustProxy` and `allowedHosts` and validates the scheme and host. The Auth.js engine keeps reading forwarded headers explicitly for its in-process session read.
- `packages/next/README.md`: the middleware snippet resolves cookie names with `getBetterAuthSessionCookieNames` (so `__Secure-` names match on https) and ships a matcher.

Upgrade impact: no schema change. Apps constructing a verifier without `baseUrl` outside `NODE_ENV=development` must pass `baseUrl`; dev setups behind a local proxy set `trustProxy: true` (and `allowedDevelopmentHosts` for non-loopback dev hosts). See `docs/upgrading.md`.
