---
'@payload-auth-link/core': minor
'@payload-auth-link/react': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
---

Web-layer fixes (issue #87).

- `safeRedirectPath` resolves dot segments (including percent-encoded ones) before the API-prefix and sign-in checks and returns the normalised path, so `/x/../api/...` and `/./sign-in` fall back.
- `AuthLinkProvider` sequences session reads: only the newest read writes state, and `signOut` aborts in-flight reads so a late response can no longer restore a signed-out session. `fetchSession` accepts an optional `AbortSignal`.
- Logout (`DELETE /api/auth-link/session`) also expires Better Auth's `dont_remember` and cookie-cache `session_data` cookies, the `__Secure-`/plain counterpart of each name, and the configured `legacySessions` names (`getBetterAuthLogoutCookieNames` returns the additional names).
- A logout presenting no session cookie and no `Authorization`/`x-api-key` header answers without querying any provider (same idempotent response, cookies still expired).
- The provider admin login view derives its break-glass endpoint (`${routes.api}/${usersCollection}/login`) and post-login destination (`routes.admin`) from the Payload config; new `admin.signInPath` and `admin.authBase` plugin options cover the app sign-in link and the Better Auth mount.
- Docs: `__Host-` cookie setup for single-host deployments.

Upgrade impact: no schema change, no push or migration needed on any adapter. Operators with a non-default sign-in page or Better Auth mount set `admin.signInPath` / `admin.authBase`. See `docs/upgrading.md`.
