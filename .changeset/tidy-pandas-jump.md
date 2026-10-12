---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/next': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
'@payload-auth-link/react': patch
---

Enterprise review hardening.

Security fixes:

- Logout now expires session cookies with their live attributes
  (`Secure`, `Domain`, `Path`) reported by each provider through the
  new optional `IdentityProviderPort.sessionCookieClearOptions` hook,
  so `__Secure-` and custom-domain cookies actually die. Providers
  that predate the hook fall back to prefix-derived attributes
  (`expiringCookieOptions`).
- New `safeRedirectPath` guard in `@payload-auth-link/next`: the
  post-login `redirect` param is attacker-controlled input and must
  never reach the router unvalidated (open redirect).
- New server authorization helpers `requireSessionUser` /
  `requireRoles` in `@payload-auth-link/next` (throw
  `SessionInvalidError` / `ForbiddenError` by default; pass
  `redirect()` / `notFound()` as handlers). `RequireRoles` is
  UI-hiding only and must never gate content.
- Auth.js credentials `authorize` burns a dummy scrypt verification
  for unknown emails and hashless rows, closing the
  user-enumeration timing oracle.
- Session reads anchor to the configured `baseUrl`/`AUTH_URL` origin
  whenever set; the request-host fallback is local-development only
  (host headers are client-spoofable and session cookies are
  forwarded to that origin).

Strictness and consistency:

- Better Auth `AdapterOperationError` now extends `AuthLinkError`
  (code `ADAPTER_OPERATION_FAILED`) like its Auth.js twin; it moved
  from `adapter.js` to `errors.js` (barrel import unchanged).
- Slug overrides validate at wiring time in both providers
  (`resolveSlugs`: non-empty, known models) and collections reject
  slug collisions (`assertUniqueSlugs`), including custom-model
  slugs against core slugs; new `customModelSlug` helper.
- Shared core building blocks replace nine local copies:
  `isRecord` / `isNonEmptyString` / `toDate` guards,
  `runProviderOperation` port-call wrapper, `denyAllAccess` system
  collection default, `secureCookiePrefix` / `hostCookiePrefix`
  constants. The Edge-safe `/cookies` subpaths keep local literals
  (runtime-import-free) pinned to core by tests.
- `CookieOptions` gains `partitioned`; `SessionVerifier` is now a
  named export.
