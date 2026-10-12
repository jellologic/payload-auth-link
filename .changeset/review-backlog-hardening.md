---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/web': minor
'@payload-auth-link/react': minor
'@payload-auth-link/next': patch
'@payload-auth-link/tanstack-start': patch
'@payload-auth-link/provider-authjs': patch
'@payload-auth-link/provider-better-auth': patch
---

Close the low-severity review backlog. Every change fails closed; see
docs/upgrading.md.

- core: `safeRedirectPath` moves to core with a destination policy
  that refuses the sign-in page and `/api` (`SafeRedirectOptions`).
  New exports: `isCookieName` and `SafeRedirectOptions`. Cookie
  `Domain`/`Path` values that could inject attributes or split
  headers throw. Provider registration rejects illegal session cookie
  names. `validateStartupConfig` drops the unused `secret`.
- plugin: `secret` is deprecated and ignored. An empty provider
  session id is a 401, not a 500. Logout already sweeps every
  provider (PAR-7).
- web: `requireRoles` validates its roles (`InvalidRoleError`, and
  `InvalidConfigError` for an empty list). It re-exports
  `SafeRedirectOptions`.
- react: `SignOutButton` narrows `redirectTo`. `AuthLinkProvider`
  syncs a changed `initialUser` (value-compared, so a client sign-out
  is never undone by an equal snapshot).
- next, tanstack-start: re-export the whole web surface through one
  shared statement, so adapters cannot drift (now includes
  `SafeRedirectOptions`).
- provider-authjs: `authorize` lowercases the email. A corrupt
  `emailVerified` throws `AdapterMappingError`. Gapped session chunk
  sets are malformed.
- provider-better-auth: adapter rows assert `baId` and date fields,
  and throw `AdapterOperationError` on storage drift.
