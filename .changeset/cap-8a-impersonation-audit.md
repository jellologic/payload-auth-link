---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': patch
---

Impersonation audit hole closed (CAP-8a): Better Auth's
`session.impersonatedBy` now reaches the port as the new optional
`ProviderSession.actor` (`{ providerUserId }`, `null` for plain
sessions; Auth.js always reports `null`), the plugin audit-logs every
verified use of an impersonated session through `LoggerPort` with the
operator and target ids, and plugin logout also expires Better Auth's
`admin_session` cookie via the new optional `logoutCookieNames` port
field (`getBetterAuthLogoutCookieNames`). All additions are optional
and backward compatible.
