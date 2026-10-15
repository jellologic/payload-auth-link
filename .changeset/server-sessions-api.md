---
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/core': minor
---

Supported server session API (issue #54): `authLinkServer(payload)` —
`getSession` (same rules as the strategies), `createSessionFor` (audited,
refused for suspended users, gated by `allowServerSessions`:
`'dev-only'` default | `true` | `false`), `listSessions`,
`revokeSession`, `revokeAllForUser`, `verifyApiKey`, and
`sessionCookie` — so apps never touch Better Auth internals or
hand-sign cookies. Provider capability-gated (`server-session-create`,
`server-session-list`, `api-key-verify`); Better Auth implements all
three, Auth.js reports none and the server API refuses with typed
errors. `Upgrade impact:` none — additive.
