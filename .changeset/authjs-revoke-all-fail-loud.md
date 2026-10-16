---
'@payload-auth-link/provider-authjs': minor
---

`revokeUserSessions` (database sessions — `authLinkServer.revokeAllForUser`
on Auth.js) now fails loudly instead of reporting success while
sessions stay alive: Payload's bulk delete resolves with per-row
`errors` rather than rejecting, so a partial delete used to pass
silently. The engine now throws when any row failed to delete, and
re-counts the user's session rows afterwards and throws if any remain.
