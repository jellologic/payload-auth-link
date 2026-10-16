---
'@payload-auth-link/provider-authjs': patch
---

`revokeSession` on a database-session Auth.js engine now fails when no session matches the handle, instead of reporting success. `authLinkServer(payload).revokeSession` no longer stops at an Auth.js provider that revoked nothing, so a session held by another registered provider is still revoked.
