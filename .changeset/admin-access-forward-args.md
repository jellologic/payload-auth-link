---
'@payload-auth-link/plugin': patch
---

The users collection's admin-access wrapper (the impersonation deny) now forwards every argument Payload passes to a host-declared `access.admin`, not just `req`, so host functions that read the other arguments (Payload v4) keep working.
