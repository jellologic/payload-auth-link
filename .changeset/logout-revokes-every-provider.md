---
'@payload-auth-link/plugin': patch
---

Logout revokes every provider session the request presents, not only
the verified one. Verification stops at the first registered provider
with a live session (registry order is precedence, now documented), so
a browser signed in through two providers previously kept the second
session alive server-side after `DELETE /api/auth-link/session`. The
sweep is best-effort — failures are logged, never fatal — and also runs
on the idempotent 401 path, where a provider session can be live behind
a failed verification.
