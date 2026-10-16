---
'@payload-auth-link/plugin': minor
---

Restrict the users collection's `unlock` operation to role managers by default (never while impersonating). Payload's own default let any signed-in user unlock any account, which undid the brute-force lockout. A host that sets `access.unlock` itself keeps its own function.

Upgrade impact: no schema change. Self-service "unlock my account" flows run by plain users now get 403; route them through a role manager or set `access.unlock` on your users collection.
