---
'@payload-auth-link/plugin': patch
---

`GET /api/users/me` answers for auth-link sessions presented on the bearer channel (`admitChannels: ['cookie', 'bearer']`). Payload's `me` operation decoded the provider's opaque bearer token as a Payload JWT (a 500) and would echo it back as `token`; the plugin's `me` hook now answers for auth-link users with the verified session's `exp` and never returns the provider token. The `admitChannels` TSDoc now states which channels each adapter reports and the bearer CSRF relaxation.

Upgrade impact: no schema change (no column added, removed or retyped; push and migrations have nothing to do on SQLite, Postgres or MongoDB). The users collection gains a `me` hook, which runs ahead of any host `me` hooks for auth-link sessions only.
