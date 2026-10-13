---
'@payload-auth-link/plugin': patch
---

Security hardening: the injected users-collection fields now fail
closed by default. Payload's own collection defaults give every
authenticated user write access to every field, which is the wrong
default for fields that decide privileges. The new defaults:

- **`roleManagerRoles`** (new option) names the roles that govern
  the auth system. Defaults to `['admin']` when an `admin` role is
  configured; **required at config time when it is not** (the plugin
  refuses to guess who manages roles).
- `roles`, `phone`, `suspendedUntil` and `suspendReason` field
  writes: role-manager roles only, with the existing
  deny-while-impersonating rule on top. Local-API
  (`overrideAccess`) writes — the plugin's own engine paths and
  your own scripts — are never restricted.
- Field reads: `suspendReason` and `suspendedUntil` are
  role-manager only (matching the documented "never exposed");
  `identities` too (engine-managed rows carry provider ids and
  emails); every user still reads their own `roles` (and phone).
- `identities` writes are denied for every REST/admin caller —
  linking happens through the plugin only.
- The default admin-panel grant is the role-manager roles, not "any
  signed-in user". A builder `access.admin` on the users collection
  still wins (wrapped with the impersonation deny, as before).

Upgrade impact: default-behaviour change — REST/admin writers other
than the manager roles lose write access to the injected fields, and
non-managers no longer read `identities`/`suspension` fields. Hosts
whose editors use a non-admin role must pass
`roleManagerRoles: [...]`. Docs updated (getting-started, concepts,
capabilities guide); negative e2e specs added on every adapter.
Schema snapshots unchanged (access functions are not DB shape).
