---
'@payload-auth-link/plugin': minor
---

Adopt an existing roles field instead of throwing (issue #20) — the
migration path from `payload-auth`-style schemas where the Payload
users table already carries a role column. A compatible field at the
configured `rolesField` (Payload `select`, `hasMany: true`, options
covering every configured role) is taken over: the plugin imposes
required-ness, the default, and its governed write access, while the
host's options, labels, and extra roles survive. Incompatible shapes
fail at config time naming the exact remediation; `rolesField:
'role'` remapping against an existing `role` column now works.

Alongside: **docs/migrating-from-payload-auth.md** — the runbook for
moving data from `payload-auth` (users → `ba-users` with `baId` =
old id, `user_accounts` → `ba-accounts` with password hashes and
OAuth tokens verbatim, identity pre-linking, plugin-model foreign-key
rewrites, session/verification drop policy, `advanced.cookiePrefix`
continuity) with a script sketch, plus the prominent
`req.user`-is-the-session-projection note.

Upgrade impact: config-time behavior — setups that previously failed
with a roles-field collision now boot and adopt the field, which
gains the role-manager write restriction; no database change.
