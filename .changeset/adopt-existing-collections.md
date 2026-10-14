---
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/plugin': minor
---

Adopt existing collections instead of moving rows (issue #49), and
keep stored role values untouched with the role value map (issue #56).

**provider-better-auth**: `createBetterAuthEngine({ schemaMap, idStrategy: 'payload' })`
serves Better Auth models from EXISTING Payload collections — the
payload-auth layout boots with zero row moves. The engine creates no
collection for an adopted model, forces no access, and preserves host
fields (the adapter writes partial updates only). Per-model field maps
rename fields both ways (`userId` → `user` or `referenceId`);
relationship fields read and write as ids, coerced to the Payload id
type. Every Better Auth field must resolve to a host column — missing
ones fail fast, naming the model and field, on first adapter use.

**plugin**: `authLink({ roleValues })` translates canonical roles to
stored values at the storage edge (field reads, governed writes, the
injected select's options), so a camelCase role like `frontPlugin`
stays stored as-is while `requireRoles(['front-plugin'])` works.
Duplicate stored values and entries for undeclared roles fail at
config time. `projectRolesAs: 'stored'` (default `'canonical'`)
projects stored values onto `req.user.roles` for access checks that
compare the stored literal; the MFA gate and role governance always
run on canonical roles.

`Upgrade impact:` no schema changes and no backfill. Adopt-mode boots
run their own additive step for the plugin-injected users columns (see
the migrating-from-payload-auth guide); pushing over a payload-auth
layout is NOT supported (drizzle's push prompts on the layout's enums).
The fixture proves the whole path: a payload-auth 1.9.4 Postgres dump
boots on payload-auth-link with zero row moves, old passwords sign in,
orgs/members/API keys resolve, and host fields survive Better Auth
writes.
