---
'@payload-auth-link/core': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
'@payload-auth-link/migrate': minor
---

Round 8 (issue #132): the kit refuses external KV adapters, and adopt mode links identities at creation.

`Upgrade impact:` no database schema change — columns, fields, and
indexes are untouched. The regenerated
`snapshots/schema/plugin-users.json` diff is the users collection's
hook array gaining the `afterChange` identity-at-creation hook. Push
and migrations have nothing to do on SQLite, Postgres, or MongoDB.
Operators on a NON-database key-value adapter must move the app to the
default database-backed store for the migration window (every kit
command refuses until then — see the first bullet).

- **migrate (BREAKING for one configuration)**: every kit command — and the doctor (blocker `kv-adapter-unsupported`) — now refuses when the app's `payload.config.kv` is a NON-database adapter (Redis, …). The migration's database identity, run records, and finalize marker must live IN the database they describe: under an external adapter, a restore, branch, or clone stops carrying them and eviction can lose the finalize marker after finalize. Switch to the default database-backed key-value store for the migration window. The `payload-kv-table-missing` check no longer misfires for such apps (the table legitimately does not exist there); it keeps firing for database-backed setups whose table is genuinely missing. The `kvAdapterOf` classifier is exported.
- **plugin / provider-better-auth (issue #132 part 3)**: in adopt mode the engine stamps its user creates, and the plugin writes the identities row at creation — so a sign-up that never completes sign-in (an unverified email) is still linked, and `migrate verify` no longer reports a permanent mismatch for post-cutover users. Operator-created documents never gain a synthetic identity.
