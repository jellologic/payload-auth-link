---
'@payload-auth-link/plugin': minor
'@payload-auth-link/migrate': minor
---

The kit owns its record store (issue #139): records live in a `payload-auth-link-migrations` collection the plugin declares, in the database they describe — and `payload.config.kv` becomes irrelevant to the kit.

- **plugin** (new collection): `payload-auth-link-migrations` — hidden, access-denied, no document locking; columns `key` (unique) and `data`. A host colliding with the slug fails config validation.
- **migrate**: the database identity, run records, and finalize marker are recorded in that collection — in the database they describe, so restores, branches, and clones carry them and eviction cannot drop the finalize marker. The round-8 refusal of non-database KV adapters is REMOVED: a Redis (or any) `payload.config.kv` is supported again. Legacy databases are migrated on the first kit command (one bulk copy of `payload-auth-link/migrate/*` records from the old `payload_kv` store, flagged); the legacy table can be dropped whenever the app likes.
- **migrate (doctor)**: the `kv-adapter-unsupported` blocker is gone; the store check now verifies the new collection's table (or the legacy `payload_kv` for pre-upgrade databases) and blocks as `migration-records-store-missing` until the app's migrations create it. `kvAdapterOf` remains exported for hosts that want the classification.

`Upgrade impact:` ONE new database table (`payload_auth_link_migrations`: `id`, `key` unique, `data` jsonb — no timestamps, no versions), created by the app's own migrations from the plugin's declared collection. Additive only: no existing table, column, or index changes; no data moves. SQLite/Mongo: push creates it. Postgres: `payload migrate:create` generates the additive table — run `payload migrate` after upgrading and BEFORE any kit command; until then every kit command refuses (fail closed) and the doctor blocks with `migration-records-store-missing`. Databases with legacy `payload_kv` records: the first kit command copies them into the new store automatically.
