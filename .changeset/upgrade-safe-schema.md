---
'@payload-auth-link/provider-authjs': patch
'@payload-auth-link/provider-better-auth': patch
---

Upgrade-safe collection shapes (upgrade-resilience Phase 0). Booting
these versions on a database seeded by 0.1.1 no longer hangs,
crashes, or destroys rows:

- Auth.js: `aj-verification-tokens.key` is no longer DB-level
  `required` — it stays unique (NULLs tolerated by SQLite and
  Postgres) and is written and read by the adapter, backfilled
  lazily. Adding the column on push is an in-place ALTER, not a
  table rebuild; seeded tokens survive and stay consumable.
- Better Auth: `ba-users.name` keeps its DB-level NOT NULL (the
  physical column is unchanged, so SQLite never rebuilds the table)
  while BA's `name: ""` writes are accepted via field-level
  validation.
- Golden-DB upgrade tests now boot the 0.1.1 seed on current code
  in push and migrations modes on SQLite, Postgres, and MongoDB,
  in both upgrade and rollback directions.

Upgrade impact: none for fresh installs. For 0.1.1 databases, see
docs/upgrading.md § 0.1.1 → 0.2.0 — SQLite/Postgres push boots
cleanly; migrations mode requires `key` nullable in the generated
migration; MongoDB needs the one-time index reconciliation
(`reconcileAuthJsMongoIndexes`, shipped alongside). No verification
tokens are invalidated.
