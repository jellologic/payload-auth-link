---
'@payload-auth-link/migrate': minor
---

New package: the migration kit's CLI, starting with the read-only
`doctor` preflight (issue #52).

```sh
bunx @payload-auth-link/migrate doctor --config ./src/payload.config.ts --src ./src
```

Reports version bands, Better Auth plugin support, users-collection
collisions and role values, the 0.7.0 behaviour changes that bite,
source call sites that must migrate, and (with a database URL) row
counts, unverified users, and orphans. `--json` + exit codes
(`0` clean / `1` blockers / `2` warnings / `3` usage) make it CI-able;
every finding carries a stable machine code. See
docs/migrating-from-payload-auth.md ("Step 0: run the doctor").
