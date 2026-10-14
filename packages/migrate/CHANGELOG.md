# @payload-auth-link/migrate

## 0.2.0

### Minor Changes

- [#62](https://github.com/jellologic/payload-auth-link/pull/62) [`dd8f6a5`](https://github.com/jellologic/payload-auth-link/commit/dd8f6a54e50fc0f6f83ca04c75a860a34226b141) Thanks [@jellologic](https://github.com/jellologic)! - New package: the migration kit's CLI, starting with the read-only
  `doctor` preflight (issue [#52](https://github.com/jellologic/payload-auth-link/issues/52)).

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

- [#63](https://github.com/jellologic/payload-auth-link/pull/63) [`e7baac6`](https://github.com/jellologic/payload-auth-link/commit/e7baac6472dcd08f04156c07b0b9af4d0bcb5de2) Thanks [@jellologic](https://github.com/jellologic)! - The runnable, reversible importer (issue [#50](https://github.com/jellologic/payload-auth-link/issues/50)):
  `bunx @payload-auth-link/migrate from-payload-auth`.

  Dry run by default (planned counts per model, unmappable rows,
  unverified users); `--apply` copies users, credential accounts (hashes
  verbatim), OAuth tokens, verifications, API keys, jwks and the
  organization plugin's rows into the payload-auth-link collections,
  granting `linkable`/`linkableEmail` from VERIFIED emails only and —
  with the default `--sessions=carry` — carrying the session table so
  nobody is logged out. Every created row and field change lands in the
  manifest; `verify` checks both sides (non-zero exit on any mismatch),
  `rollback` undoes exactly the manifest, `finalize` marks the point of
  no return. Idempotent and resumable; the source tables are never
  modified.

  `Upgrade impact:` none — the CLI is additive and the source tables stay
  untouched until you drop them yourself after `finalize`.
