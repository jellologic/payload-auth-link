# @payload-auth-link/migrate

## 0.3.1

### Patch Changes

- [#66](https://github.com/jellologic/payload-auth-link/pull/66) [`a23a0c6`](https://github.com/jellologic/payload-auth-link/commit/a23a0c6a793ebc7d5b933780b3f6f4191b791bcf) Thanks [@jellologic](https://github.com/jellologic)! - The migrate CLI's `codemod --write` now writes the rewritten content to disk — it previously wrote the original file back, so `--write` reported the files as rewritten while changing nothing. `codemod`, `export` and `finalize` also no longer require `--config`, matching their documented usage (`codemod` needs `--src`, `export` needs `--database-url`, `finalize` is manifest-only).

  Upgrade impact: none — schema, options, and the programmatic `applyCodemods` result gain an additive `after` field only. CLI users running `codemod --write` get the rewrite they were promised; no stored data is touched.

## 0.3.0

### Minor Changes

- [`8d2dfc4`](https://github.com/jellologic/payload-auth-link/commit/8d2dfc4b9aef0c57c8f84ba6f39d82bd9a9ea2dd) Thanks [@jellologic](https://github.com/jellologic)! - Codemods + temporary `payload.betterAuth` compatibility shim (issue [#53](https://github.com/jellologic/payload-auth-link/issues/53)).

  `bunx @payload-auth-link/migrate codemod --src ./src` rewrites the
  named payload-auth call-site patterns (`getPayloadAuth()`,
  `payload.betterAuth.api.getSession({ headers })`,
  `toNextJsHandler(payload.betterAuth)`) and reports what needs a human
  decision — nothing is half-rewritten. Dry run by default; `--write`
  rewrites.

  `createBetterAuthCompatShim(payload)` is the opt-in
  `payload.betterAuth`-shaped accessor backed entirely by the supported
  server API — same suspension gate, same MFA projection, same audit
  sink, no back door — with one deprecation warning per process. The
  doctor counts remaining shim call sites.

- [`a7bf621`](https://github.com/jellologic/payload-auth-link/commit/a7bf62112ae818d6c287d4dbe809aac51f92c08f) Thanks [@jellologic](https://github.com/jellologic)! - Off-ramp (issue [#58](https://github.com/jellologic/payload-auth-link/issues/58)): `bunx @payload-auth-link/migrate export
--database-url URL [--out file.jsonl]` exports every auth table
  losslessly as JSONL — every column (plugin-injected fields,
  credential hashes, role child rows) typed as stored, re-importable
  without transformation. The uninstall path is a supported operation
  with a CI-validated test (plugin removed → users/content intact on
  the same database) and documentation of every plugin-injected field.

### Patch Changes

- Updated dependencies [[`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c)]:
  - @payload-auth-link/core@0.5.0
  - @payload-auth-link/next@0.3.1

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
