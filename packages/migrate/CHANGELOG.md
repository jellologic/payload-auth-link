# @payload-auth-link/migrate

## 0.4.3

### Patch Changes

- Updated dependencies [[`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94)]:
  - @payload-auth-link/core@0.6.2
  - @payload-auth-link/next@0.3.4

## 0.4.2

### Patch Changes

- [`e09d20c`](https://github.com/jellologic/payload-auth-link/commit/e09d20c10e25c038628c896e601e5d09cc2ca8b6) Thanks [@jellologic](https://github.com/jellologic)! - The importer fails fast on the wrong config, and the doctor's signal is clean (issue [#75](https://github.com/jellologic/payload-auth-link/issues/75), from the real-data re-verification).

  - **The importer refuses configs that declare no payload-auth-link target collections BEFORE booting** — an untouched payload-auth app's config has no `ba-*` collections to write to, and the failed run used to park forever on the boot's live database pool (0% CPU, no output, never exits). It now refuses at the config-module read with the fix in the message, the Payload boot runs under a 120s watchdog, and a failed CLI exits the process outright. The guide states plainly that the importer runs against the TARGET config.
  - **Doctor plugin detection requires a Better Auth import and skips test files**: a security-tail test mentioning `mcp(` no longer blocks the doctor (the app used Payload's own MCP plugin), and `admin(` in prose or another package's API is noise, not a plugin. The unverified-users warning now matches the imported-identity semantics ([#69](https://github.com/jellologic/payload-auth-link/issues/69)): imported unverified users are pre-linked and resolve on their next sign-in after verifying — no operator action required.
  - **Node parity**: vitest inlines the CSS-bearing `@payloadcms/ui` chain and stubs CSS (an externalized `react-image-crop` stylesheet crashed some Node runtimes with `Unknown file extension ".css"`), and CI adds a Node 20/22/24 matrix running the suite under each runtime.

  Upgrade impact: none stored — the pre-flight runs before any database access; CLI behavior on an untouched config changes from an indefinite hang to a fast named failure with exit 1.

## 0.4.1

### Patch Changes

- Updated dependencies [[`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe)]:
  - @payload-auth-link/core@0.6.1
  - @payload-auth-link/next@0.3.3

## 0.4.0

### Minor Changes

- [#73](https://github.com/jellologic/payload-auth-link/pull/73) [`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c) Thanks [@jellologic](https://github.com/jellologic)! - The migration kit fails closed, matches real payload-auth layouts, and links imported users so they can actually sign in (issues [#68](https://github.com/jellologic/payload-auth-link/issues/68)–[#71](https://github.com/jellologic/payload-auth-link/issues/71), found running the kit against a production payload-auth database with custom slugs and 17% unverified users).

  - **Fail-closed source layout ([#68](https://github.com/jellologic/payload-auth-link/issues/68)).** The importer, `verify`, the exporter and the doctor no longer hardcode payload-auth's default table names or skip missing tables silently: a missing expected table or column is a blocker (exit 1, nothing written) naming the table and the new `--source-map '{"accounts":"user_accounts","sessions":"user_sessions"}'` override. `verify` is strict — exact per-model equality, zero never skips, extra target rows fail — and the api-key orphan check probes `reference_id` (better-auth's real column) with a `user_id` fallback. `export --tables` reports missing tables and exits non-zero instead of exporting a lossy "lossless" file.
  - **Imported users can sign in ([#69](https://github.com/jellologic/payload-auth-link/issues/69)).** The importer pre-links every imported user (verified or not, credential-only included) with `{ providerId: 'better-auth', providerUserId: <their ba-users id> }` — the identity the plugin actually looks up — so a user who verifies after the import resolves to their original document instead of being stranded. The verification gate still governs `linkable` proofing; `verify` now checks every imported user's identity resolves.
  - **Codemods match real usage ([#70](https://github.com/jellologic/payload-auth-link/issues/70)).** Rewritten on the TypeScript compiler API: `getPayloadAuth` from `'payload-auth'` or `'payload-auth/better-auth'` with any argument, `getSession({ headers: … })` in any shape, aliased imports, `import type` — and every reference the rules cannot rewrite is reported under manual follow-up (nothing silently ignored). `typescript` is now a regular dependency.
  - **The doctor runs where people will use it ([#71](https://github.com/jellologic/payload-auth-link/issues/71)).** `better-auth` is no longer a peer (installing the kit no longer upgrades the app's better-auth and breaks it); an unloadable config becomes a `config-unloadable` blocker with a static-analysis report instead of a crash (including the mid-upgrade `oidcProvider` state); plugin detection scans the whole `--src` tree (admin, anonymous, magicLink, nextCookies, genericOAuth, …) and names files; CLI errors are prefixed with the command name.

  Upgrade impact: none stored — source tables are read, never written. Behavior: runs that silently imported zero credential accounts from custom-slug layouts now abort with the exact fix in the message; re-run `doctor`, then the importer with `--source-map` if your slugs differ. `codemod --write` now persists rewrites for the patterns it actually matches.

### Patch Changes

- Updated dependencies [[`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c)]:
  - @payload-auth-link/core@0.6.0
  - @payload-auth-link/next@0.3.2

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
