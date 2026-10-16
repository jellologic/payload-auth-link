---
'@payload-auth-link/core': minor
'@payload-auth-link/web': minor
'@payload-auth-link/react': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/next': minor
'@payload-auth-link/tanstack-start': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
'@payload-auth-link/migrate': minor
---

Release and supply-chain hardening (#85).

- Every package tarball now ships the MIT `LICENSE` (previously no
  tarball carried it).
- Releases publish only after the full CI workflow passes on the exact
  commit, from a dedicated `npm-publish` environment, with npm
  provenance. Local publishing is refused outside an explicit,
  documented emergency override.
- `@payload-auth-link/migrate`: the published `.d.ts` no longer
  references `pg`, so consumers type-checking with
  `skipLibCheck: false` no longer fail with TS7016 (no `@types/pg`
  needed). `openSource` and the source readers (`probeSourceLayout`,
  `countTables`, `readSourceUsers`, `readFlatRows`, `findOrphans`) now
  type their client as the new exported structural `SourceClient`
  (`query` + `end`); a `pg.Client` still satisfies it. Code that used
  `openSource()`'s result as a full `pg.Client` must narrow to those
  two methods or open its own `pg` client.
- `@payload-auth-link/migrate`: the TypeScript compiler API is loaded
  lazily, only by the `codemod` command; importing the package or
  running `doctor`/import/export no longer loads it.

Upgrade impact: none for stored data or schemas (no collection shape
changed). Type-level only for `@payload-auth-link/migrate` API
consumers, as described above.
