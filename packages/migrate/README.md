# @payload-auth-link/migrate

The payload-auth → payload-auth-link migration kit
([issues #49–#59](https://github.com/jellologic/payload-auth-link/issues/59)):
a read-only **doctor/preflight** today, with the runnable importer and
exporters riding the same CLI as they land (#50, #58).

## Doctor (read-only preflight)

```sh
bunx @payload-auth-link/migrate doctor --config ./src/payload.config.ts --src ./src
```

Reports, without writing anything:

- **Version bands** — payload, better-auth, next against the supported
  bands (better-auth 1.6 → 1.7 removed `oidcProvider`, so apps using it
  are flagged).
- **Better Auth plugins** — supported, auto-declarable, unprobed, or
  removed upstream, derived from the collections payload-auth built and
  the plugin calls in the config source.
- **The users collection** — field collisions with the plugin's
  injected fields, the existing role field and its values
  (non-canonical values such as `frontPlugin`), and whether Payload's
  local strategy is on.
- **0.7.0 behaviour changes that will bite** — provider-owned
  documents, suspension on every strategy, access defaults, the
  `req.user` projection.
- **Source scan** — `payload-auth/*` imports, `payload.betterAuth` /
  `getPayloadAuth` call sites, `$context` internals, and
  `req.user.<field>` reads outside the session projection.
- **Database** (with `--database-url` or `DATABASE_URL`) — row counts
  per auth table, unverified users (who will not JIT-link), and
  orphans.

Output: human-readable text, or `--json` for tools. Exit codes:
`0` clean, `1` blockers, `2` warnings only, `3` usage errors.

Every finding carries a stable machine `code`, so CI (and the
migration guide) can assert exact blocker lists. The authoritative
exercise of the doctor lives in the repo's payload-auth fixture
(`fixtures/payload-auth-app`), where the CI job pins the exact
blockers it must report — and none it must not.

## Importer lifecycle

`from-payload-auth` (dry run; `--apply` writes), `verify`, `rollback`,
and `finalize` all take `--config` (the TARGET app) and share one
signed manifest — see
[docs/migrating-from-payload-auth.md](../../docs/migrating-from-payload-auth.md):

- `rollback` deletes only rows in the import's own target collections
  that still carry the importer's `baId`; a failed delete exits
  non-zero with the rows named and the manifest kept.
- `finalize --config …` records the finalize in the app's database
  (Payload's `payload-kv` store) and re-signs the manifest; rollback
  is refused afterwards, whatever the file says.
- `--allow-unsigned-manifest` accepts a pre-0.6.0 manifest (or a
  0.6.0 one for rollback) but never deletes; add
  `--allow-unsigned-deletes` after reviewing its created rows.
- `export --source-map …` exports a renamed layout; a mapped table
  that is missing exits 1.

Requires Bun (`bunx`): the doctor loads the app's config module with
Bun's module loader, which tolerates the directory imports
payload-auth's dist uses.

Peers: `payload` ^3.83.0 || 4.0.0-beta.0 (the import commands boot the
app's own Payload instance; the doctor itself only reads) and
`@payload-auth-link/next` ^0.6.0 (optional — only the codemod's
emitted route handlers need it). `better-auth` is NOT a peer since
0.4.0: installing the kit must never touch the app's own better-auth
dependency (the #71 rehearsal finding), and the doctor falls back to
static analysis when the app sits outside the validated band.

`typescript` is a dependency only for the `codemod` command (it parses
call sites with the compiler API); it is imported lazily, so importing
the package or running `doctor`/import/export never loads it. The
public types reference no `pg` types (source reads take the structural
`SourceClient`), so consumers need no `@types/pg`.
