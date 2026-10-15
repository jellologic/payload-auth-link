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

Requires Bun (`bunx`): the doctor loads the app's config module with
Bun's module loader, which tolerates the directory imports
payload-auth's dist uses.

Peers: `payload` ^3.83.0 || 4.0.0-beta.0 (the import commands boot the
app's own Payload instance; the doctor itself only reads) and
`@payload-auth-link/next` ^0.3.3 (optional — only the codemod's
emitted route handlers need it). `better-auth` is NOT a peer since
0.4.0: installing the kit must never touch the app's own better-auth
dependency (the #71 rehearsal finding), and the doctor falls back to
static analysis when the app sits outside the validated band.
