# Upgrade Resilience Plan (temporary working plan)

Status: temporary checklist from the 2026-10-13 deep dive. Delete or
fold into `docs/` once every item lands. Goal: a Payload CMS,
Better Auth, Auth.js, or payload-auth-link update must never break a
user's database or install the way updates repeatedly broke
[payload-auth](https://github.com/payload-auth/payload-auth).

## Why payload-auth breaks on updates (evidence)

- **It generates Payload collections from Better Auth's live schema**
  (`getAuthTables` / `getSchema` from `better-auth/db` →
  `transform-schema-fields-to-payload.ts`,
  `sync-resolved-schema-with-collection-map.ts`, plus a CLI that
  regex-parses and rewrites the user's schema file). Any Better Auth
  field addition/change silently rewrites the user's Payload schema,
  so the next boot hits a DB schema diff, push warnings, or admin
  crashes (issue #88: a BA `onUpdate` function leaked into a field
  config and broke the admin panel).
- **It consumes unstable BA internals**: `better-auth/db`,
  `better-auth/api` helpers, client-plugin re-exports, hand-rolled
  adapter transaction wrappers. BA minors move these (issue #108:
  `passkeyClient` export removed → build break; issue #160: new
  adapter method `consumeOne` missing → runtime `TypeError`).
- **Wide peer ranges, single-version testing** (`better-auth
  > =1.5.0 <2`, `payload >=3.79.1 <4`, dev pinned to one version).
Users bump inside the "supported" range and break (issue #151:
duplicate Payload copies → incompatible `Config` types).
- **BA's schema is merged into the Payload users collection**
  (role field transformations, issue #112), so BA churn hits the
  application's most central table.

## Where we already differ (keep these)

- Provider collections are **hand-written, static** `ba-*` / `aj-*`
  Payload collections; BA's schema never generates ours, and Payload
  owns the `users` collection.
- The BA adapter **validates the live BA schema at startup and fails
  fast both ways** (`UnsupportedSchemaError` naming the field), and
  a committed schema-probe test pins BA's full field/model inventory
  as a drift alarm.
- The adapter is built on BA's official `createAdapterFactory`, and
  the session wire parser is forward-compatible (legacy shapes
  normalize instead of throwing).

## Break attempts against payload-auth-link 0.2.0 (observed)

- **B1 — DB upgrade, production mode (push off).** Booting 0.2.0 on a
  seeded 0.1.1 SQLite DB starts fine, then the first `users` query
  dies with raw `SQLITE_ERROR: no such column: phone`. No startup
  guard, no actionable message, and `docs/upgrading.md` has no
  0.2.0 section at all.
- **B2 — DB upgrade, dev mode (push on).** Boot hangs on drizzle's
  interactive `DATA LOSS WARNING` prompt (new required unique `key`
  column on `aj-verification-tokens`). Accepting recreates that
  table empty (seeded token lost), then the `ba_users` table
  rebuild (triggered by the `name` required → optional change)
  generates `INSERT INTO __new_ba_users (... is_anonymous ...)
SELECT ... is_anonymous FROM ba_users` → `no such column:
is_anonymous` on every boot; the `users` columns are never added.
  The DB is left half-migrated and unbootable. No upgrade test
  existed to catch any of this.
- **B3 — Better Auth range is false.** Shipped source does not
  compile against BA 1.6.33 (5 errors, `modelKey`) or 1.4.22
  (11 source errors); the true floor is 1.7.x. Declared:
  `better-auth: ^1.0.0` as a direct **dependency** (not a peer), so
  every fresh install floats to the newest 1.x — a future BA minor
  that adds a core field will brick boot via our own fail-fast
  (data-safe, but downtime), and a semantics-only change could pass
  types and misbehave. Same pattern for `@auth/core` (its 0.x caret
  is narrow by accident, not design).
- **B4 — Payload range is false.** Plugin source does not compile
  against Payload 3.50.0 (`GlobalBeforeOperationHook`, globals
  `beforeOperation`, named-plugin `slug`/`options`); peer claims
  `^3.0.0 || ^4.0.0-beta.0`. The providers (Local API only) did
  compile — coupling is concentrated in the plugin.
- **B5 — Guardrails absent.** CI tests exactly one version set; no
  dependabot/renovate; no runtime version assertion; examples are
  push-only with zero migration files or production-migration
  guidance; `docs/upgrading.md` still describes pre-release 0.0.1.

### Second round (same day, deeper hunting)

- **B6 — Postgres variant of B2: converges, same two costs.**
  Accepting the push prompt on Postgres completes (columns added,
  indexes swapped `token` → `key`, boot + writes green). But the
  interactive `DATA LOSS WARNING` hang and the emptied
  `aj_verification_tokens` table are identical, and in migrations
  mode the generated `ADD COLUMN key NOT NULL` **provably fails**
  on a non-empty table (`column "key" contains null values`,
  demonstrated). So neither SQL adapter has a working 0.1.1→0.2.0
  path today; Postgres push users just lose less.
- **B7 — MongoDB: boots fine, constraints silently wrong.** Schema
  drift can't crash Mongo (upgrade boots, writes succeed), but
  index lifecycle is the trap: Payload's adapter sets mongoose
  `autoIndex: true` and never calls `syncIndexes` (verified in
  adapter source), so **removed** unique indexes (aj `token`)
  persist forever — the 0.2.0 composite-key fix silently doesn't
  apply to upgraded Mongo deployments until a human drops the old
  index — and **added** unique indexes (aj `key`) build in the
  background over rows lacking the field and fail on duplicate
  nulls, leaving uniqueness silently unenforced. Observed too:
  short-lived processes exit with index builds half-finished
  (only 2 of ~10 unique indexes present after boot).
- **B8 — Downgrade/rollback is unsafe in push mode.** Booting
  0.1.1 on a 0.2.0 SQLite DB prompts to **delete** the 0.2.0
  columns (`key`, `is_anonymous`, `two_factor_enabled`, …);
  accepting destroys 0.2.0 data, declining exits the process
  silently with no error. In migrations mode the old code boots,
  but its Auth.js token writes fail (`NOT NULL constraint failed:
aj_verification_tokens.key`, demonstrated) — rollback breaks
  Auth.js email flows.
- **B9 — Rolling-deploy skew (old + new pods, one DB).** Same
  mechanism as B8's write failure, mid-deploy instead of rollback:
  a not-yet-upgraded pod cannot write Auth.js tokens once the
  schema is migrated, and it doesn't know `suspendedUntil`, so a
  suspended user keeps verifying on old pods until the rollout
  finishes. We have no stated N/N−1 compatibility criterion.
- **B10 — Prerelease peer range leaks canaries.** `payload:
^4.0.0-beta.0` admits 4.0.0-canary.39 by semver prerelease
  ordering, and our plugin already fails typecheck against it
  (access-args gained a required `slug`; 1 shipped-source error,
  25 test errors). Anyone tracking Payload v4 canaries is inside
  our declared range and broken.
- **B11 — Config changes can break the DB without any package
  update.** Roles are a Payload `select` field, which on Postgres
  is a native enum (`enum_users_roles`, observed). Removing or
  renaming a role in `authLink({ roles })` while rows use it makes
  enum recreation fail on push/migrate. Softer variant: stored
  roles are format-validated, not membership-validated, so a
  removed role keeps being granted in sessions until any user-doc
  write silently drops it. Neither behavior is documented.
  (Organization slug collisions, by contrast, are already guarded
  with a typed startup error — keep that pattern.)
- **B12 — BA satellite lockstep chain.** `@better-auth/passkey`
  peers `better-auth: ^1.7.7` (exact-minor lockstep). When a
  satellite ships for BA 1.8, it will force BA to 1.8 under our
  users before we've validated 1.8's schema — and our fail-fast
  then bricks boot. Satellite/core/provider compat is a three-way
  matrix we don't state anywhere.
- **B13 — Framework ranges are unbounded or floor-false too.**
  `next: >=15.0.0` admits Next 16.4 (import smoke passes; the
  middleware→proxy convention change is unverified end-to-end).
  TanStack peers `^1.0.0` / `^1.120.0` admit early 1.x versions
  lacking APIs we use (untested floor; we validate ~1.168/1.170).
- **B14 — Verified non-issues (keep as regression checks).**
  Published 0.2.0 tarballs install and import cleanly under both
  npm and pnpm consumers (pnpm caveat: direct
  `@payload-auth-link/core` imports need core installed
  explicitly — strict-linker behavior, worth one docs line). No
  phantom dependencies in shipped code. Our inter-package deps
  publish as exact pins, so partial upgrades can't skew our own
  packages. Import surface on Payload is small (`payload` only,
  one `@payloadcms/ui` hook).

### Third round (2026-10-13, type-safe alarms + schema interop)

- **B15 — Our own `zod` range is false the same way.** Core declares
  `zod: ^4.0.0`; only 4.6.5 is ever installed or tested, while BA
  requires `^4.5.4` and Payload v4 `^4.6.0`. Core also exports live
  Zod schema objects (`emailSchema`, `roleSchema`, …): a consumer
  composing one inside a Zod 3 schema (common in Payload-3-era
  trees) gets a runtime crash, not a type error.
- **B16 — Hand-synced union/schema pairs drift silently.**
  `AuthMethod` (type, `ports.ts`) and `authMethodSchema` (`z.enum`,
  `http.ts`) were two manually duplicated lists with no compiler
  link, and `sessionChannels: readonly SessionChannel[]` accepted a
  _missing_ member without error. Adding a variant to one side
  degraded sessions at runtime instead of failing `tsc`. (Fixed in
  Phase 3b: single-source derivation + `expectTypeOf` pins.)
- **B17 — Switches without `assertNever` discover new upstream
  variants in production.** `event.type`
  (`apply-identity-event.ts`), BA `field.type` (`collections.ts`),
  and the BA where-operator switch fell through or threw at
  runtime. A new variant must fail CI typecheck, not boot.
- **B18 — No public-API type snapshot.** `index.test.ts` pinned two
  exports; a breaking `.d.ts` change (e.g. a new required
  `UserRepository` method breaking every custom adapter) could
  ship as a patch. `attw`/`publint` check packaging, not surface.
- **B19 — `skipLibCheck: true` + TS-6-only build mask consumer
  breakage.** Broken upstream `.d.ts` and our declarations under a
  consumer's TS 5.x were never exercised; no TS floor was stated.
- **B20 — Silent wire degradation, inconsistent alerting.**
  `parseSessionUser` degraded malformed `assurance`/`actor`
  fail-closed with no log or hook, while one unparsable role nulled
  the whole session (logout loop, zero signal); `mapping.ts` warned
  per-row with no dedupe. Policy now: degradation is typed,
  observable once, and never silently grants anything.
- **B21 — Effect users had no bridge, and the bridge was unpinned.**
  Ports return neverthrow `ResultAsync`; errors carry `code`, not
  `_tag`. Verified locally: Zod 4.6.5 schemas expose `~standard`
  (`vendor: 'zod'`, `version: 1`, `validate`, `jsonSchema`) and
  Effect converts its schemas via `Schema.standardSchemaV1`, so
  Standard Schema is the two-way bridge — but nothing pinned it and
  `@standard-schema/spec` was undeclared. Decision: Zod stays the
  implementation, Standard Schema is the public boundary type, and
  `effect` is a dev-only interop test — never a core runtime dep.
- **B22 — Probe blind spots.** BA `api-key`/`sso` satellites are
  `it.skip` in the schema probe (users adding them meet
  `UnsupportedSchemaError` with no advance warning), and Auth.js
  adapter conformance was runtime-only: a newly added optional
  `@auth/core` `Adapter` method passed silently. A `keyof Adapter`
  type pin now alarms at compile time (Phase 3b).

## Success criteria

- The seeded 0.1.1 database boots on the next release in both push
  and migrations modes, with users/identities/sessions intact
  (verification-token invalidation is the only allowed loss, and it
  is documented) — on all three adapters, with Mongo indexes
  reconciled. The previous minor also boots and serves core flows
  on the new schema (rollback/rolling-deploy safety).
- Declared version ranges equal CI-tested bands; a fresh install
  cannot resolve an untested Payload/BA/Auth.js version silently.
- An unsupported upstream version fails at startup with a typed,
  actionable error — before any DB write — never as a raw SQL or
  `TypeError` crash mid-request.
- Every future schema change ships with an upgrade test and an
  `upgrading.md` entry; CI enforces both.

## Checklist

### Phase 0 — Stop the bleeding (patch release)

- [x] Make the `aj-verification-tokens.key` addition upgrade-safe:
      drop the DB-level `required` (unique index tolerates NULLs on
      SQLite/Postgres), keep adapter-side write + validation, and
      backfill lazily on read/write. Verify no table recreation on
      SQLite push against the 0.1.1 seed.
- [x] Remove the SQLite table-rebuild trap on `ba-users.name`:
      restore DB-level NOT NULL and accept BA's `name: ""` writes
      via field-level validation instead of the `required` flag (or
      equivalent that leaves the physical column unchanged).
- [x] Re-run B1/B2/B6 after the two fixes above (SQLite + docker
      Postgres, push and production modes) and record outcomes.
- [x] Mongo index reconciliation for B7: ship an idempotent
      upgrade script (or startup warning via `LoggerPort`) that
      drops the stale `token` unique index and reports a failed
      `key` index build; document the manual `dropIndex` step in
      the 0.2.0 upgrade notes for already-upgraded deployments.
- [x] Write the missing `docs/upgrading.md` 0.2.0 section (exact DB
      steps per adapter and mode; token invalidation note) and fix
      its stale pre-release wording; add a troubleshooting entry
      mapping `no such column` errors to the upgrade steps.
- [x] Ship as patch changesets with the upgrade notes in the
      changeset text (they surface in CHANGELOGs).

### Phase 1 — Version-range honesty

- [x] Bisect true floors: BA (confirm first working 1.7.x patch),
      Payload (named-plugin + global-hook APIs; test 3.6x/3.7x),
      `@auth/core`, `@better-auth/passkey`, TanStack (v4 beta line).
- [x] Decide and implement dep → peer for `better-auth` and
      `@auth/core` (install-breaking: migration note, keep a clear
      "module not found" failure mode, update examples/docs), with
      ranges set to the tested bands from the bisect; align
      `payload` peers the same way.
- [x] Add a runtime version assertion at engine/plugin init: read
      the installed upstream version, compare to the supported band,
      throw `UnsupportedVersionError` (found vs supported + docs
      link) before any collection write.
- [x] Add CI: a scheduled + dispatchable compatibility workflow
      running typecheck + unit + schema-probe on {floor, latest} ×
      {Payload, BA}; a non-blocking canary job that installs
      `payload@beta`/latest BA unpinned to detect drift early.
- [x] Enable dependabot (or renovate) for `packages/*` and
      `examples/*` so upstream bumps arrive as reviewed PRs that
      run the full gates.
- [x] Fix the framework ranges (B13): cap `next` below the next
      unvalidated major, bisect true TanStack floors, and verify
      Next 16's middleware/proxy convention end-to-end in the
      example (docs + e2e) before claiming it.
- [x] Close the prerelease leak (B10): pin the v4 peer to the
      exact tested beta (`4.0.0-beta.0`, no caret) until a canary
      policy exists; cover prerelease ordering in the
      range-setting checklist.
- [x] Publish the three-way BA lockstep rule (B12) in
      `docs/compatibility.md`: core BA and `@better-auth/*`
      satellites move together, and both move only within our
      validated band; note it in the provider README install
      section.

### Phase 2 — Upgrade-safety engineering

- [x] Golden-DB upgrade tests: committed seed generation for the
      0.1.1 schema (script + SQLite fixture produced in CI from the
      tag) and a test that boots current code on it in push mode
      and migrations mode, asserting boot, sign-in, session verify,
      and row survival. Add the reverse (new DB on previous minor)
      for rollback safety. Wire into `bun run check` and the
      release checklist.
- [x] Schema-change policy in `AGENTS.md` + `docs/`: additive-only
      by default; no new NOT NULL column without a DB default or
      backfill plan; no nullability/type/unique changes or renames
      on existing columns without a two-release
      expand → backfill → contract sequence.
- [x] Schema-snapshot CI gate: snapshot every package's collection
      configs as JSON; a PR that changes a snapshot must include a
      changeset section `Upgrade impact:` and an `upgrading.md`
      entry, or CI fails.
- [x] Production migrations story: example (or docs recipe) running
      with migrations instead of push, generated migration files
      attached to each release's upgrade notes for SQLite/Postgres.
- [x] Deploy-skew criterion (B8/B9): state and test N/N−1
      compatibility — previous minor must boot and serve core
      flows on the new schema (extra columns ignored, no NOT NULL
      without default ever ships), and new code must tolerate
      pre-migration rows. Add both directions to the golden-DB
      suite; document that dev-push makes downgrades destructive
      (Payload behavior) and is unsupported for rollback.
- [x] Role-config safety (B11): document a role removal/rename
      runbook (drain assignments first), warn at startup when
      stored role values exist outside the configured set
      (one aggregate `LoggerPort` warning, fail-open read /
      never grant unconfigured roles — decide explicitly), and
      add a config-change test (role removed between boots).
- [x] Consumer-install smoke in `release:check` (B14): pack
      tarballs, install into throwaway npm + pnpm consumers,
      import every public entry (incl. `/cookies`, `/admin`);
      document the pnpm explicit-core-install line.

### Phase 3 — Reduce coupling further

- [x] Confine every `better-auth/db` and `better-auth/cookies`
      import to one module per package, behind the Phase-1 version
      assertion; add conformance tests for the cookie helpers.
- [x] Adapter-contract exhaustiveness: compile-time test that our
      BA `CustomAdapter` and Auth.js `Adapter` implementations
      satisfy the full installed upstream interfaces, so newly
      added upstream methods (the `consumeOne` class) fail CI
      typecheck instead of production requests.
- [x] Pin an inventory of imported `payload` / `payload/shared`
      symbols in a test; new imports require a compatibility note
      (they set our real Payload floor).

### Phase 3b — Type-safe alarms & schema interop (B15–B22)

Alarm order: compiler first, CI snapshot second, typed runtime
alert last. Every check fails at the earliest layer that can
express it; runtime alerts cover only what exists solely at
runtime (installed versions, stored rows, wire payloads).

- [x] Single-source every union/schema pair: `authMethods` tuple in
      `ports.ts` derives both `AuthMethod` and (via `z.enum`)
      `authMethodSchema`; `sessionChannels` is an `as const` tuple
      with `SessionChannel` derived from it. Pin all
      `z.output` ↔ domain-type pairs in
      `core/src/__tests__/type-alarms.test.ts` (`expectTypeOf`).
- [x] `assertNever` in every discriminated-union switch
      (`apply-identity-event`, BA `collections`, BA `where`), plus
      a structural test that fails when a new switch over a union
      lacks it.
- [x] Standard Schema contract: declare `@standard-schema/spec`
      (type-only surface) in core; test that every exported schema's
      `~standard.validate` agrees with `safeParse` and that
      `InferOutput` equals the domain type.
- [x] Bisect the true `zod` floor: **the claimed `^4.0.0` floor is
      true.** Core source typechecks against zod 4.0.0 types and the
      built `dist` passes a runtime probe (all parsers + every
      schema's `~standard.validate`) on 4.0.0 / 4.0.17 / 4.1.0
      (`/tmp/zodfloor` probe, 2026-10-13). Range stays `^4.0.0`; a
      zod {floor, latest} CI cell still rides the Phase-1 matrix.
      Documented: exported schemas are Zod 4 / Standard Schema —
      compose via `~standard`, never inside a Zod 3 schema. Also
      bisected: the consumer TypeScript floor is **5.5** (5.5.4
      passes the strict consumer fixture; 5.0.4 fails inside Zod
      4.6's own types, `NoInfer`).
- [x] Effect interop proof with `effect` as a devDependency only:
      decode core schemas inside an `Effect` via
      `~standard.validate`, convert a `ResultAsync` port call to an
      `Effect`, and document the recipe. No `effect` import may
      reach shipped source (lint + size budget prove it). A shipped
      `/effect` subpath with `Layer`s waits for a user request.
- [x] Public-API `.d.ts` snapshot per package
      (`scripts/api-snapshot.mjs`, gated in `bun run check`): a
      snapshot change requires a changeset with semver
      justification. Add a `skipLibCheck: false` consumer fixture
      typechecking built `dist` types, and state the tested
      TypeScript floor in `docs/compatibility.md`.
- [x] Typed degradation alerts: `parseSessionUser` accepts an
      `onDegrade` callback with a reason union; plugin `mapping.ts`
      row warnings aggregate once per kind per process. Tests cover
      the newer-server/unknown-`AuthMethod` forward-compat path.
- [x] Auth.js `keyof Adapter` type pin so upstream-added adapter
      methods fail typecheck; document the unprobed BA
      `api-key`/`sso` satellites as unsupported-until-probed next to
      the `UnsupportedSchemaError` guidance.

### Phase 4 — Process

- [x] Support policy in `docs/compatibility.md`: supported bands
      are exactly the CI matrix; recommend exact pins; state the
      compat-patch commitment window after an upstream minor.
- [x] Release checklist (release workflow PR template or
      `docs/` runbook): upgrade tests green, schema snapshot
      reviewed, `upgrading.md` current, compat matrix regenerated
      from the matrix workflow results.

## Validation plan

- Phase 0: re-run the 0.1.1 seed boot in dev-push and
  `NODE_ENV=production` modes on SQLite; same against docker
  Postgres; `bun run check`; targeted e2e (`passwordless`,
  `security`) to confirm no behavior change.
- Phase 1: scratch installs at each claimed floor/ceiling
  (`bun run build`, unit suite, schema-probe) mirroring the B3/B4
  method; matrix workflow green on all cells.
- Phase 2: the golden-DB tests are the evidence; demonstrate the
  CI gate blocks a synthetic schema change without upgrade notes.
- Phase 3: `bun run check` with the new exhaustiveness/inventory
  tests; simulate drift by bumping BA in a scratch worktree and
  confirming CI-style checks fail with the new typed errors.

## Risks / open questions

- Dep → peer (Phase 1) is install-breaking for existing users;
  needs a minor release and prominent migration notes. Alternative
  (exact-pin the dependency) keeps installs working but forces our
  BA version on users — decide before Phase 1 starts.
- A runtime schema-version stamp (considered and deferred) would
  itself be a schema change; only adopt if the startup version
  assertion + upgrade tests prove insufficient.
- Drizzle push behavior differs per database (resolved by B6/B7:
  Postgres converges after the prompt, SQLite rebuilds and fails,
  Mongo never blocks but leaves wrong indexes) — every schema
  change needs per-adapter upgrade evidence, not one.
- Exact Payload floor between 3.50.0 and 3.90.2 is not yet
  bisected; Phase 1 owns the number, the matrix owns its proof.
