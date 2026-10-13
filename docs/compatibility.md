# Compatibility

The **supported bands are exactly the CI-tested matrix**: the
`compat` workflow proves `{floor, latest}` per upstream (build +
unit + schema-probe), the e2e suites run every release against
SQLite, Postgres, and mongo, and the golden-DB tests keep the
previous minor's database booting. A range below is a promise only
as wide as those cells; the runtime version assertions
(`UnsupportedVersionError` at wiring time) enforce the same bands
before any database write.

Support policy: recommend **exact pins** for upstreams in your
lockfile (the manifests' ranges exist so fresh installs resolve
something tested, not so every version is blessed). After an
upstream minor lands, the compat patch that widens the band is the
next release — file or watch an issue; until then the old band
holds and the assertion fails fast with a typed error instead of
letting an unvalidated version touch your database.

**Better Auth lockstep (three-way rule):** `better-auth` core and
every `@better-auth/*` satellite you enable (`@better-auth/passkey`
today) move **together**, and only within our validated band.
Satellites peer-lock to exact BA minors — when a satellite ships for
BA 1.8, installing it forces BA 1.8 under you — so bump satellites
and core in one commit, run the provider's schema probe (it fails
fast on unvalidated BA schemas), and never let a satellite drag you
outside the band: the version assertion will refuse to boot, which
is the intended outcome. Unprobed satellites (`@better-auth/api-key`,
`@better-auth/sso`) are **unsupported until probed**: adding one
meets `UnsupportedSchemaError` with this same fail-fast.

## Runtimes and frameworks

| Dependency                               | Validated (floor / installed) | Range (peer unless noted)           | Notes                                                                               |
| ---------------------------------------- | ----------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------- |
| `payload`                                | 3.83.0 / 3.90.2               | `^3.83.0 \|\| 4.0.0-beta.0`         | v3 for Next; 3.83 is the named-plugin/global-hook floor; v4 pin is exact            |
| `payload` (Start)                        | 4.0.0-beta.0                  | exact beta pin (example)            | `@payloadcms/tanstack-start` exists only on the v4 line                             |
| `better-auth`                            | 1.7.6 / 1.7.7                 | `>=1.7.6 <1.8.0`                    | Type-level floor 1.7.6 (`modelKey` types); validated 1.7 line only — lockstep above |
| `@auth/core`                             | 0.41.0 / 0.41.3               | `>=0.41.0 <0.42.0`                  | Raw core, not the `next-auth` wrapper; 0.x minors add Adapter methods               |
| `next`                                   | 15.0.0 / 16.4.0               | `^15.0.0 \|\| ^16.0.0` (next pkg)   | Both majors typecheck; 16.4 e2e-tested by the example                               |
| `@tanstack/react-start` / `react-router` | 1.140.2 / 1.168.61 · 1.170.41 | `^1.140.2` / `^1.170.0` (start pkg) | 1.140.2 is the `createMiddleware` types floor                                       |
| `vite` (Start)                           | 8.3.4                         | dev (example)                       | + `@vitejs/plugin-rsc`, `react-server-dom-webpack` for Payload admin                |
| `react` / `react-dom`                    | 19.2.6                        | `^19.0.0` (peer, UI pkgs)           |                                                                                     |
| `neverthrow`                             | 8.2.0                         | dep                                 | `Result`/`ResultAsync` throughout                                                   |
| `zod`                                    | 4.6.5 (floor 4.0.0)           | dep                                 | Boundary schemas + branded types; floor proven by probe (see below)                 |
| `@standard-schema/spec`                  | 1.1.0                         | dep (types)                         | Every exported schema is a Standard Schema v1                                       |
| `typescript` (consumer)                  | 5.5.4 / 6.0.3                 | —                                   | Floor is 5.5; 5.0 fails inside Zod 4.6's own types (`NoInfer`)                      |
| `effect`                                 | 3.22.2                        | dev only                            | Interop tested in CI; never a runtime dependency (recipe below)                     |
| `bun`                                    | 1.4.2                         | `packageManager`                    | CI pins the same                                                                    |
| `node`                                   | 20.9+ / 22                    | `engines`                           | All packages ESM-only (`type: module`)                                              |

Module resolution: shipped code builds under `nodenext`, except
`@payload-auth-link/next`, which uses `esnext`/`bundler` because
Next.js ships no `exports` map for `next/*` subpaths. Tests run
under bundler resolution for the same reason.

## Databases

| Adapter                   | Validated how                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `@payloadcms/db-sqlite`   | Unit integration (in-memory) + `bun run e2e`                                          |
| `@payloadcms/db-postgres` | `bun run e2e:postgres` (per-run database, `push: true`), GH service in CI             |
| `@payloadcms/db-mongodb`  | `bun run e2e:mongo` (per-run wiredTiger memory replset, transactions off — see below) |

Product code issues only single-document Local API calls, so the
parity risk sits in Where translation, date serialization, and id
types — all six suites assert identical behavior (33 specs each:
`e2e`, `e2e:postgres`, `e2e:mongo` on Next; `e2e:tanstack`,
`e2e:tanstack-postgres`, `e2e:tanstack-mongo` on Start). Each
example's mongo branch disables Payload transactions: several
Payload instances (plugin + provider loaders) lock-fight on a
single-node memory server. Production mongo deployments keep
transactions on; nothing we ship depends on their absence.

## Browsers

The SQLite suites (`e2e`, `e2e:tanstack`) run in Chromium, Firefox,
and WebKit (Playwright Desktop Chrome / Firefox / Safari profiles),
one engine after another against the same server. Postgres and Mongo
suites run Chromium only. Traces are kept on failure; CI retries
exist as a backstop, but specs pass with retries off. The shipped UI
is unstyled primitives with no browser-specific APIs beyond `fetch`
and `location`.

## Sign-in capabilities by provider

Canonical capability matrix (how to wire each row:
[Capabilities guide](guide-capabilities.md)). Capabilities are
**declared per provider and checked at wiring** — configuring a
feature on an undeclared capability throws
`UnsupportedCapabilityError` at startup, never silently at runtime.
✅ works · ◐ partial/recipe · — not available.

| Capability                      | Better Auth 1.7.7                    | Auth.js (`@auth/core` 0.41.3) | Notes                                                          |
| ------------------------------- | ------------------------------------ | ----------------------------- | -------------------------------------------------------------- |
| Email/password                  | ✅                                   | ✅ credentials service        | Verified-email linking gate on both                            |
| Magic link                      | ✅ `magicLink`                       | ✅ Email provider             | Single-use; dev mailbox in examples                            |
| Email OTP                       | ✅ `emailOTP` (native 3-attempt cap) | ✅ recipe helpers             | Auth.js attempts capped by your route                          |
| OAuth / OIDC                    | ✅ social + `genericOAuth`           | ✅ providers                  | Unverified assertions refused; Auth.js needs the D6 allow-list |
| One Tap                         | ✅ `oneTap` plugin                   | ◐ JWKS-verifier recipe        | No live-Google automated proof                                 |
| Passkeys                        | ✅ `@better-auth/passkey`            | — (experimental upstream)     | Session `methods` stay `unknown` (BA marks none)               |
| Two-factor (TOTP)               | ✅ `twoFactor` (enrollment-mapped)   | —                             | `requireMfaForRoles` throws on Auth.js                         |
| Suspend + revoke                | ✅                                   | ✅ database strategy only     | Payload verify gate also covers JWTs                           |
| Impersonation                   | ✅ audited, TTL-bounded              | —                             | Deny layers + audit trail in the plugin                        |
| Phone sign-in                   | ✅ `phoneNumber`                     | —                             | Links existing users only; never provisions                    |
| Anonymous / guest               | ✅ `anonymous`                       | —                             | Guest principal, no Payload access                             |
| Multi-session / bearer / device | ◐ logout sweeps all device sessions  | ◐                             | Admission is explicit (`admitChannels`)                        |
| Organizations                   | ✅ Payload-owned                     | ✅ Payload-owned              | Provider org stores are never authorization                    |
| Enterprise SSO domains          | ◐ registered-provider gate           | ◐ registered-provider gate    | Exact verified-domain match required                           |
| Identity lifecycle events       | ✅                                   | ✅ engine callbacks           | Optional subscription; core works without                      |

Framework support is uniform across the matrix: every row behaves
the same on Next.js and TanStack Start (one framework-free web
core), and every e2e spec runs against both examples.

## Type surface

`attw --profile esm-only` + `publint` gate every package
(`bun run release:check`). Legacy node10/CJS resolution is the
documented non-goal: ESM-only by decision.

More alarms run in `bun run check` so breakage is caught here, not
in your build:

- **API snapshots** (`snapshots/api/*.txt`, `bun run api:check`):
  the full shipped `.d.ts` surface of every package. Any change
  requires a changeset at the right semver level.
- **Schema snapshots** (`snapshots/schema/*.json`,
  `bun run schema:check`): the DB-facing collection shapes both
  providers ship and the plugin's injected users fields. A change
  must carry an `Upgrade impact:` changeset section and a
  [upgrading.md](upgrading.md) entry, or CI fails — a silent shape
  change is a broken user database.
- **Consumer fixture** (`bun run consumer:check`): the built `dist`
  types typechecked with `skipLibCheck: false` under the strictest
  flags, the way a strict consumer compiles.
- **Type pins** (`expectTypeOf` in `type-alarms.test.ts` and the
  adapter inventory alarms in both providers): union inventories,
  schema↔domain-type pairs, and the full `Adapter`/`CustomAdapter`
  method surfaces pinned literal-for-literal — an upstream-added
  adapter method fails `tsc`, not a production request.
- **Payload import inventory** (`payload-inventory.test.ts`): every
  `payload`/`payload/shared` symbol shipped source imports is
  pinned; a new import (which sets the real Payload floor) fails CI
  until it is verified against the band and noted here.

## Schema interoperability (Zod, Effect, Standard Schema)

Core's boundary schemas (`emailSchema`, `roleSchema`,
`providerIdSchema`, `phoneNumberSchema`, `linkingPolicySchema`,
`collectionMapSchema`, `startupConfigSchema`) are Zod 4 schemas and
therefore Standard Schema v1 objects: each carries
`~standard.validate` with `StandardSchemaV1.InferOutput` equal to
its domain type (`Email`, `Role`, …). That is the supported
composition surface for every schema ecosystem:

- **Do not** nest an exported schema inside a Zod 3 schema; the
  majors are runtime-incompatible. Compose through `~standard`, or
  validate with the paired parser (`parseEmail`, `parseRole`, …)
  and keep the branded result.
- **Effect users:** decode through `~standard.validate` inside
  `Effect.tryPromise`, convert your own schemas with
  `Schema.standardSchemaV1`, and lift neverthrow `ResultAsync` port
  calls with `Effect.promise` + `Result.match` (they never reject
  by contract). The recipe is pinned by
  `packages/core/src/__tests__/effect-interop.test.ts`, which runs
  in CI against the current Effect release; `effect` stays a
  devDependency — nothing shipped imports it.
- The `zod: ^4.0.0` floor is proven, not assumed: core source
  typechecks against Zod 4.0.0 and the built package passes a
  runtime probe on 4.0.0 (Better Auth's own `^4.5.4` requirement
  will float most real trees higher).
