## Goal

Replace `payload-auth/payload-auth` with a greenfield Payload CMS v3
plugin: hexagonal ports/adapters, strict typesafe, enterprise grade,
where Better Auth (first) and Auth.js/NextAuth integrate as swappable
adapters while users stay first-class Payload documents managed from
the Payload admin. WorkOS and Clerk are deferred post-v1 (SaaS-backed,
not fully validatable locally). Research is done (9-agent workflow,
synthesis `complete:true`); this plan turns decisions D1–D18 plus
payload-onpage precedent into shippable phases.

## Success Criteria

- A site builder installs packages, adds one plugin call, and signs
  in via Better Auth with users/roles/sessions in Payload collections.
- Each provider is an isolated adapter package; core has zero
  framework imports (lint-proven).
- Zero `any` at boundaries; generic-preserving option types;
  canonical `Role` type; `Result`-based errors; Zod boundaries.
- Full e2e: sign-in, callback, webhook sync, logout, admin session
  revoke — green in CI before any release.
- Docs a builder can follow: tour, getting-started, guides, plus
  `llms.txt`/`AGENTS.md` for agent consumers.

## Approach

Clone the proven payload-onpage monorepo shape (core ports,
framework adapters, example app as e2e target, `check` pipeline),
fill it with the auth domain from the synthesis, and ship the two
locally-validatable providers behind `IdentityProviderPort`.
Better Auth first (researched); Auth.js gated on a short research
spike since only Better Auth bodies were inspected. WorkOS and Clerk
stay out of the initial build; the registry reserves their ids.
Re-verify every delegated-research claim against installed `payload`
types and official docs at implementation start; unresolved items
below stay open until then.

## Steps

### Phase 0 — Scaffold and tooling

- Bun monorepo: `packages/{core,plugin,react,next}`,
  `packages/provider-better-auth`, `examples/basic`, `e2e/`.
- TS `strict` + `noUncheckedIndexedAccess` +
  `exactOptionalPropertyTypes` + `verbatimModuleSyntax` + `noUnused*`;
  eslint `no-restricted-imports` boundaries; Prettier; `tsc -b`.
- `check` script: format, lint, typecheck, coverage gates, build,
  size budgets. Changesets, `publint`, `are-the-types-wrong`.
- `examples/basic`: SQLite, self-seeding, reference integration.
- `docs/` skeleton, `AGENTS.md`, `SECURITY.md`, `CONTRIBUTING.md`.

### Phase 1 — Core domain and ports

- `ports.ts`: `UserRepository`, `SessionPort`,
  `IdentityProviderPort` + registry, `CookiePort`, `TransactionPort`,
  `LoggerPort`, `TracerPort`, `ClockPort`, `IdPort`.
- Canonical `Role` + smart constructor; typed slug/field map;
  `Result<T,E>` error taxonomy; Zod boundary schemas; startup
  validation (baseURL/secret, default-role-in-roles).
- Explicit composition-root factories. No DI container.
- Unit tests next to code; public API = explicit `index.ts` lists.

### Phase 2 — Payload plugin (first-class citizenship)

- `definePlugin` shape: copy config, append collections/globals,
  merge hooks, chain `onInit`.
- Users collection extension (identities, roles, sessions views),
  custom `AuthStrategy` delegating to `SessionPort`, unauthenticated-
  by-default endpoints with CSRF guard + `access.ts`, hook appends,
  RSC admin components (`path#Export`).
- Correctness starters: `pagination:false` on logout finds,
  forward+reverse joins, refresh-disabled session reads,
  configurable query depth. Host-owned migrations only.

### Phase 3 — Better Auth + Next.js adapters

- `provider-better-auth`: `betterAuth({ database: payloadAdapter,
plugins })`, session/cookie delegation, no `next/headers` outside
  the Next adapter, no hand-rolled cookies.
- `@scope/next`: route handlers (`/api/auth/[...all]`), proxy/
  middleware, `nextCookies()` (Edge optimistic + Node full
  validation), `<Provider />`, `useNextRefresh`-style renderer.
- `@scope/react`: sign-in buttons, user menu, admin helpers.
- Integration tests on SQLite-in-memory via `handleEndpoints`;
  security tests that fail without each guard.

### Phase 4 — Auth.js spike, then adapter ✅ DONE

- Spike (`spike.test.ts`, 6/6): Credentials is JWT-only and ignores
  the adapter; credentials + `database` strategy is rejected at
  config time (`UnsupportedStrategy`); the jwt callback re-runs
  without `user` on reads (guard claims); the port reads via Auth's
  own session action (`skipCSRFCheck`, no hand JWT decode).
- `packages/provider-authjs` behind `IdentityProviderPort` +
  registry: engine (fail-fasts, `/api/authjs` basePath,
  claims-callback chaining), Payload database adapter (users,
  accounts, sessions, verification tokens, authenticators), scrypt
  credentials service with builder-stamped verification, port with
  chunk-joining session-id extraction, edge-safe `/cookies` subpath.
- Example coexistence: Auth.js mounted alongside Better Auth
  (`lib/authjs.ts`, `/api/authjs/[...authjs]`, builder-owned
  `/api/authjs-signup`, `/sign-in-authjs` page, concatenated
  middleware cookie names). E2E finding: @auth/core's credentials
  callback always 302s (`json=true` is a v4 convention it ignores) —
  the form follows the redirect and reads success/failure from the
  final URL (`?error=…` on reject).
- Validation: 67 provider tests (unit + SQLite adapter lifecycle +
  error mapping), `bun run check` green, 3 Auth.js e2e specs green.
- WorkOS and Clerk: no spike, no adapter in the initial build
  (deferred post-v1; registry ids reserved).

### Phase 5 — E2E, CI, release hygiene ✅ DONE

- Playwright against `examples/basic` + fresh DB: sign-in,
  callback, webhook sync, logout, admin revoke, role-gated access,
  axe on admin UI. Chromium, CI retries, traces on failure.
  ✅ Local e2e green: 10/10 (Better Auth sign-up/in/out + wrong
  password + role gate + users-admin + smoke + 3 Auth.js specs).
  Remaining: axe pass on admin UI, CI retries/traces already
  configured in `playwright.config.ts`.
- CI matrix: SQLite local, `mongodb-memory-server` replset,
  containerized Postgres parity. Coverage gates enforced.
  ✅ `ci.yml` (check + e2e + release-check jobs, trace artifacts).
  ✅ Postgres: `e2e:postgres` + `dev:e2e-pg`, per-run database,
  13/13 in 11 of 13 runs (two `users-admin` admin-list wait failures;
  structural causes ruled out with DB evidence — no seed dupes,
  no pagination, fresh DB per run — leaving transient slowness;
  spec wait split for diagnosis, CI `retries: 2` covers the
  class). No compose file — GH `services:` in CI, `docker run`
  locally.
  ✅ Mongo: `e2e:mongo` via `e2e/run-mongo.mjs` (per-run
  wiredTiger replset, `transactionOptions: false` in the example's
  mongo branch — three Payload instances lock-fight on one node,
  and our adapters never use multi-doc transactions), 13/13 x3.
  ✅ `ci.yml`: `e2e` (sqlite) + `e2e-postgres` (service) +
  `e2e-mongo` (memory replset) + `check` + `release:check`.
  Note: run parity suites separately, not chained — three
  back-to-back suites saturate one box (mongo leg timed out
  in-chain, 13/13 in 17s solo; CI isolates per job).
- Release checklist: changesets, provenance, no debug output,
  no logged credentials (anti-#154). ✅ Wired: `.changeset/`
  config, `release`/`version-packages` scripts, `release.yml`
  (trusted publishing, provenance), `CONTRIBUTING.md` release
  section. `bun run release:check` (`publint` + `attw --profile
esm-only`) green on all 6 packages as a pre-publish gate
  (kept out of `check` for speed; runs in CI).

### Phase 6 — Builder docs ✅ DONE

- ✅ Tour, getting-started (four-edit drop-in: install, engine,
  config, routes+UI), concepts, Better Auth + Auth.js guides,
  compatibility, troubleshooting, upgrading — all in `docs/`.
- ✅ `docs:api` (typedoc, 0 errors), `llms.txt`/`llms-full.txt`
  (generated by `bun run docs:llms`, drift-proof), media from the
  example app (`bun run docs:media`, 5 screenshots in
  `docs/media/`). Every public API has TSDoc (audit clean).
- ✅ Fresh-eyes validation: independent agent audit of every guide
  snippet against source — 7 factual wrongs found and fixed
  (route import depth, BA model/field constraints, error names,
  measured JWT size, dep classification), plus nits.

## Validation Plan

- Phase 0: `bun run check` green on empty packages; example boots
  and seeds (`bun run dev:example`).
- Phase 1: `vitest run --coverage` passes gates; eslint proves
  core imports no framework; type tests prove generics survive.
- Phase 2: integration suite green on SQLite memory;
  `pagination:false`/join/refresh-disabled behaviors covered;
  admin renders users + identities + sessions.
- Phase 3: Better Auth sign-in/callback/logout pass in
  integration; route-handler + middleware tests green.
- Phase 4: Auth.js integration suite green before merge. ✅
  (67 tests + 3 e2e specs green, `check` green.)
- Phase 5: `bun run e2e` green locally and in CI across DBs;
  highest-risk gate — no release without it. ✅ Local: 16/16 on
  sqlite + postgres + mongo; CI runs all three plus check and
  release-check (first CI run happens on first push — no remote
  yet).
- Phase 6: fresh-clone walkthrough of getting-started by a
  second person (or agent) with zero prior context. ✅ Proxy:
  independent agent audit of all guides vs source; all findings
  fixed and re-verified against source. True fresh-clone still
  wants a human on first publish (no remote yet).

## Known issues, resolved post-Phase 6

- ✅ Auth.js factory-provider bypass: the engine now inspects
  factories the way Auth.js normalizes them (called with `{}`),
  so wrapped credentials fail fast; factories that throw on
  inspection surface `InvalidConfigError` at wiring time.
- ✅ Auth.js giant-claim chunks: `chunkSlots` on the engine input
  (default 3) sizes the session-cookie slots; the middleware names
  mirror it. Only tokens past the raised slots need Auth.js's own
  signout action.
- ✅ Better Auth custom fields + plugin models: `customFields` /
  `customModels` engine options generate matching Payload columns
  and extend the adapter allowlist; strict both directions
  (undeclared extras, declared-but-absent names, and undeclared
  plugin models all throw `UnsupportedSchemaError` at startup).
- ✅ Enterprise review hardening (multi-agent review + fixes):
  open-redirect guard (`safeRedirectPath`, both example forms, e2e);
  logout clears with live cookie attributes (`Secure`/`Domain` via
  `sessionCookieClearOptions`, prefix-derived fallback); server
  authorization helpers (`requireSessionUser`/`requireRoles`,
  example admin page enforced on Node, e2e proves the secret never
  ships to denied callers); credentials dummy-hash anti-oracle;
  `baseUrl`-anchored session reads (host fallback dev-only);
  unified error taxonomy (BA `AdapterOperationError` under
  `AuthLinkError`); Auth.js slug validation parity
  (`resolveSlugs`/`assertUniqueSlugs`, custom-model collision
  checks); shared core guards (`isRecord`/`toDate`,
  `runProviderOperation`, `denyAllAccess`). 331 unit + 17×6 e2e
  green (Next + TanStack × SQLite/Postgres/Mongo; see
  PLAN-TANSTACK.md).
  Proven by `custom-schema.test.ts` (additionalFields round-trip +
  organization/member/invitation CRUD on SQLite memory).
- ⏸️ Postgres `users-admin` intermittence (~2/13 runs): structural
  causes ruled out with container evidence; split-wait added for
  diagnosis; CI `retries: 2` covers. Revisit if it ever fails twice
  in a row or appears on sqlite/mongo.
- ⏸️ Next.js `middleware.ts` → `proxy.ts` rename (Next 16
  deprecation warning, log noise only): staying on `middleware.ts`
  deliberately — `proxy.ts` needs Next 16+ and the peer range is
  `>=15`. Revisit when the floor rises.

## Risks / Open Questions

- ~~Only Better Auth integration bodies inspected; Auth.js needs
  its spike (Phase 4).~~ RESOLVED in Phase 4: spike green, adapter
  - port + engine shipped, session-verify sync proven by e2e.
    (No webhooks in either provider path — sync is read-time via the
    port, not webhook-to-users.) WorkOS/Clerk spikes explicitly out
    of scope.
- Access `Where` shape, full hook arg shapes, `templates/plugin`
  3.x source not inspected — verify against installed types in
  Phase 0/2, not from memory.
- No official Payload testing docs (404) and no published
  `@payloadcms/test` — harness follows onpage precedent
  (SQLite memory + `handleEndpoints` + Playwright on example).
- ~~Postgres parity mechanism (compose vs replset vs testcontainers)
  undecided — spike in Phase 5, default to compose.~~ RESOLVED:
  no compose file — GH `services: postgres:16` in CI, `docker run`
  locally, per-run database names; mongo via in-process
  `mongodb-memory-server` replset (wiredTiger, no transactions).
- payload-auth issue bodies beyond titles and audit-rec landing
  status unconfirmed — re-verify anti-patterns against its `main`
  at Phase 1 start so guardrails track reality.

## Sources

- [payload-onpage repo](https://github.com/jellologic/payload-onpage)
- [payload-onpage README](https://raw.githubusercontent.com/jellologic/payload-onpage/main/README.md)
- [payload-onpage root package.json](https://raw.githubusercontent.com/jellologic/payload-onpage/main/package.json)
- [payload-onpage architecture](https://raw.githubusercontent.com/jellologic/payload-onpage/main/docs/concepts/architecture.md)
- [payload-onpage AGENTS.md](https://raw.githubusercontent.com/jellologic/payload-onpage/main/AGENTS.md)
- [onpage core package.json](https://raw.githubusercontent.com/jellologic/payload-onpage/main/packages/core/package.json)
- [onpage plugin package.json](https://raw.githubusercontent.com/jellologic/payload-onpage/main/packages/plugin/package.json)

Payload/Better Auth contract details came from delegated workflow
research (synthesis `complete:true` with gaps listed above); each is
re-verified against installed types and official docs in Phases 0–2
before it becomes load-bearing.
