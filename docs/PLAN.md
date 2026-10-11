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

### Phase 4 — Auth.js spike, then adapter

- One spike: Auth.js/NextAuth (session verify, webhooks → users
  sync, token handling, Payload mapping), run fully locally.
- A passing spike becomes `packages/provider-authjs` behind the
  same port + registry, with integration tests. No spike, no adapter.
- WorkOS and Clerk: no spike, no adapter in the initial build
  (deferred post-v1; registry ids reserved).

### Phase 5 — E2E, CI, release hygiene

- Playwright against `examples/basic` + fresh DB: sign-in,
  callback, webhook sync, logout, admin revoke, role-gated access,
  axe on admin UI. Chromium, CI retries, traces on failure.
- CI matrix: SQLite local, `mongodb-memory-server` replset,
  containerized Postgres parity. Coverage gates enforced.
- Release checklist: changesets, provenance, no debug output,
  no logged credentials (anti-#154).

### Phase 6 — Builder docs

- Tour, getting-started (four-edit drop-in target), concepts,
  Better Auth + Auth.js guides, compatibility, troubleshooting,
  upgrading.
- `docs:api` (typedoc), `llms.txt`/`llms-full.txt`, media from
  the example app. Every public API has TSDoc + a guide.

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
- Phase 4: Auth.js integration suite green before merge.
- Phase 5: `bun run e2e` green locally and in CI across DBs;
  highest-risk gate — no release without it.
- Phase 6: fresh-clone walkthrough of getting-started by a
  second person (or agent) with zero prior context.

## Risks / Open Questions

- Only Better Auth integration bodies inspected; Auth.js needs its
  spike (Phase 4). No authoritative Payload-specific IdP page
  found; webhook-to-users + JWT/session-verify sync unconfirmed
  until the spike. WorkOS/Clerk spikes explicitly out of scope.
- Access `Where` shape, full hook arg shapes, `templates/plugin`
  3.x source not inspected — verify against installed types in
  Phase 0/2, not from memory.
- No official Payload testing docs (404) and no published
  `@payloadcms/test` — harness follows onpage precedent
  (SQLite memory + `handleEndpoints` + Playwright on example).
- Postgres parity mechanism (compose vs replset vs testcontainers)
  undecided — spike in Phase 5, default to compose.
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
