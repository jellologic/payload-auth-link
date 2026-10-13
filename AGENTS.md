# AGENTS.md

Guidance for coding agents working **on this repository**. Start with
[docs/MISSION.md](docs/MISSION.md), [docs/DNA.md](docs/DNA.md),
[docs/PLAN.md](docs/PLAN.md), [docs/PLAN-TANSTACK.md](docs/PLAN-TANSTACK.md), and
[docs/PLAN-CAPABILITIES.md](docs/PLAN-CAPABILITIES.md)
— they are the authority this file summarizes.

## Commands (repo root, Bun)

| Command                             | Does                                                         |
| ----------------------------------- | ------------------------------------------------------------ |
| `bun install`                       | Install (workspaces: `packages/*`, `examples/*`)             |
| `bun run check`                     | Format, lint, typecheck, coverage, build, size budgets       |
| `bun run test` / `bun run coverage` | Vitest (unit, component, Payload integration), on source     |
| `bun run e2e`                       | Build, then Playwright on `examples/basic` (:3101, fresh DB) |
| `bun run e2e:tanstack`              | Same suite on `examples/tanstack-start` (:3201, fresh DB)    |
| `bun run build`                     | `tsc -b` → `packages/*/dist`                                 |
| `bun run dev:example`               | Example site on :3100                                        |
| `bunx changeset`                    | Describe a user-facing change (required for releases)        |

## Layout

- `packages/core`: framework-free. Ports (`ports.ts`), domain (roles,
  errors, session types), Zod boundary schemas. No framework imports.
- `packages/plugin`: Payload plugin. Plugin fn, collections, strategy,
  `endpoints.ts`, `access.ts`, `hooks.ts`, `admin/`.
- `packages/react`: provider-agnostic UI (sign-in, user menu). No Next,
  no Payload imports.
- `packages/web`: framework-free web (handlers, verifier, authz,
  redirect). No framework imports.
- `packages/next`: Next adapter. Edge middleware, client refresh,
  server provider. Re-exports `web`.
- `packages/tanstack-start`: Start adapter (Payload v4). Route
  handlers, request middleware, loaders, refresh. Re-exports `web`.
- `packages/provider-*`: one identity-provider adapter each
  (`better-auth`, then `authjs`; `workos`/`clerk` ids reserved).
- `examples/basic`: Next reference integration and e2e target.
- `examples/tanstack-start`: Start reference integration and e2e target.

## Invariants (don't break these)

1. **Payload owns the users.** No second user store, shadow session
   table, or out-of-band auth cookie. Storage goes through the Payload
   Local API via `UserRepository`.
2. **Core is framework-free.** No `payload`, `next/*`, React, or
   provider-SDK imports in `packages/core` (lint-enforced).
3. **No monkey-patches.** No `Object.defineProperty(payload, …)`, no
   string flags on `config.custom`, no per-invocation client re-entry.
   Typed injected clients from the composition root only.
4. **No framework leaks.** No `next/headers` (or any framework import)
   in Payload hooks or core. Transport lives in framework adapters.
5. **Authorization goes through `plugin/src/access.ts`** (Payload's
   access ops). Never add a state-changing endpoint without a CSRF
   guard + an access check.
6. **Package boundaries** (lint-enforced): core imports no framework;
   react imports no Next/Payload; plugin imports no React outside
   `admin/`; adapters sit beside the plugin, never above it.
7. **Sources import siblings with `.ts`/`.tsx` extensions**
   (rewritten to `.js`). Import Next modules as `next/headers.js`
   etc. so `dist` runs under plain Node.
8. **No `any` at boundaries, no silent fallbacks, no `console.*`.**
   Expected failures are `Result<T, E>`; logs go through `LoggerPort`.

## Conventions

- Prettier (single quotes, no semicolons, width 100).
  typescript-eslint type-checked, react-hooks, jsx-a11y.
- TypeScript: `strict` plus `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `noUnused*`.
  Guard indexes instead of asserting (`!`).
- Make the compiler check it: discriminated unions + `assertNever`,
  branded keys, one canonical `Role` with a smart constructor.
- Reuse before writing: Payload (`payload`, `payload/shared`),
  core ports, neverthrow, Zod at untyped boundaries.
- Core's public API is the explicit list in `core/src/index.ts`.
- Tests: next to the code in `src/__tests__/`. Integration tests use
  real Payload on SQLite in memory via `handleEndpoints`. Component
  tests use Testing Library + happy-dom
  (`// @vitest-environment happy-dom`).
- Behavior change → test. Security change → an integration test that
  would fail without it.
- Public API → TSDoc, plus docs in `docs/`.

## Schema changes (upgrade safety)

Shipped collection shapes — the provider `ba-*`/`aj-*` collections
and the plugin-injected users fields — are what a Payload push or
migration acts on; a careless change there has historically left
user databases unbootable. Therefore:

- **Additive-only by default.** No new `required` (NOT NULL) column
  without a DB default or a backfill plan; adapter-side validation
  instead of DB-level `required` when the column must tolerate
  pre-existing rows.
- **No nullability/type/unique change or rename** on an existing
  column without a two-release expand → backfill → contract
  sequence. The previous minor must keep reading AND writing the
  new schema (N/N−1 is tested by the golden-DB suite).
- Every shape change ships: a regenerated `snapshots/schema/`
  (`bun run schema:snapshot`), a changeset with an `Upgrade impact:`
  section (per-adapter push/migrations behavior + operator steps),
  an `upgrading.md` entry, and a golden-DB upgrade test. `bun run
schema:check` enforces the first three in CI.
- Upstream version bands move only with compat-matrix evidence
  (`.github/workflows/compat.yml`); the runtime
  `supported*Band` constants and the manifest ranges change
  together, never one without the other.
