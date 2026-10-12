# DNA — engineering constitution

How this repo is built. Every decision below traces to the research
synthesis (D1–D18) or to `payload-onpage` precedent. Violating these
rules requires updating this file first.

## 1. Architecture: ports and adapters

- `core` owns the domain and all port interfaces (`core/src/ports.ts`).
  It imports nothing framework-specific — no `payload`, no `next/*`,
  no React, no provider SDK.
- Adapters live at the leaves: one package per surface.
- Wiring happens only at an explicit composition root
  (factory functions like `nextSession()`, `payloadRest()`).
  No DI container (awilix/tsyringe/inversify rejected: magic,
  weak inference, worse tree-shaking).
- Constructor injection everywhere: `RegisterUser(repo, ids, clock)`.
- Public API is the explicit export list in each `index.ts`.
  Exporting something new is a decision, not a side effect.

### Package map (mirrors payload-onpage)

- `@scope/core` — framework-free: ports, domain (roles, session
  types, errors), provider-neutral orchestration. Depends on nothing.
- `@scope/plugin` — Payload server: plugin fn, collections/globals
  extension, AuthStrategy, endpoints, hooks, access, `admin/`.
  Depends on core + payload.
- `@scope/react` — provider-agnostic UI (sign-in buttons, user menu,
  admin helpers). No Next, no Payload imports.
- `@scope/next` — Next.js adapter: route handlers, middleware/proxy,
  cookie/session helpers. Depends on core + react.
- `@scope/provider-<id>` — one package per identity provider.
  Initial build: `better-auth` first, `authjs` after its spike (both shipped, Phase 4).
  `workos` and `clerk` deferred post-v1 (SaaS-backed, not locally
  validatable); the registry reserves their ids.
- `examples/basic` — reference integration and e2e target (SQLite,
  self-seeding, like onpage's `:3100` example).

### v1 ports

- `UserRepository` — users via Payload Local API (never raw DB).
- `SessionPort` — verify/create/revoke sessions; strategies delegate here.
- `IdentityProviderPort` — per-IdP authorize/callback/webhook/profile
  normalize; instances registered in an adapter registry keyed by id.
- `CookiePort` — read/write/clear; implemented by the framework adapter.
- `TransactionPort`, `LoggerPort`, `TracerPort` — storage transactions,
  structured logs, spans. `ClockPort` + `IdPort` for determinism.

### Dependency rules (lint-enforced via `no-restricted-imports`)

- core imports no framework. react imports no Next/Payload.
  plugin imports no React outside `admin/`.
- Sources import siblings with `.ts`/`.tsx` extensions.
- Cross-package imports use workspace package names, never deep paths
  outside declared subpath exports.

## 2. Payload contract

- Plugin shape: `definePlugin<TOptions>({ slug, order, plugin })`;
  `(options) => (incomingConfig) => Config`. Copy config, spread-append
  collections/globals, merge hook objects (never overwrite), chain
  `onInit`, return config. Lower `order` first; cross-plugin via `plugins` map.
- Auth strategy: `{ name, authenticate({ headers, payload, req, ... }) }`
  returning `{ user: { ...doc, collection } } | null`. Read-only session
  checks use refresh-disabled reads (no login loops).
- `auth.strategies[]` plus explicit cookies/token/api-key options.
- Custom `endpoints[]` are unauthenticated by default: check `req.user`,
  method lowercase, `handler(req: PayloadRequest) => Response`.
  Every state-changing endpoint gets a CSRF guard + access check —
  authorization goes through one `access.ts` using Payload's access ops.
- Preserve existing hooks when extending (append, don't replace);
  inject admin/meta fields as a group. Root/collection/global/field
  hooks are awaited in series; `afterError` may transform.
- Admin UI is React Server Components by default; `'use client'` only
  where needed, registered as `{ path#Export, clientProps/serverProps }`.
- Migrations are host-owned (`up`/`down`, `migrate:create/status/down`).
  The plugin ships no migration mechanism.

## 3. Coupling guardrails (the payload-auth anti-patterns, banned)

- No double-pass init: resolve schemas once, before hooks/endpoints/
  `useAsTitle` attach — never build-collections → sync → rebuild.
- No monkey-patch contract: no `Object.defineProperty(payload, …)`,
  no string flags on `config.custom`, no per-invocation client
  re-entry from strategies/hooks/endpoints. Typed injected client
  from the composition root instead.
- No framework leak: no `next/headers` (or any framework import)
  inside Payload hooks or core. Cookie/transport work lives in the
  framework adapter (`toNextJsHandler`, `nextCookies()`).
- No stringly schema map: typed slug/field maps with explicit errors.
  No silent fallbacks, no "warns but uses wrong slug", no runtime
  patching of provider internals.
- No hand-rolled sessions: no admin-session hacks, manual `Set-Cookie`
  concat, or fabricated endpoint contexts. Sessions go through
  `SessionPort` + `CookiePort`.

## 4. Type safety

- `strict` plus `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `noUnused*`.
  Guard indexes; never assert (`!`). Options filled from other
  optionals are typed `?: T | undefined`.
- Zero-`any` boundary: no `: any`, no `as` casts at module edges,
  no whole-instance erasure (`as unknown as …`). Sanitize by deep-copy,
  never shallow-spread-then-deep-write the caller's options.
- Generics survive: provider/plugin options preserve their type
  parameters end to end (no hardcoded generated-types artifact that
  silently drops endpoints when plugins change).
- One canonical `Role` type with a smart constructor at the boundary.
  No `array | string | comma-string` branching at every call site;
  normalize once, use everywhere.
- Make the compiler check it: discriminated unions + `assertNever`,
  branded keys for document refs, readiness guards before reading
  loaded state, typed message catalogs for UI strings.

## 5. Errors and validation

- Expected failures return `neverthrow` `Result<T, E>` /
  `ResultAsync` (`ok`/`err`, `fromThrowable`, `combine`,
  `fromPromise`/`fromSafePromise`). Throw only for the truly unexpected.
- Domain errors vs application errors stay distinct
  (`InvalidEmailError` vs `UserExistsError`); the web adapter maps
  them to status codes. Never swallow (`null`/`[]`/`0` on failure),
  never drop nulls, never leave endpoints unauthenticated by accident.
- Validate at every untyped boundary with Zod
  (`safeParse`/`safeParseAsync`, `z.infer`, `.strict()`).
  Zod over TypeBox: distinct `z.input`/`z.output` and superior error
  reporting matter more here than schema-reuse speed, and validation
  sits off the session hot path.
- Startup validation fails fast: baseURL/secret present, default role
  inside roles, adapter-boundary schemas valid.

## 6. Observability

- Domain depends on `LoggerPort` + `TracerPort` only. Adapters use
  pino (child loggers per module, `serializers.err`, never untrusted
  keys) and OpenTelemetry spans, injected — never imported.
- No `console.*` anywhere. Forward into Payload's pino instance and
  the provider logger where supported.
- No hardcoded query depth: depth is configurable per call site.
- Transactions go through `TransactionPort` — no no-op stubs.

## 7. Testing constitution (e2e is mandatory)

- Unit tests live next to code in `src/__tests__/`.
- Integration tests run real Payload on in-memory SQLite through
  `handleEndpoints` (onpage precedent), or the Local API over a
  memory DB with fixtures (`config`, `resetBetweenTests`).
- Behavior change → test. Security change → an integration test
  that fails without the fix.
- Playwright e2e runs against `examples/basic` with a fresh DB:
  sign-in, OAuth callback, webhook user-sync, logout, session
  revoke from the admin, role-gated access. Chromium, retries on CI,
  traces retained on failure, axe for admin UI regressions.
- DB strategy: SQLite in-memory for local/unit, `mongodb-memory-server`
  replica set for integration default, containerized Postgres for
  parity in CI.
- `bun run check` gates everything: format, lint, typecheck,
  coverage thresholds, build, size budgets. No merge on red.

## 8. Repo conventions

- Bun monorepo: `packages/*` + `examples/*` workspaces, `tsc -b` build,
  `publint` + `are-the-types-wrong` on publishable packages.
- Prettier: single quotes, no semicolons, width 100.
  typescript-eslint type-checked, react-hooks, jsx-a11y.
- Changesets required for user-facing changes; provenance-enabled
  publishes; `SECURITY.md` for private reports.
- Public API → TSDoc plus `docs/` guides. Docs follow the onpage
  system as they grow: tour, getting-started, concepts, guides,
  compatibility, troubleshooting, upgrading — plus `llms.txt` and
  `AGENTS.md` for agent consumers.
- Never commit secrets, never log credentials, never ship a release
  with debug output (release hygiene is a checklist item, not a hope).

## 9. Security invariants

- Never link a provider identity to an existing user, or reuse an
  existing email for a provider login, unless the provider verified the
  email (`emailVerified`). Unverified profiles must not take over
  existing accounts; creation of a standalone user is the provider's
  verification lifecycle to complete.
- State-changing endpoints require CSRF proof: matching `Origin` or a
  custom header a cross-site page cannot set. Redirect targets are
  validated same-origin against `baseUrl` — never an open redirect.
