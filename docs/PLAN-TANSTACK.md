# TanStack Start support plan

## Goal

Make TanStack Start a first-class citizen alongside Next.js: a sibling
framework adapter (`@payload-auth-link/tanstack-start`) built on the
same hexagonal ports, so site builders get identical auth behavior on
either framework with zero provider changes. Day-one target is
Payload v4 (TanStack support ships in `v4.0.0-beta.0`, not v3).

## Success Criteria

- A builder wires Better Auth or Auth.js into a TanStack Start app
  with the same calls as Next: engine, collections, provider
  registration, route mounting, session verification, role
  enforcement.
- The Next and TanStack adapters share one implementation of every
  framework-free behavior (no forked copies).
- A TanStack example app runs both providers with 16/16 e2e green,
  in CI, on SQLite at minimum.
- `bun run check` and `bun run release:check` cover the new
  package; guides document the Start path.

## Approach

Mirror Payload's own adapter pattern: thin framework package over
shared UI. Payload renders one `@payloadcms/ui` behind
`@payloadcms/next` and `@payloadcms/tanstack-start`; we render one
`@payload-auth-link/react` behind `@payload-auth-link/next` and the
new `@payload-auth-link/tanstack-start`.

Four of the seven Next modules are already framework-free
(`handlers`, `verify`, `authz`, `redirect` — pure
Request/Response/Headers/fetch). They move to a new shared
`@payload-auth-link/web` package; `next` re-exports them so existing
imports keep working. Only `middleware`, `client`, and
`server-provider` stay Next-only (`next/server`, `next/navigation`,
`next/headers`). The Start package then holds only Start imports,
per DNA §3 (no framework leak outside the adapter).

Payload constraint: `@payloadcms/tanstack-start` exists only on the
v4 line (beta, no stable). Our plugin peers `payload ^3.0.0` and the
Next example runs 3.90.2, so Phase 0 is a go/no-go compat spike
before any adapter code.

## Capability mapping

| Capability            | Next today                       | Start target                       |
| --------------------- | -------------------------------- | ---------------------------------- |
| Mount provider routes | `createRouteHandlers` → GET/POST | Same handlers in `server.handlers` |
| Catch-all API shape   | `[...all]/route.ts`              | `api/auth/$.ts` splat route        |
| Optimistic bounce     | `createAuthMiddleware`           | `createMiddleware().server()`      |
| Server session read   | `createSessionVerifier`          | Shared; headers via `getRequest()` |
| Role enforcement      | `requireRoles`                   | Shared; called from `beforeLoad`   |
| Hydration             | `AuthLinkServerProvider`         | Root `loader` + `initialUser`      |
| Post-auth refresh     | `router.refresh()`               | `router.invalidate()`              |
| Redirect safety       | `safeRedirectPath`               | Shared unchanged                   |
| BA framework plugin   | `nextCookies()`                  | `tanstackStartCookies()`           |

## Steps

### Phase 0 — v4-compat spike ✅ DONE — GO

- Scaffolded `examples/tanstack-start` on `payload@4.0.0-beta.0` +
  `@payloadcms/tanstack-start@4.0.0-beta.0` (file routes per PR
  #16139: `__root.tsx` shell, `_payload` layout, `api.$.ts`).
- Plugin loads under v4 beta with **zero changes**: collections
  register, strategy + endpoints serve, onInit seeds.
- Better Auth signup → session read (JIT user, `roles: [user]`) →
  logout (both providers' cookies expired) verified over HTTP;
  Auth.js mount verified (`/api/authjs/csrf` 200); admin renders.

Findings (all recorded from the spike session):

- **GO.** No plugin rewrite needed; both engines round-trip.
- v4 flips the Local API access default: builder code (seeds,
  scripts) must pass `overrideAccess: true`. Every shipped
  plugin/provider Local API call already does (audited).
- `withPayload` requires the caller to apply `rsc(pluginOptions.rsc)`
  (else SSR 500s); `@vitejs/plugin-rsc` +
  `react-server-dom-webpack` are required dev deps.
- `devServerExternalPackages: ['ajv']` required — ajv's CJS breaks
  under the RSC rewrite (frozen namespace hits `uri.code = ...`).
- Server route handlers receive `{ request }` context, not a bare
  `Request` — shapes the Phase 2 `createServerRouteHandlers` API.
- Spike ran under node; `bun run dev` for this example is untested
  (verify in Phase 3, fall back to node for the e2e webServer).
- `importMap.js` stub suffices for page load; run the real
  `payload generate:importmap` in Phase 3 for admin components.
- Pinned: payload 4.0.0-beta.0, Start 1.168.61, Router 1.170.41,
  vite 8.3.4, react 19.2.6.

### Phase 1 — Extract `@payload-auth-link/web` ✅ DONE

- Moved `handlers`, `verify`, `authz`, `redirect` + tests verbatim
  to the new package; no behavior change.
- `next` re-exports the moved API (back-compat); `next` depends on
  `web`; build refs, typedoc extended (vitest + release-check
  auto-discover).
- Validation: `bun run check` green, 315 unit green,
  `release:check` passes for all 7 packages, Next e2e 16/16 —
  zero regression proven.

### Phase 2 — `@payload-auth-link/tanstack-start` ✅ DONE

- `createServerRouteHandlers(handle)` → `{ GET, POST }` for
  `server.handlers` (uniform error envelope, same as Next).
- `createAuthRequestMiddleware()` — optimistic cookie-presence
  bounce to sign-in via `createMiddleware().server()` (parity
  default; document live-verify as optional hardening).
- Session server functions: `getSessionUser()` via `createServerFn`
  - `getRequest()` headers into the shared verifier
    (`baseUrl`-anchored, CSRF middleware per Start docs).
- `createSessionLoader()` for root-route hydration into
  `AuthLinkProvider initialUser`; `useAuthLinkRefreshStart()`
  (refresh + `router.invalidate()`).
- `beforeLoad` guard recipe using shared `requireRoles` (no new
  authz code).
- Better Auth engine gains a `tanstackStartCookies` plugin option
  mirroring `nextCookies` (verified exported by the installed
  better-auth 1.7.7 `better-auth/tanstack-start` subpath; Auth.js
  needs nothing — `handleRequest` is already Request/Response).
- Unit tests mirror the Next suite (middleware bounce matrix,
  handler envelope, loader hydration, refresh).
- Package re-exports the shared `web` API (same one-import DX as
  `next`).
- Validation: `bun run check` green, 331 unit green (16 new
  - BA engine), `release:check` passes all 8 packages.

### Phase 3 — `examples/tanstack-start` + e2e ✅ DONE

- Example on Payload v4 beta: both providers, sign-in forms,
  account page, server-guarded admin page, Payload admin.
- The 16-spec e2e suite runs unchanged against it (one suite, two
  frameworks — shared `admin-denied` marker, hydration-tolerant
  `gotoOwn`/`toggleToSignUp`, v3/v4 `listTable`/`listCell`
  locators); CI jobs `e2e-tanstack`, `e2e-tanstack-postgres`,
  `e2e-tanstack-mongo`.
- Postgres/Mongo matrix extension done in-phase: 16/16 on all six
  suites (Next + Start × SQLite/Postgres/Mongo).

Findings (all recorded from the Phase 3 session):

- SSR streams before hydration: suite clicks that land in the
  window are silently lost. Both examples render a
  `HydratedMarker` (`html[data-hydrated]`) and the suite waits
  for it (`gotoOwn`).
- `/_serverFn/` must stay public in Start request middleware —
  bouncing RPC corrupts the server-function protocol (redirect
  followed with a JSON Accept → Start 406 → admin detail crash
  on SPA navigation).
- TanStack `redirect()` / `notFound()` must be **thrown** in
  `requireRoles` handlers, not returned.
- v4 admin list renders `grid`/`gridcell` (same `<table>` markup,
  so tbody a11y scoping holds); v4 login adds a show-password
  toggle; v4 ID cells carry an upstream `.id-label` contrast
  failure (triaged exclusion, no-op on v3).
- `bun run dev` verified for the example; no node fallback needed.
- ⏸️ One transient (1/6 runs): post-login SSR to
  `/admin/collections/users` 307-bounced with a valid
  `payload-token` while a later `/me` succeeded — same class as
  the known parallel-worker admin intermittence; CI `retries: 2`
  covers. Revisit if it ever fails twice in a row.

### Phase 4 — Docs + release ✅ DONE

- `docs/guide-tanstack-start.md`, concepts/tour/compatibility
  updates, getting-started + guide-better-auth pointers, PLAN
  counts, llms regen, changesets (minor).
- `release:check` green for all 8 packages; publish together.

## Validation Plan

- Phase 0: scratch app boots, plugin loads, one provider
  round-trip each (manual + recorded findings doc).
- Phase 1: `bun run check`, `bunx vitest run` (315 green),
  `bun run e2e` (16/16, proves zero Next regression).
- Phase 2: new package unit suite green; `bun run release:check`
  covers it.
- Phase 3: TanStack e2e 16/16 on SQLite locally + CI job green
  (plus Postgres/Mongo matrix, done in-phase).
- Highest-risk gate: Phase 0 v4-compat outcome — everything downstream
  depends on the plugin loading under the v4 beta.

## Risks / Open Questions

- **v4 beta churn.** The adapter pins `4.0.0-beta.x`; beta API drift
  may force re-spikes. Mitigation: narrow peer range, Phase 0 records
  exact versions, CI pins lockfile.
- **Should the Next example migrate to v4?** No — stays on v3 until
  v4 stable. Separate work, tracked as a non-goal here.
- **Start middleware runs server-side** (unlike Edge), so full live
  verification is possible there; v1 ships optimistic parity and
  documents the upgrade.
- No Solid/Vue Start flavors in scope.

## Non-goals

- Payload v4 migration of the Next example or existing packages
  beyond what Phase 0 requires.
- TanStack Solid / Vue variants.
- Depending on a future payloadcms.com beta TanStack wiring doc —
  none was found; the PR and demo repo are the wiring reference.

## Sources

- https://github.com/payloadcms/payload/pull/16139
- https://raw.githubusercontent.com/payloadcms/payload-tanstack-demo/HEAD/README.md
- https://registry.npmjs.org/@payloadcms/tanstack-start
- https://registry.npmjs.org/@payloadcms/next/latest
- https://api.github.com/repos/payloadcms/payload/releases?per_page=5
- https://tanstack.com/start/latest/docs/framework/react/guide/server-functions
- https://tanstack.com/start/latest/docs/framework/react/guide/server-routes
- https://tanstack.com/start/latest/docs/framework/react/guide/middleware
- https://tanstack.com/router/latest/docs/framework/react/guide/data-loading
