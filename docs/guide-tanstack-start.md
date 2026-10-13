# TanStack Start guide

`@payload-auth-link/tanstack-start`: the same auth behavior as
`@payload-auth-link/next`, on TanStack Start. The framework-free
pieces (`createSessionVerifier`, `requireRoles`,
`safeRedirectPath`, `createRouteHandlers`) live in
`@payload-auth-link/web` and are shared verbatim — the Start
package holds only Start imports, and re-exports the shared API so
one import covers both. Day-one target is **Payload v4**
(`@payloadcms/tanstack-start` exists only on the v4 line, beta).

Every snippet below is copied from `examples/tanstack-start`,
which the shared e2e suite exercises on SQLite, Postgres, and
Mongo — if a snippet and the example disagree, the example wins
(and please file an issue).

Prerequisites: Bun 1.4+, a Payload 4 + Start 1 app, React 19.
All packages are ESM-only.

## Install

```bash
bun add @payload-auth-link/core @payload-auth-link/plugin \
  @payload-auth-link/react @payload-auth-link/tanstack-start \
  @payload-auth-link/provider-better-auth
```

(`@payload-auth-link/web` arrives as a dependency — install it
directly only to import the shared API without a framework
adapter.)

## Engine: declare `tanstackStartCookies()`, not `nextCookies()`

```ts
import { tanstackStartCookies } from 'better-auth/tanstack-start'

export const engine = createBetterAuthEngine({
  getPayload: loadPayload,
  options: {
    baseURL: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200',
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Start owns cookie I/O here (not Next.js): declare Better Auth's
    // Start cookie plugin in your own plugins list. The engine passes
    // it through verbatim and never appends framework plugins itself.
    plugins: [tanstackStartCookies()],
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})
```

Pick the framework you mount on — each cookie plugin reads its own
framework's cookie store. Auth.js needs nothing
(`handleRequest` is already Request/Response). The plugin call in
`payload.config.ts` is identical to Next (framework-free).

## Mount provider routes (`server.handlers`)

```ts
// src/app/api.auth.$.ts
import { createServerRouteHandlers } from '@payload-auth-link/tanstack-start'

export const Route = createFileRoute('/api/auth/$')({
  server: {
    handlers: createServerRouteHandlers((request) => auth.handler(request)),
  },
})
```

Same envelope as Next's `createRouteHandlers`. Handlers receive
`{ request }` context — `createServerRouteHandlers` adapts that to
the shared implementation. Mount Auth.js the same way at
`/api/authjs/$`.

## Request middleware (`src/start.ts`)

```ts
import { createAuthRequestMiddleware } from '@payload-auth-link/tanstack-start'

const authRequestMiddleware = createAuthRequestMiddleware({
  sessionCookieNames, // from the /cookies subpaths, as on Next
  publicPaths: [
    '/',
    '/sign-in',
    '/sign-in-authjs',
    '/favicon.ico',
    /^\/api(\/|$)/,
    /^\/admin(\/|$)/,
    // …client asset prefixes (`/@`, `/_build`, `/src/`, …)
    // (`/_serverFn/` needs no entry: the middleware exempts Start
    // RPC by default — a redirect there corrupts the
    // server-function protocol — and server functions authenticate
    // themselves via the shared verifier. Set
    // `bounceServerFunctions: true` to opt out.)
  ],
})

// Defining start.ts disables Start's automatic CSRF middleware —
// reinstall it explicitly for server functions.
const csrfMiddleware = createCsrfMiddleware({
  filter: (ctx) => ctx.handlerType === 'serverFn',
})

export const startInstance = createStart(() => ({
  requestMiddleware: [csrfMiddleware, authRequestMiddleware],
}))
```

Optimistic parity with Next: cookie _presence_ bounces obvious
anonymous traffic early; real validation is always the verifier.
Both middlewares share one framework-free bounce decision,
`decideAuthRedirect` from `@payload-auth-link/web` (bounce matrix
unit-tested there); the adapters only map its verdict onto their
response types.

## Session reads: server functions + shared verifier

```ts
// src/lib/session.ts
import {
  createSessionVerifier,
  getSessionUserFromRequest,
  requireRoles,
} from '@payload-auth-link/tanstack-start'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { exampleBaseURL } from './auth-base-url'

export const verifySession = createSessionVerifier({ baseUrl: exampleBaseURL })

export const getSessionUser = createServerFn({ method: 'GET' }).handler(() =>
  getSessionUserFromRequest(getRequest(), verifySession)
)
```

Anchor to the configured origin (`EXAMPLE_BASE_URL` matches the
running port in every mode) — host headers are client-spoofable
and the session cookie is forwarded to that origin. Export a
helper, not a prebuilt server function, so bundler transforms
never go stale.

## Hydration: root loader + `initialUser`

```tsx
// src/app/_frontend.tsx
// AuthLinkProvider is provider-agnostic UI: it comes from react, not
// from the Start adapter (which re-exports web, not react).
import { AuthLinkProvider } from '@payload-auth-link/react'
import { createSessionLoader } from '@payload-auth-link/tanstack-start'
import { createFileRoute, Outlet } from '@tanstack/react-router'
import { getSessionUser } from '../lib/session.js'

export const Route = createFileRoute('/_frontend')({
  loader: createSessionLoader(() => getSessionUser()),
  component: FrontendLayout,
})

function FrontendLayout() {
  const { initialUser } = Route.useLoaderData()
  return (
    <AuthLinkProvider initialUser={initialUser}>
      <main>
        <Outlet />
      </main>
    </AuthLinkProvider>
  )
}
```

First paint already knows the user — no loading flash, no client
fetch waterfall. After auth changes, `useAuthLinkRefreshStart()`
re-reads the session endpoint and calls `router.invalidate()`.

## Role enforcement: `beforeLoad` + a server-function gate

`beforeLoad` runs client-side on navigation too, where
`getRequest()` is out of scope — so the check lives in a server
function (SSR and RPC alike), and `beforeLoad` just awaits it:

```ts
export const requireAdminUser = createServerFn({ method: 'GET' }).handler(() =>
  requireRoles(getRequest().headers, verifySession, {
    roles: ['admin'],
    onAnonymous: () => {
      throw redirect({ to: '/sign-in', search: { redirect: '/admin-only' } })
    },
    onDenied: () => {
      throw notFound()
    },
  })
)
```

`redirect()` / `notFound()` produce the router's control-flow
signal — they must be **thrown**, not merely returned, or
execution falls through to `requireRoles`' default errors. Denied
callers never receive the content (e2e asserts the secret is
absent from denied responses, and both examples render the same
`admin-denied` marker so one suite covers both frameworks).

## Payload v4 notes (all hit building the example)

- `withPayload` callers must apply `rsc(pluginOptions.rsc)`, with
  `@vitejs/plugin-rsc` + `react-server-dom-webpack` installed —
  else SSR 500s.
- `devServerExternalPackages: ['ajv']` — ajv's CJS breaks under
  the RSC rewrite.
- v4 flips the Local API access default: builder code (seeds,
  scripts) must pass `overrideAccess: true`. Every shipped
  plugin/provider call already does.
- Run the real `payload generate:importmap` for admin components
  (the example commits the generated map).
- The v4 admin list renders as `grid`/`gridcell` (not
  `table`/`cell`); the v4 login adds a show-password toggle. The
  shared e2e suite locates both.

## Run and verify

```bash
cd examples/tanstack-start && bun run dev        # :3200
bun run e2e:tanstack                             # SQLite, 33 specs × 3 engines
bun run e2e:tanstack-postgres                    # per-run database
bun run e2e:tanstack-mongo                       # memory replset
```

## Next steps

- [Getting started](getting-started.md): the Next path — same
  calls, same behavior.
- [Concepts](concepts.md): ports, JIT linking, verification
  gating, two-layer validation on both frameworks.
- [Troubleshooting](troubleshooting.md): failure modes and fixes.
