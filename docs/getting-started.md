# Getting started

Four edits take a Payload CMS v3 + Next.js site from zero to signed-in
users with Better Auth: install, engine, config, routes + UI. Every
snippet below is copied from `examples/basic`, which the e2e suite
exercises on SQLite, Postgres, and Mongo — if a snippet and the example
disagree, the example wins (and please file an issue).

Prerequisites: Bun 1.4+, a Payload 3 + Next.js 15+ app, React 19.
All packages are ESM-only (`type: module`, `engines: node >= 20.9`).

## Edit 1 — Install

```bash
bun add @payload-auth-link/core @payload-auth-link/plugin \
  @payload-auth-link/react @payload-auth-link/next \
  @payload-auth-link/provider-better-auth better-auth
```

(`better-auth` ships as a dependency of the provider, but you import
it yourself for the `nextCookies()` framework plugin in Edit 2, so it
is a direct dependency too.)

## Edit 2 — The engine (`lib/auth.ts`)

The engine composes Better Auth on Payload storage. `getPayload` is a
thunk (cached here) so the engine never imports your Payload config
statically — no import cycle.

```ts
import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { nextCookies } from 'better-auth/next-js'
import { getPayload, type Payload } from 'payload'

let cachedPayload: Promise<Payload> | undefined

function loadPayload(): Promise<Payload> {
  cachedPayload ??= import('../payload.config').then((mod) => getPayload({ config: mod.default }))
  return cachedPayload
}

export const engine = createBetterAuthEngine({
  getPayload: loadPayload,
  options: {
    baseURL: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100',
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Framework cookie plugin, declared by you exactly as Better Auth
    // documents: required for cookie handling in Next.js server
    // actions. The engine never touches this list.
    plugins: [nextCookies()],
    emailAndPassword: {
      enabled: true,
      // Local example only: no email delivery here, so verification is
      // off. The engine requires verification by default — production
      // builders keep the default and configure an email sender.
      requireEmailVerification: false,
    },
  },
})

export const { auth, provider: betterAuthProvider, collections: betterAuthCollections } = engine
```

Notes:

- `options` is Better Auth's own options object, passed through
  verbatim except `database` (wired to Payload here). Your plugins,
  rate limits, and session settings keep working — and keep their
  types, since the engine's return type is inferred.
- With `emailAndPassword` present, the engine **requires email
  verification by default**. The snippet above opts out only because
  the example has no email delivery; production sites keep the
  default and configure a sender. Unverified users can hold provider
  sessions but the plugin refuses to link them to Payload users
  (see [Concepts](concepts.md)).
- Casing callout: the engine takes Better Auth's `baseURL` (capital
  URL) while the plugin takes Payload-style `baseUrl` (Edit 3).
  Each spelling belongs to its owner — do not "fix" either one.

## Edit 3 — The plugin (`payload.config.ts`)

```ts
import { authLink } from '@payload-auth-link/plugin'
import { betterAuthCollections, betterAuthProvider } from './lib/auth'

export default buildConfig({
  // …your db, secret, serverURL…
  collections: [
    { slug: 'users', auth: true, fields: [] },
    // …your collections…
    ...betterAuthCollections,
  ],
  plugins: [
    authLink({
      baseUrl: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [betterAuthProvider],
    }),
  ],
})
```

What this does:

- Appends the Better Auth system collections (`ba-users`,
  `ba-sessions`, `ba-accounts`, `ba-verifications`, `ba-rate-limits`,
  deny-all access, hidden from the admin nav).
- Extends your `users` collection with `roles` and `identities`
  fields (customize via `usersCollection` / `emailField` /
  `rolesField` / `identitiesField`), registers the `auth-link`
  strategy, and mounts `GET` + `DELETE /api/auth-link/session`.
- Validates everything fail-fast: bad secrets, unknown roles, or
  zero providers throw at config time, not on first login.

Users stay first-class Payload documents: the admin users list shows
roles and linked identities, and opening a row shows each identity
(`better-auth · user@example.com`).

## Edit 4 — Routes, middleware, UI

**Auth routes** (`app/api/auth/[...all]/route.ts`):

```ts
import { createRouteHandlers } from '@payload-auth-link/next'
import { auth } from '../../../../lib/auth'

export const { GET, POST } = createRouteHandlers((request) => auth.handler(request))
```

**Edge middleware** (`middleware.ts` + `lib/auth-cookie-names.ts`).
The middleware only checks cookie _presence_ (optimistic UX, never
authorization — real validation happens on Node). Cookie names come
from the dependency-free `/cookies` subpath so the Edge bundle never
imports server code:

```ts
// lib/auth-cookie-names.ts
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'
export const sessionCookieNames: readonly string[] = getBetterAuthSessionCookieNames({
  baseURL: exampleBaseURL,
})
```

```ts
// middleware.ts
import { createAuthMiddleware } from '@payload-auth-link/next'
import { sessionCookieNames } from './lib/auth-cookie-names'

export default createAuthMiddleware({
  sessionCookieNames,
  publicPaths: ['/', '/sign-in'],
})

export const config = {
  // Segment-anchored: bare `api`/`admin` prefixes would also exempt
  // frontend routes like `/admin-only` from the middleware.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api(?:/|$)|admin(?:/|$)).*)'],
}
```

Mounting Auth.js alongside (as `examples/basic` does — see the
[Auth.js guide](guide-authjs.md)) adds a second cookie-name source
and a second public sign-in path:

```ts
// lib/auth-cookie-names.ts (dual-provider delta)
import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'
export const sessionCookieNames: readonly string[] = [
  ...getBetterAuthSessionCookieNames({ baseURL: exampleBaseURL }),
  ...getAuthJsSessionCookieNames({ baseURL: exampleBaseURL }),
]

// middleware.ts (dual-provider delta)
export default createAuthMiddleware({
  sessionCookieNames,
  publicPaths: ['/', '/sign-in', '/sign-in-authjs'],
})
```

**Server validation + hydration** (`lib/session.ts`, layout):

```ts
// lib/session.ts
import { createSessionVerifier } from '@payload-auth-link/next'
import { exampleBaseURL } from './auth-cookie-names'

// Anchor to the canonical origin: host headers are client-spoofable
// and the session cookie is forwarded to this origin, so the
// header-derived fallback is local-development only.
export const verifySession = createSessionVerifier({ baseUrl: exampleBaseURL })
```

```tsx
// app/(frontend)/layout.tsx
import type { ReactNode } from 'react'
import { AuthLinkServerProvider } from '@payload-auth-link/next'
import { verifySession } from '../../lib/session'

export default function FrontendLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthLinkServerProvider verify={verifySession}>{children}</AuthLinkServerProvider>
      </body>
    </html>
  )
}
```

**A sign-in form.** POST to Better Auth's endpoints, then refresh both
layers (`useAuthLinkRefresh` re-reads the session endpoint and
revalidates server state):

```tsx
'use client'

import { safeRedirectPath, useAuthLinkRefresh } from '@payload-auth-link/next'
import { useRouter, useSearchParams } from 'next/navigation'

const router = useRouter()
const searchParams = useSearchParams()
const refreshAuth = useAuthLinkRefresh()

const response = await fetch('/api/auth/sign-up/email', {
  method: 'POST',
  credentials: 'same-origin',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name: email, email, password }),
})
if (response.ok) {
  await refreshAuth()
  // The redirect param is attacker-controlled input: narrow it to an
  // in-app path so a crafted link cannot bounce fresh logins off-site.
  router.push(safeRedirectPath(searchParams.get('redirect')))
}
```

The example's full form (`app/(frontend)/sign-in/form.tsx`) adds
sign-in mode, error display, and the local-only dev verification
stamp — copy it.

## Run and verify

```bash
# Dev-only admin seed (explicit opt-in — nothing is seeded without it):
ALLOW_DEV_ADMIN_SEED=true DEV_ADMIN_PASSWORD=choose-a-password bun run dev:example
```

1. Open `/sign-in`, create an account — you land on `/account` with
   the `user` role.
2. `GET /api/auth-link/session` returns
   `{ user: { id, collection, email, roles } }`.
3. Open `/admin` (seeded admin: `dev@payload-auth-link.test` with
   your `DEV_ADMIN_PASSWORD`), browse Collections → Users: your user
   is there with its role and 1 linked identity.
4. Sign out via the user menu: the session is revoked, cookies are
   expired, `/account` bounces back to sign-in.

## Next steps

- [TanStack Start guide](guide-tanstack-start.md): the same
  integration on Start (Payload v4) — same calls, same behavior.
- [Tour](tour.md): what every file in the example does.
- [Concepts](concepts.md): ports, JIT linking, verification gating.
- [Better Auth guide](guide-better-auth.md): verification, plugins,
  custom cookie names, session tuning.
- [Auth.js guide](guide-authjs.md): mount Auth.js alongside (or
  instead) — credentials, builder signup, OAuth.
- [Troubleshooting](troubleshooting.md): the failure modes we hit
  building this, and their fixes.
