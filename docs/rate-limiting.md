# Rate limiting

**payload-auth-link ships no rate limiter, so abuse control is your
job.** Core has no shared counter storage, and a limiter that lives in
one process protects nothing once you run two. This guide lists
every HTTP surface the library exposes or relies on, gives a
starting limit and key for each, and says where to enforce it.

The numbers below are starting points for a typical app with a few
thousand users. Tune them against your real traffic. Every limit
should return `429`, with `Retry-After` when you control the
response.

## Where to enforce

| Layer                                                        | Use it for                                                           | Notes                                                                                                                  |
| ------------------------------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Reverse proxy / CDN / WAF (nginx `limit_req`, Cloudflare, …) | Coarse per-IP ceilings on every auth path; the first line of defense | Sees the real client IP; rejects traffic before your app spends anything on it                                         |
| Better Auth `rateLimit` (in the engine's `options`)          | Everything under Better Auth's base path (`/api/auth/*` by default)  | Built in, per IP + path, path-aware rules; needs shared storage in production ([below](#better-auth-built-in-limiter)) |
| Next middleware / Start request middleware                   | Payload's users auth routes, `/api/auth-link/*`, GraphQL             | Needs a shared store (Redis, Upstash, Postgres); see [examples](#middleware-examples)                                  |
| Route wrapper around a handler                               | Auth.js catch-all, your own signup route                             | Wrap the handler you pass to `createRouteHandlers` / `createServerRouteHandlers` (the reference examples do this)      |
| Payload `auth.maxLoginAttempts` / `lockTime`                 | Per-account lockout on local password login                          | Defaults are 5 attempts / 10 minutes. It is a lockout, not a rate limit ([pitfalls](#pitfalls))                        |

## Endpoint inventory

Paths assume Payload's default `routes.api` (`/api`), a users
collection with the slug `users`, Better Auth at `/api/auth`, and
Auth.js at `/api/authjs` (the provider's default `basePath`).

### Plugin endpoints (`/api/auth-link/*`)

Registered by `authLink()` (`endpoints.ts`; `organizations.ts` only
when `organizations` is configured). Each one verifies the session
itself, and every state-changing one also requires the CSRF proof.
None of them takes a password or a code, so these limits protect
cost (database reads), not credentials.

| Endpoint                                   | Purpose                            | Starting limit (key)            | Notes                                                                                                                                                                                |
| ------------------------------------------ | ---------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /api/auth-link/session`               | current `SessionUser` (or guest)   | 300 / min (IP)                  | Called on page loads and by the client refresh hooks. Each call reads the provider session and reloads the user. Keep the limit generous: a 429 here looks like a sign-out to the UI |
| `DELETE /api/auth-link/session`            | logout (revokes provider sessions) | 30 / min (IP)                   | Anonymous calls are cheap (no provider walk)                                                                                                                                         |
| `GET /api/auth-link/organizations`         | caller's memberships               | 120 / min (IP)                  |                                                                                                                                                                                      |
| `POST /api/auth-link/organizations`        | create an organization             | 10 / hour (IP); 10 / day (user) | Creates rows; also limit per signed-in user if orgs are self-service                                                                                                                 |
| `POST /api/auth-link/organizations/invite` | invite by email                    | 30 / hour (IP)                  | Each invite can trigger an email you send; cap it like any outbound-mail path                                                                                                        |
| `POST /api/auth-link/organizations/accept` | accept an invitation               | 30 / hour (IP)                  |                                                                                                                                                                                      |

The admin login view (`admin.loginView: 'provider'`) adds no endpoint
of its own. It posts to `${admin.authBase}/sign-in/email` (Better
Auth's route, see below), and Payload's own admin form posts to
`/api/users/login`.

### Payload's auth operations on the users collection

Payload 3 has no request-level rate limiter. These are Payload's
endpoints. The plugin adds hooks that refuse suspended and
provider-linked accounts, but it does not throttle them. A users
collection that the plugin creates disables the local strategy
(`disableLocalStrategy`), so local login and password reset are not
available there. A **host-owned** users collection that keeps
`auth: true` exposes all of them.

| Endpoint (REST)                                                  | GraphQL                            | Starting limit (key)                                      |
| ---------------------------------------------------------------- | ---------------------------------- | --------------------------------------------------------- |
| `POST /api/users/login`                                          | `loginUsers`                       | 10 / 10 min (IP) + `maxLoginAttempts` (account)           |
| `POST /api/users/forgot-password`                                | `forgotPasswordUsers`              | 5 / hour (IP); 3 / hour (email, if you can read the body) |
| `POST /api/users/reset-password`                                 | `resetPasswordUsers`               | 10 / hour (IP)                                            |
| `POST /api/users/verify/:token`                                  | `verifyEmailUsers`                 | 10 / hour (IP)                                            |
| `POST /api/users/unlock`                                         | `unlockUsers`                      | 10 / hour (IP); role managers only by default             |
| `POST /api/users/refresh-token`                                  | `refreshTokenUsers`                | 60 / hour (IP)                                            |
| `POST /api/users/first-register`                                 | —                                  | 5 / hour (IP); works only on an empty database            |
| `POST /api/users/logout`, `GET /api/users/me`, `GET /api/access` | `logoutUsers`, `meUsers`, `access` | general API ceiling                                       |

**GraphQL** carries every operation through one `POST /api/graphql`.
A path-based limiter cannot tell `loginUsers` apart from a harmless
query, and a single request can batch many operations. Do one of
these:

- If you do not use GraphQL, disable it (`graphQL: { disable: true }`,
  and in Next delete `app/(payload)/api/graphql/route.ts`).
- Otherwise, put a tight overall ceiling on `/api/graphql` (for
  example 60 / min per IP) and keep `maxLoginAttempts` on. It counts
  per account whichever transport the login came through.

### Better Auth (`/api/auth/*`)

Every Better Auth route is served by the engine's `auth.handler`
mounted on the catch-all, so Better Auth's own limiter sees them all.
The ones that matter for abuse (core plus the plugins the examples
enable):

| Route family                                                                                                                                        | Built-in default (per IP + path)           | Recommendation                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `/sign-in/*`, `/sign-up/*`, `/change-password`, `/change-email`                                                                                     | 3 / 10 s                                   | keep; it adds up to about 1,000/hour, so add a proxy ceiling for slow-and-steady stuffing |
| `/request-password-reset`, `/send-verification-email`, `/forget-password*`, `/email-otp/send-verification-otp`, `/email-otp/request-password-reset` | 3 / 60 s                                   | keep, or tighten to an hourly window (outbound mail)                                      |
| `/two-factor/*` (twoFactor plugin)                                                                                                                  | 3 / 10 s                                   | tighten verify routes, e.g. `/two-factor/verify-totp` 5 / 5 min                           |
| `/sign-in/magic-link`, `/magic-link/verify` (magicLink plugin)                                                                                      | 5 / 60 s (plugin `rateLimit` option)       | keep                                                                                      |
| `/sign-in/email-otp`, `/email-otp/verify-email`, `/email-otp/check-verification-otp` (emailOTP)                                                     | 3 / 60 s (plugin `rateLimit` option)       | keep; OTP guesses are the brute-force surface                                             |
| `/phone-number/*` (phoneNumber plugin)                                                                                                              | 10 / 60 s                                  | tighten send routes (SMS cost)                                                            |
| `/passkey/*` (`@better-auth/passkey`)                                                                                                               | global rule                                | `customRules` for `/passkey/verify-authentication`, e.g. 10 / min                         |
| everything else (`/get-session`, `/sign-out`, `/list-sessions`, `/api-key/*`, …)                                                                    | global `window`/`max` (default 100 / 10 s) | set a global `max` that fits your traffic                                                 |

Better Auth API keys (`@better-auth/api-key`) also have a separate
**per-key** limit, configured with the plugin's
`rateLimit: { enabled, timeWindow, maxRequests }` and stored on the
key row. That limit applies when a key is verified, which includes
`authLinkServer(payload).verifyApiKey`.

The limiter runs only on HTTP requests that pass through
`auth.handler`. Server-side `auth.api.*` calls are not counted, and
the plugin's own session reads use those calls. So
`/api/auth-link/session` traffic does not use up Better Auth limits,
and Better Auth's limiter does not protect it either.

### Auth.js (`/api/authjs/*`)

Auth.js core ships no limiter. Wrap the catch-all handler, as both
reference examples do (`app/api/authjs/[...authjs]/route.ts`,
`src/app/api.authjs.$.ts`):

| Route                                                                 | Starting limit (key)                                     |
| --------------------------------------------------------------------- | -------------------------------------------------------- |
| `POST /api/authjs/callback/credentials`                               | 10 / 10 min (IP); also count failures per email          |
| `GET\|POST /api/authjs/callback/<email provider>` (magic link / code) | 3 / 10 min (email + IP), correct code included           |
| `POST /api/authjs/signin/<provider>` (starts OAuth / sends mail)      | 10 / 10 min (IP); mail-sending providers per email too   |
| `GET /api/authjs/callback/<oauth provider>`                           | 30 / 10 min (IP)                                         |
| `GET /api/authjs/session`, `/csrf`, `/providers`                      | general ceiling                                          |
| your credentials **signup** route (builder-owned)                     | 10 / 10 min (email); the examples' `authjs-signup` route |

The Auth.js engine reads sessions in-process (it calls `Auth()` with
a synthesized request), so the plugin's session checks never pass
through your wrapper.

## Better Auth built-in limiter

```ts
createBetterAuthEngine({
  // …
  options: {
    // …
    rateLimit: {
      enabled: true, // the default is "production only" (NODE_ENV)
      storage: 'database', // or 'secondary-storage', or customStorage
      window: 60,
      max: 300,
      customRules: {
        '/two-factor/verify-totp': { window: 300, max: 5 },
        '/passkey/verify-authentication': { window: 60, max: 10 },
        // false disables a rule; a function can decide per request
      },
    },
    advanced: {
      ipAddress: {
        // Pick ONE header your edge sets and clients cannot spoof...
        ipAddressHeaders: ['cf-connecting-ip'],
        // ...or walk X-Forwarded-For past your own proxies:
        // trustedProxies: ['10.0.0.0/24'],
      },
    },
  },
})
```

How the limiter behaves (Better Auth 1.7, read from its source):

- **Enabled** defaults to `NODE_ENV === 'production'`. Set it
  explicitly so staging behaves like production.
- **Key** is client IP + path. IPv6 addresses are grouped by
  `advanced.ipAddress.ipv6Subnet` (default `/64`). If no IP can be
  resolved, every client shares one bucket per path, and Better Auth
  logs a warning once. With `disableIpTracking: true`, requests
  without an IP are not limited at all.
- **Rule precedence**: built-in special rules, then plugin rules,
  then your `customRules`. `customRules` keys match the path exactly
  or with `*` wildcards.
- **Response**: `429` with an `X-Retry-After` header (in seconds), not
  `Retry-After`.
- **Storage**:
  - `memory` (the default) is per process, so it is wrong for more
    than one instance or a serverless deploy.
  - `database` uses the **`ba-rate-limits`** collection, which the
    provider always declares (`key` unique, `count`, `lastRequest`).
    There is no extra schema step. This adapter has no native atomic
    increment, so Better Auth uses its fallback: a snapshot-guarded
    update with retries. Under heavy contention on one key, that
    fallback can fail with a "could not complete an atomic increment"
    error instead of counting. Every limited request also adds
    database round trips.
  - `secondary-storage` uses your `secondaryStorage`, which must
    implement `increment`. This is the right choice at scale (Redis,
    Upstash). You can also supply `customStorage: { consume(key, rule) }`
    (atomic check-and-increment).

The reference examples enable the limiter with dev-scale ceilings
(100 sign-ins/min, because every e2e request shares one IP). Do not
copy those numbers to production.

## Middleware examples

Both examples count per IP in a shared store that you provide. The
interface below is yours to implement. One atomic `INCR` with
`EXPIRE` in Redis is enough:

```ts
// lib/rate-limit-rules.ts — framework-free, shared by both adapters
export type RateLimitStore = {
  /** Count one hit for `key` in a fixed `windowSeconds` window; resolve the new count. */
  readonly hit: (key: string, windowSeconds: number) => Promise<number>
}

type Rule = {
  readonly name: string
  readonly method: string
  readonly path: RegExp
  readonly windowSeconds: number
  readonly max: number
}

const rules: readonly Rule[] = [
  { name: 'login', method: 'POST', path: /^\/api\/users\/login$/, windowSeconds: 600, max: 10 },
  {
    name: 'forgot',
    method: 'POST',
    path: /^\/api\/users\/forgot-password$/,
    windowSeconds: 3600,
    max: 5,
  },
  {
    name: 'reset',
    method: 'POST',
    path: /^\/api\/users\/reset-password$/,
    windowSeconds: 3600,
    max: 10,
  },
  { name: 'verify', method: 'POST', path: /^\/api\/users\/verify\//, windowSeconds: 3600, max: 10 },
  {
    name: 'refresh',
    method: 'POST',
    path: /^\/api\/users\/refresh-token$/,
    windowSeconds: 3600,
    max: 60,
  },
  { name: 'graphql', method: 'POST', path: /^\/api\/graphql$/, windowSeconds: 60, max: 60 },
  {
    name: 'session',
    method: 'GET',
    path: /^\/api\/auth-link\/session$/,
    windowSeconds: 60,
    max: 300,
  },
  {
    name: 'org-create',
    method: 'POST',
    path: /^\/api\/auth-link\/organizations$/,
    windowSeconds: 3600,
    max: 10,
  },
  {
    name: 'org-invite',
    method: 'POST',
    path: /^\/api\/auth-link\/organizations\/invite$/,
    windowSeconds: 3600,
    max: 30,
  },
]

/**
 * The client IP, from ONE header your edge sets and overwrites
 * (Vercel: x-real-ip; Cloudflare: cf-connecting-ip). Never trust the
 * leftmost X-Forwarded-For entry — clients write it.
 */
function clientIp(request: Request): string {
  return request.headers.get('x-real-ip') ?? 'unknown'
}

/** A 429 to return, or null to let the request through. */
export async function rateLimit(store: RateLimitStore, request: Request): Promise<Response | null> {
  const { pathname } = new URL(request.url)
  const rule = rules.find((r) => r.method === request.method && r.path.test(pathname))
  if (rule === undefined) {
    return null
  }
  const count = await store.hit(`${rule.name}:${clientIp(request)}`, rule.windowSeconds)
  if (count <= rule.max) {
    return null
  }
  return Response.json(
    { error: 'too many requests' },
    { status: 429, headers: { 'Retry-After': String(rule.windowSeconds) } }
  )
}
```

**Next** (`middleware.ts`, or `proxy.ts` on Next 16). Compose the
limiter with the optimistic auth bounce using `checkAuthCookies`. The
matcher must include `/api` for the limiter to see those routes. The
reference matcher excludes it because the bounce must never run there:

```ts
import { checkAuthCookies } from '@payload-auth-link/next'
import { NextResponse, type NextRequest } from 'next/server'
import { sessionCookieNames } from './lib/auth-cookie-names'
import { rateLimit } from './lib/rate-limit-rules'
import { store } from './lib/rate-limit-store' // your Edge-compatible store (e.g. Upstash REST)

export default async function middleware(request: NextRequest): Promise<Response> {
  if (/^\/api(\/|$)/.test(request.nextUrl.pathname)) {
    return (await rateLimit(store, request)) ?? NextResponse.next()
  }
  if (/^\/admin(\/|$)/.test(request.nextUrl.pathname)) {
    return NextResponse.next()
  }
  return (
    checkAuthCookies(request, { sessionCookieNames, publicPaths: ['/', '/sign-in'] }) ??
    NextResponse.next()
  )
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

Edge middleware cannot import `payload` or database code (see
[troubleshooting](troubleshooting.md#edge-build-fails-importing-payload--database-code)),
so the store must be Edge-compatible, such as an HTTP Redis like
Upstash. If your store needs Node, wrap the Payload REST route
handlers in `app/(payload)/api/[...slug]/route.ts` instead.

**TanStack Start** (`src/start.ts`). Add a request middleware in
front of the existing ones. Returning a `Response` short-circuits the
request, the same way `createAuthRequestMiddleware` returns its
redirect:

```ts
import { createAuthRequestMiddleware } from '@payload-auth-link/tanstack-start'
import { createCsrfMiddleware, createMiddleware, createStart } from '@tanstack/react-start'
import { rateLimit } from './lib/rate-limit-rules'
import { store } from './lib/rate-limit-store'
import { sessionCookieNames } from './lib/session-cookie-names'

const rateLimitMiddleware = createMiddleware().server(async ({ request, next }) => {
  const limited = await rateLimit(store, request)
  return limited ?? next()
})

const authRequestMiddleware = createAuthRequestMiddleware({
  sessionCookieNames,
  publicPaths: ['/', '/sign-in', /^\/api(\/|$)/, /^\/admin(\/|$)/],
})

const csrfMiddleware = createCsrfMiddleware({
  filter: (ctx) => ctx.handlerType === 'serverFn',
})

export const startInstance = createStart(() => ({
  requestMiddleware: [rateLimitMiddleware, csrfMiddleware, authRequestMiddleware],
}))
```

**Route wrapper** (either framework), as in the examples' Auth.js
catch-all:

```ts
// Next: app/api/authjs/[...authjs]/route.ts
export const { GET, POST } = createRouteHandlers(async (request) => {
  return (await rateLimit(store, request)) ?? handleAuthJsRequest(request)
})
// Start: server: { handlers: createServerRouteHandlers(/* same function */) }
```

## Pitfalls

- **Spoofable client IPs.** Every client can set `X-Forwarded-For`,
  and any limiter that trusts its leftmost entry can be bypassed by
  rotating the header. Read one header that your edge overwrites, or
  walk the chain past known proxies (Better Auth's
  `trustedProxies`). The examples' `clientKey()` reads the first
  forwarded entry. That is a dev convenience, not a production
  design.
- **Shared IPs.** Offices, universities and carrier-grade NAT put
  many users behind one address, and IPv6 users get a whole `/64`. A
  tight per-IP limit there locks out real people. Keep per-IP
  ceilings generous, and put the tight limits on per-account or
  per-identifier keys (email + IP for OTP and magic-link callbacks,
  as the Auth.js examples do).
- **No IP at all.** Behind a proxy that forwards no client-IP header,
  every request lands in one bucket. Better Auth warns once. A
  homegrown limiter falls back to `'unknown'` and throttles everyone
  together. Fix the proxy rather than raising the limit.
- **`trustProxy` here is not about IPs.** The `trustProxy` flag on
  `createSessionVerifier`'s `hostPolicy` controls only the dev-mode
  origin fallback. Nothing in payload-auth-link resolves client IPs.
- **Lockout is a denial-of-service tool.** Payload's
  `maxLoginAttempts` locks the **account**, so anyone who knows an
  email can lock its owner out. Keep `lockTime` short, alert on
  lockouts, and stop the attacker with the per-IP limit first.
- **In-memory counters.** The examples' `lib/rate-limit.ts` and
  Better Auth's `memory` storage are per process. Behind several
  instances or on serverless, each instance counts separately, so
  the effective limit is the configured one times the number of
  instances.
- **The session endpoint is hot.** `GET /api/auth-link/session` runs
  on navigation and refresh. A tight limit makes signed-in users look
  signed out. Size it for page views, not for logins.
- **Body-keyed limits need care.** To key on the email in a login
  body, read `request.clone()` so the downstream handler still gets
  the body, and normalize the address (lowercase) before using it as
  a key.
