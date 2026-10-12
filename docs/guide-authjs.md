# Auth.js guide

`@payload-auth-link/provider-authjs`: Auth.js (@auth/core) with
Payload as its database, behind `IdentityProviderPort`. Fully
local: no SaaS, no webhooks — sessions verify read-time through
Auth.js's own session action.

## Install

```bash
bun add @payload-auth-link/provider-authjs @auth/core
```

(`@auth/core` ships as a dependency of the provider, but you import
it yourself for providers like `Credentials` in the engine below, so
it is a direct dependency too — same rule as `better-auth` in
[getting-started](getting-started.md).)

## Engine

```ts
import Credentials from '@auth/core/providers/credentials'
import { createAuthJsCredentials, createAuthJsEngine } from '@payload-auth-link/provider-authjs'

const credentials = createAuthJsCredentials({ getPayload: loadPayload })

export const engine = createAuthJsEngine({
  getPayload: loadPayload,
  // Required in production: anchors the internal session read (the
  // session cookie is forwarded there) and derives secure-cookie names.
  // Falls back to AUTH_URL, then to request host headers (local dev only).
  baseURL: 'https://app.example.com',
  options: {
    secret: process.env.AUTH_SECRET!,
    session: { strategy: 'jwt', maxAge: 3600 },
    providers: [
      Credentials({
        credentials: {
          email: { label: 'Email', type: 'email' },
          password: { label: 'Password', type: 'password' },
        },
        authorize: (candidate) => credentials.authorize(candidate),
      }),
    ],
  },
})

export const { provider, collections, handleRequest } = engine
```

Mount `handleRequest` at `/api/authjs/[...authjs]` (the default
`basePath`, chosen to coexist with Better Auth's `/api/auth`),
spread `collections` (`aj-*`) into the Payload config, register
`provider` with the plugin.

Engine fail-fasts (all `InvalidConfigError`, all at wiring time):

- **Credentials requires explicit `session: { strategy: 'jwt' }`.**
  Auth.js rejects credentials + database sessions at config time
  with loud 500s (`UnsupportedStrategy`); the engine fails faster
  with the fix attached — including through factory-wrapped
  providers, which it inspects the same way Auth.js normalizes
  them (called with `{}`).
- **Secret required** via `options.secret` or `AUTH_SECRET` — a
  missing secret throws here instead of 500ing on first use.
- `basePath` defaults to `/api/authjs`, `trustHost` to `true`;
  builders override both. `true` is mandatory, not a choice: raw
  `@auth/core` answers every request with `UntrustedHost` unless it
  is truthy (framework adapters consult `AUTH_URL` for trust, but the
  raw `Auth()` this engine calls never does — core-side, the env var
  is inert; engine-side, `AUTH_URL` remains the `baseURL` fallback).
  Host strictness comes from origin anchoring instead:
  `handleRequest` rewrites the request origin to the configured
  `baseURL` before core sees it, so forwarded host headers cannot
  steer redirects or callback validation. Set `baseURL` to the
  canonical origin in production; without it, requests pass through
  on their arrival origin (local-dev convenience only).

## Credentials: builder-owned signup

Auth.js credentials store nothing — registration is an explicit
service call, and **verification is your signup policy**: the plugin
refuses to link unverified identities, so credentials users stay
locked out until you stamp them.

```ts
// app/api/your-signup/route.ts
const result = await credentials.register({
  email,
  password, // min 8 chars (floor; raise via minPasswordLength, never lower)
  name,
  emailVerified: new Date(), // ONLY after real verification (email link, admin approval…)
})
if (result.isErr()) {
  const error = result.error
  if (error instanceof UserExistsError) {
    return Response.json({ error: 'that email is already registered' }, { status: 409 })
  }
  if (error instanceof WeakPasswordError || error instanceof InvalidEmailError) {
    return Response.json({ error: error.message }, { status: 400 })
  }
  return Response.json({ error: 'registration failed, try again later' }, { status: 500 })
}
const user = result.value
```

Registration flows through the core `registerWithStore` use-case over
an `aj-users` store and never throws: errors arrive as values
(`UserExistsError` → 409, `WeakPasswordError` / `InvalidEmailError`
→ 400, `AdapterOperationError` → 500 with its cause kept
server-side).

Passwords hash with scrypt (random salt, constant-time verify);
Auth.js never sees them — `authorize` reads the `aj-users` row and
returns the user (or `null` for unknown email / wrong password;
corrupt rows throw `AdapterMappingError`, loudly). Unknown emails
and hashless rows burn a dummy scrypt verification, so response
timing reveals no account existence.

**Why a separate credential store, not Payload's password auth?**
Credentials live in the provider-owned `aj-users` collection rather
than the Payload users collection's native `password` field.
Provider secrets stay with the provider, just as Better Auth keeps
its own accounts table, and Payload users stay identity documents
that any provider can link to. The cost is a second credential
pipeline to maintain. Moving to Payload-native password auth would
be a breaking change and needs its own design pass. It is tracked as
an accepted risk (ARCH-5), not a commitment.

The example's signup route stamps every signup immediately **because
it has no email delivery** — mirroring Better Auth's
`requireEmailVerification: false`. Do not copy that stamp into
production.

## The credentials callback contract

@auth/core's credentials callback **always answers 302** — to your
`callbackUrl` on success (session cookie attached), to the Auth.js
error page with `?error=…` when `authorize` rejects. There is no JSON
mode (`json=true` is a next-auth v4 convention @auth/core ignores).
Drive it like the example form does:

1. `GET /api/authjs/csrf` → `{ csrfToken }` (sets the CSRF cookie).
2. `POST /api/authjs/callback/credentials` (form body: `csrfToken`,
   `email`, `password`, `callbackUrl`), follow the redirect.
3. Read the final URL: `error=` means rejected — show the form error.
4. On success the session cookie is jarred; `refreshAuth()` and go.

## Sessions, claims, revocation

### JWT post-logout replay window

**Credentials are JWT-only** (Auth.js never touches the adapter for
them): users come solely from `authorize`, sessions are encrypted
JWTs. A copied token replays until `maxAge` — there is no
server-side revocation for stateless JWTs, and no denylist is built
(see `docs/SPRINT.md` Accepted risks for the deliberate deferral).
Logout expires every registered cookie (even on the idempotent 401
path), which stops the browser presenting the token but does not
invalidate copies.

The mitigation is a short window: credentials deployments default
to `session.maxAge` of one hour (3600s) instead of Auth.js's thirty
days, unless you set `maxAge` explicitly. Lower it further for
sensitive deployments; the window is always exactly your `maxAge`.

- The engine chains your `callbacks` with the claims the port needs
  (subject + verification timestamp). Yours run first; the claims
  layer wins on its own keys; a `null` jwt return (forced logout)
  is respected.
- The port reads sessions through Auth.js's own session action
  (never a hand-rolled JWT decode) and needs a `host` header to
  build the internal request — the plugin endpoints pass live
  headers through, so this just works.
- JWTs over ~4k chunk across `name.0`, `name.1`, …; the port joins
  them and logout expires the listed slots (default `.0`–`.2`, ~12k
  of token — ours measure ~550 bytes). Raise `chunkSlots` on the
  engine (and mirror it in the middleware names) when custom claims
  push past that; only tokens beyond the raised slots need Auth.js's
  own signout action, which clears arbitrary chunks.

## OAuth / database sessions

Add OAuth providers to `providers` as usual; the Payload database
adapter serves users, accounts, sessions, verification tokens, and
authenticators (Auth.js ids live in `auId`; accounts carry a
composite `key` since Payload has no compound unique indexes).
Database sessions revoke server-side via `deleteSession`. Mixing
OAuth (database) with credentials in one engine is impossible —
Auth.js forbids it — so credentials deployments stay JWT while
OAuth-only deployments may choose either strategy.

## Cookie names (middleware + logout)

```ts
import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'

getAuthJsSessionCookieNames({ baseURL }) // + useSecureCookies / sessionTokenName / chunkSlots mirrors
```

Concatenate with your other providers' names for the middleware
presence check. Only session-indicating cookies are listed —
csrf/callback cookies exist pre-login and never count as a session.

**Production needs a canonical https `baseURL`.** Secure-cookie
names follow one rule shared by every provider: an explicit
`useSecureCookies` wins, then the configured origin (https →
secure), then `NODE_ENV=production`. The https origin is the
only input on which both SDKs and the session layer's origin
anchoring agree — without it, production falls back to
`NODE_ENV` detection, which matches Auth.js on https deployments
but fails closed (session detection misses) on http ones.
(`@auth/core` exposes no public cookie getter, so these names
mirror its internal `defaultCookies` rule instead of deriving
from it; the Auth.js e2e specs run real Auth.js cookies through
this derivation and would catch upstream drift.)

## Rate limiting (builder-owned)

The library ships no throttles — core has no storage primitive for
counters, so abuse control is builder-owned. Auth.js core itself
ships none either, which is why the examples carry a reference
pattern — copy it, then harden it:

- `lib/rate-limit.ts`: a minimal in-memory sliding-window limiter
  (`createRateLimiter`), a 429 + `Retry-After` responder, and a
  forwarded-IP client key. Deterministic unit tests included.
- The builder signup route throttles per email (10 per 10 minutes):
  legit signups use each address once, so abuse of one address can
  never lock out another. Proven by `e2e/rate-limit.spec.ts`, which
  asserts 200 → 409s → 429 + `Retry-After`.
- The `/api/authjs/*` catch-all (the authorize path) throttles per
  client IP at a generous ceiling (100 per 10 minutes).
- Better Auth paths use Better Auth's own `rateLimit` option (see
  the [Better Auth guide](guide-better-auth.md)) — also configured
  in the examples.

In-memory state is dev-scale: it neither spans instances nor
survives restarts. Production deployments keep the pattern (per-key
windows, 429 + `Retry-After`) but back it with a shared store with
TTLs (Redis, Upstash, Postgres counters) and tune ceilings down to
real traffic. Skipping throttles entirely leaves signup, sign-in,
and authorize open to brute-force and enumeration pressure.
