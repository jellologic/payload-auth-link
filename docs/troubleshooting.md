# Troubleshooting

Every entry below is a failure mode hit while building this project,
with the fix that resolved it. Symptoms first.

## Everyone bounces to sign-in (including fresh logins)

The middleware's cookie names don't match the engine's. The names in
`lib/auth-cookie-names.ts` must mirror the engine options exactly —
custom `advanced.cookies` names (Better Auth) or
`cookies.sessionToken.name` (Auth.js) included. A mismatch fails closed by design. Compare the
`set-cookie` response headers against your names list.

## Auth.js sign-in shows the form error, or lands on the Auth.js error page

The credentials callback always 302s; read the final URL (see the
[Auth.js guide](guide-authjs.md)). If _every_ login fails, check the
server log for `CredentialsSignin` (wrong password / unknown user —
expected for bad credentials) versus `Configuration` (missing
secret, untrusted host). If the user exists but login never sticks,
the row is unverified — the plugin links verified identities only.

## `UnsupportedStrategy` 500s on every Auth.js action

Credentials + database session strategy. Auth.js rejects that
combination at config time; the engine fail-fasts first — including
through factory-wrapped providers, which it inspects by calling them
with `{}` exactly as Auth.js does
(`packages/provider-authjs/src/engine.ts`, covered by the engine
suite's factory tests). A credentials provider in any form without
explicit `session: { strategy: 'jwt' }` throws at wiring with the fix
attached; a factory that throws on inspection fails at wiring as
`provider factory threw` (Auth.js would throw identically on first
request — the factory must tolerate `{}`).

So a request-time 500 means a genuine problem, not an inspection
miss: either the served config really lacks the jwt strategy (check
that the route serves the engine's `config` — a hand-composed `Auth()`
bypasses the fail-fast), or a factory threw (read the wiring error,
not the 500 page). Fix: `Credentials(...)` — direct or via a
`{}`-tolerant factory — with explicit `session: { strategy: 'jwt' }`.

## `AdapterMappingError` / `UnsupportedSchemaError` on login

A storage row is corrupt (missing id field, wrong date shape, account
without `userId`). Auth.js throws `AdapterMappingError` naming the
field — inspect the `aj-*` row directly. Better Auth's equivalent
fail-fast is `UnsupportedSchemaError` on the `ba-*` row. Fix or
delete the row; this never becomes a silent login failure — that is
the point.

## Edge build fails importing `payload` / database code

Something in `middleware.ts`'s import graph reaches the engine or
`payload.config`. Middleware must import _only_ the cookie-names
module (which uses the `/cookies` subpaths). The classic trap: a
shared `lib/auth.ts` exporting both the engine and the names —
split them, as the example does.

## Session endpoint 401s with a live provider session

- **Unverified email.** Provider session exists, plugin linking
  refused. Verify the user (Better Auth: complete verification;
  Auth.js credentials: stamp `emailVerified`).
- **Missing origin (Auth.js / verifier).** Without `baseURL`
  (`AUTH_URL`) the internal session request falls back to the live
  `host`/`x-forwarded-host` headers. Proxies that strip host break
  it — and spoofed host headers would redirect the forwarded
  session cookie, so set the canonical origin in production
  instead of relying on the fallback.
- **Clock skew.** Expiry checks run against the injected clock;
  wild skew reads as expired.

## Changes don't take effect locally

Stale `dist` — cross-package workspace imports resolve `dist`, not
`src` (same-package unit tests import `src` relatively and are
unaffected). `bun run build` after cross-package core changes. (The
`e2e` and `dev:example` scripts build first; ad-hoc `next dev` does
not.)

## Postgres parity run fails to boot

`bun run e2e:postgres` expects Postgres at `localhost:5433`
(`postgres` / `payload`): `docker run -d --name pal-pg -e
POSTGRES_PASSWORD=payload -p 5433:5432 postgres:16`. Override with
`PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `DATABASE_URL`.

## Mongo parity run throws lock/write conflicts

Single-node memory-server transients under concurrent transactions.
The example's mongo branch already disables transactions and uses
wiredTiger — if you re-enable transactions, expect `LockTimeout` /
`WriteConflict` flakes. Never "fix" these with product-code retries;
they are a test-environment artifact (real replica sets don't
behave this way).

## `attw` / `publint` failures on release

Run `bun run release:check`. `attw` must use `--profile esm-only`
(all packages are ESM-only by decision — legacy node10/CJS
resolution failures are the documented tradeoff). If `publint`
complains about missing files, check the package `files` list and
the `exports` map agree.
