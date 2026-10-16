# Better Auth guide

`@payload-auth-link/provider-better-auth`: Better Auth with Payload
as its database, behind `IdentityProviderPort`. This guide covers
what the engine adds and constrains; Better Auth's own docs cover
`BetterAuthOptions` in full.

## Engine

```ts
import { nextCookies } from 'better-auth/next-js'

const engine = createBetterAuthEngine({
  getPayload: loadPayload, // cached getPayload thunk
  slugs: { session: 'sessions' }, // optional per-model overrides
  depth: 0, // Payload read depth for the adapter (default 0)
  collectionsAccess: undefined, // deny-all by default
  options: {
    baseURL: 'https://app.example.com',
    secret: process.env.PAYLOAD_SECRET!,
    // Framework cookie plugin, declared by you exactly as Better Auth
    // documents: `nextCookies()` on Next.js, `tanstackStartCookies()`
    // on TanStack Start. The engine never touches this list.
    plugins: [nextCookies()],
    emailAndPassword: { enabled: true },
    // …the rest is yours: rateLimit, session, advanced…
  },
})

export const { auth, provider, collections } = engine
```

`auth` mounts at `/api/auth/[...all]`; `provider` registers with the
plugin; `collections` spreads into `payload.config.ts`. The return
type is inferred, so plugin endpoints and `$Infer` session types flow
through untouched.

## Secure defaults

- **Verification required.** When `emailAndPassword` is present but
  silent on `requireEmailVerification`, the engine sets it `true`.
  Opt out explicitly only when you mean it (the example does — no
  email delivery — and says so). Unverified users hold provider
  sessions the plugin refuses to link (401 at the session endpoint).
- **No plugin-list surgery.** Framework cookie plugins
  (`nextCookies()`, `tanstackStartCookies()`, …) are declared in
  your `options.plugins` exactly as Better Auth documents them;
  the engine passes the list through verbatim. There is no second
  engine-owned cookie API to misconfigure — see the [TanStack Start
  guide](guide-tanstack-start.md) for the Start spelling.
- **No `databaseHooks` needed.** The plugin provisions Payload users
  lazily at session verification, so there is no signup hook to
  keep in sync and no ordering that strands users.

## Pass-through philosophy

`options` is Better Auth's options minus `database` (wired to
Payload here — it is omitted from the type, so passing it is a
compile error). Everything else — `plugins`, `rateLimit`,
`session`, `account`, `advanced` — passes through verbatim.

## Custom fields and plugin models

The adapter serves the five core models out of the box, and anything
else you declare. `additionalFields`, plugin-added core fields (the
organization plugin adds `session.activeOrganizationId`), and whole
plugin models (the organization plugin's `organization`, `member`,
`invitation`) all work the same way: declare them on the engine, and
matching Payload columns are generated while the adapter allowlists
exactly what you declared.

```ts
const engine = createBetterAuthEngine({
  getPayload: loadPayload,
  customFields: {
    user: [{ name: 'favoriteColor', type: 'text' }],
    session: [{ name: 'activeOrganizationId', type: 'text' }],
  },
  customModels: [
    {
      model: 'organization',
      fields: [
        { name: 'name', type: 'text', required: true },
        { name: 'slug', type: 'text', required: true, unique: true },
        { name: 'logo', type: 'text' },
        { name: 'metadata', type: 'text' },
      ],
    },
    // …member, invitation…
  ],
  options: {
    user: { additionalFields: { favoriteColor: { type: 'string' } } },
    plugins: [organization()],
    // …
  },
})
```

Field types map to Payload columns: `text`, `number`, `boolean`
(checkbox), `date`, `json`. Declarations are strict both directions
at startup: an undeclared schema field, a declared-but-absent name
(probably a typo), and an undeclared plugin model all throw
`UnsupportedSchemaError` naming the offender. Payload owns the row
timestamps — never declare `createdAt`/`updatedAt`. Custom models
get their own `ba-*` collections (override the slug per model) with
the same deny-all access and `baId` id column as core models.

- **Cookie cache is off unless you enable it.** When Better Auth's
  cookie cache is on, the port disables it per read
  (`disableCookieCache`, `disableRefresh`) — session reads are
  always live, never stale cache.

## Roles: the `admin` plugin's `role` is not Payload authorization

Payload roles are the one role system; the BA `admin` plugin's
`user.role` is **ignored by design** — see [One role system: Payload
roles](concepts.md#one-role-system-payload-roles). The plugin's
extra fields are ordinary storage as far as this adapter is
concerned: declare `user.role` / `banned` / `banReason` /
`banExpires` and `session.impersonatedBy` via `customFields` like
any other plugin fields, and BA's own admin endpoints may consult
the BA role. But nothing maps it into a session, a `SessionUser`, or
a Payload access decision — set Payload `roles` to grant rights,
and treat `banned` the same way (provider-side and optional, never
the authority). The same applies to the `organization` plugin's
member roles: storage-compatible, not Payload authorization.

## Cookie names (middleware + logout)

Session cookie names derive from your options through
`getBetterAuthSessionCookieNames` (the dependency-free `/cookies`
subpath — import it in Edge middleware, never the engine):

```ts
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

getBetterAuthSessionCookieNames({
  baseURL,
  advanced: options.advanced, // custom names must mirror here
  session: options.session, // cookie-cache shape must mirror here
})
```

It mirrors Better Auth's own getter exactly (the cookie-suite
drift test asserts parity against the real getter, option for
option). A mismatch fails closed — everyone bounces to
sign-in — never open. Logout expires every registered name with
its live attributes (`Secure`, `Domain`), so keep this call in
sync with `options`. Deployments using `crossSubDomainCookies`
should sign out through Better Auth's own sign-out for full
cookie clearing — the plugin still revokes server-side, so any
surviving cookie is dead.

**Production needs a canonical https `baseURL`.** Secure-cookie
names follow one rule shared by every provider: an explicit
`useSecureCookies` wins, then the configured origin (https →
secure), then `NODE_ENV=production`. The https origin is the
only input on which both SDKs and the session layer's origin
anchoring agree — without it, production falls back to
`NODE_ENV` detection.

## Sessions and revocation

Database sessions: the port reads via `auth.api.getSession` (no
hand-rolled anything) and revokes via the internal adapter's
`deleteSession`. Sign-out through `DELETE /api/auth-link/session`
revokes server-side _and_ expires cookies; direct
`/api/auth/sign-out` calls revoke provider-side only (the plugin
never sees them — prefer the plugin endpoint).

## Query semantics and sort collation

The Payload adapter answers Better Auth's queries with the same
results as Better Auth's reference `memoryAdapter` — every operator,
`null` handling, case-insensitive `eq`, numeric/date sorting, and
`limit`/`offset` pagination are pinned against it by a differential
test suite. The documented differences:

- **String sort collation belongs to your database.** `findMany`
  with `sortBy` on a text field orders by the database's collation:
  binary on SQLite and MongoDB (`A, B, a, b`), the column collation on
  Postgres. The memory adapter uses `localeCompare` (`a, A, b, B`).
  Payload exposes no portable collation option, and re-sorting in
  memory would break paginated windows, so the adapter does not
  normalise. Better Auth core never pages through string-sorted
  results; plugins or app code that do should sort on a normalised
  (e.g. lower-cased) column.
- **String range comparisons follow the same collation.** `lt`,
  `lte`, `gt`, `gte` on a text field compare in the database's
  collation too — binary on SQLite and MongoDB, the column collation
  on Postgres (where e.g. `'B' < 'a'` can be false under a
  locale-aware collation). The memory adapter compares JS strings
  (code units). Same-case ASCII strings agree everywhere; avoid
  string range filters over mixed-case or non-ASCII data, or compare
  on a normalised column.
- **`NULL` in negative filters keeps the row**, like the memory
  adapter: `ne` and `not_in` on a nullable column include rows where
  the column is `NULL` (SQL's `NOT IN` alone would drop them; the
  adapter adds the `IS NULL` branch).
- **Case-insensitive `eq` is Unicode-aware on every database.**
  SQLite's `LIKE` folds ASCII only, so the adapter narrows on the
  value's ASCII fragments and decides the match in JS
  (`toLowerCase`) — `ÄRGER` finds `ärger` on SQLite too.
- **`null` placement** in sorted results follows the database
  (first in ascending order on SQLite/MongoDB, last on Postgres).
- **Unsupported operators fail loud:** `contains`, `starts_with`,
  `ends_with`, case-insensitive `ne`/`in`/`not_in`, and a
  case-insensitive `eq` combined with `OR` throw
  `UnsupportedOperatorError` instead of returning wrong rows.

## Rate limiting (builder-owned)

Same rule as everywhere in this project: the library ships no
throttles, so abuse control is builder-owned. Better Auth paths use
Better Auth's own `rateLimit` option (passed through verbatim in
`options` — the examples enable it at a generous dev-scale ceiling);
the Auth.js authorize path and the builder signup route use the
reference throttle in `lib/rate-limit.ts` — see [Rate limiting in
the Auth.js guide](guide-authjs.md#rate-limiting-builder-owned) for
the pattern. Note Better Auth's default special rules (3
sign-ups/sign-ins per 10s per IP) apply on top of your `max`: the
examples raise those two paths via `customRules` because shared-IP
dev traffic would otherwise trip them constantly. Production
deployments tune ceilings down, resolve real client IPs, and back
them with shared storage.

## Troubleshooting

`UnsupportedSchemaError` names the offending field or model —
inspect the `ba-*` row and your plugin's schema ask.
`AdapterOperationError` wraps the storage `cause`. Both are loud by
design: fix the row, don't retry blindly.
