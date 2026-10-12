# Concepts

The mental model behind the packages. Read [Mission](MISSION.md) for
_why_; this is _how it fits together_.

## Hexagon: core ports, swappable adapters

`@payload-auth-link/core` owns the domain and the ports; everything
else is an adapter:

- **`IdentityProviderPort`** — the seam. `getSession(headers)` narrows
  whatever a provider knows into a `ProviderSession`
  (`sessionId`, `providerUserId`, `email`, `emailVerified`,
  `expiresAt`); `revokeSession(id)` undoes it. Better Auth and Auth.js
  each implement it; WorkOS/Clerk will later. The port never exposes
  provider SDKs to the plugin.
- **`ProviderRegistry`** — id → port map, explicit at the composition
  root. No discovery, no magic: `providers: [betterAuthProvider]`
  in the plugin options _is_ the registry contents.
- **`UserRepository`** — Payload users behind CRUD + identity-link
  lookup. The plugin implements it over the Local API.
- **`SessionPort`** — the bridge: ask each provider for a session,
  JIT-provision the Payload user, return a provider-agnostic
  `Session`. Implemented once in the plugin; providers never touch it.
- **Leaf ports** (`LoggerPort`, `ClockPort`, `IdPort`, `TracerPort`,
  `CookiePort`, `TransactionPort`) — injected everywhere time,
  randomness, logs, or cookies are needed, so tests control them.

```
providers ──IdentityProviderPort──▶ registry ──▶ SessionPort ◀── UserRepository
(Better Auth, Auth.js)                                  │              (Payload)
                                                        ▼
                                              strategy + endpoints
                                    (Payload + web + Next/Start + React)
```

## Users are Payload documents

There is exactly one user store: your Payload `users` collection.
The plugin extends it with `roles` and `identities` (slugs
configurable) and registers the `auth-link` strategy. Provider data
(hashes, tokens, OAuth accounts) lives in the provider's own
deny-all system collections (`ba-*`, `aj-*`) — never in `users`.

**Just-in-time linking.** Nothing provisions a Payload user at
provider signup. At the first session verification for an unknown
provider identity, the session service creates the user (default
role) and links the identity — idempotently, so no signup ordering
or race can strand a provider user without its document.

**Verification gating.** Linking requires a verified email. Better
Auth enforces it via `requireEmailVerification` (defaulted on by the
engine); Auth.js credentials carry a builder-stamped `emailVerified`
through a JWT claim. An unverified identity resolves to 401 at the
session endpoint — a provider session is not yet a Payload session.

## Session flow (read-time, no webhooks)

There are no webhooks and no background sync. Every read is live:

1. Request carries provider cookies.
2. The session service asks each registered provider in turn
   (`getSession`). Provider failures are logged and skipped — one
   provider down never breaks the others.
3. The first live session wins — precedence is the order of the
   `providers` array, so a browser signed in through two providers
   resolves to the first registered one. Expiry is checked against
   the injected clock.
4. The linked Payload user is resolved (or JIT-provisioned), then
   reloaded fresh — role changes apply to the very next request.
5. The endpoint/strategy returns `{ user: { id, collection, email,
roles } }` (`SessionUser` — the versioned wire contract in
   `core/src/http.ts`).

The Payload strategy is read-only: it never refreshes provider state,
so login loops are impossible by construction. Failures at any step
resolve to anonymous (`{ user: null }` / 401), loudly logged.

## Two-layer validation (both frameworks)

- **Optimistic bounce** (`createAuthMiddleware` on Next.js,
  `createAuthRequestMiddleware` on TanStack Start) — cookie
  _presence_ check. Bounces obvious anonymous traffic to sign-in
  early. Cannot reach the database, so it never authorizes.
- **Node validation** (`createSessionVerifier` in
  `@payload-auth-link/web`, strategy, endpoints) — full
  verification against live provider + Payload state. This is the
  only authorization that counts. Both framework packages re-export
  it, so one import covers either.

Next hydrates via `AuthLinkServerProvider` (per-request Node
validation into the React context); Start hydrates via a root
`loader` (`createSessionLoader`) into `AuthLinkProvider
initialUser`. Either way the client never fetches on mount unless
unhydrated.

## Server authorization vs UI hiding

- **Enforcement** (`requireSessionUser`, `requireRoles` in
  `@payload-auth-link/web`, re-exported by the Next and Start
  adapters) runs on Node _before_ protected content renders or a
  protected mutation executes. Anonymous callers bounce (default:
  throw `SessionInvalidError`), role-missing callers are denied
  (default: throw `ForbiddenError`) — pass your framework's
  `redirect()` / `notFound()` as the handlers (thrown, not
  returned), or catch in route handlers and map to 401 / 403.
- **Hiding** (`RequireRoles`, `useHasRoles` in
  `@payload-auth-link/react`) only controls what renders in the
  browser. It must never gate content: server-rendered children ship
  in the RSC payload regardless. Use it for menus and buttons, never
  for secrets.

## Logout semantics

`DELETE /api/auth-link/session` (CSRF-guarded):

1. Verifies the session to learn which provider owns it.
2. Calls that provider's `revokeSession` (deletes database sessions;
   a documented no-op for stateless JWT sessions), then best-effort
   revokes every _other_ provider session the request presents —
   verification stops at the first match, so a second sign-in would
   otherwise outlive logout. Sweep failures are logged, never fatal;
   the 401 path sweeps too (a provider session can be live behind a
   failed verify).
3. Expires **all registered providers' session cookies** (`Max-Age=0`),
   even on the idempotent 401 path — logout never leaves a live
   cookie behind, whichever provider issued it. The clearing write
   carries each cookie's live attributes (`Secure`, `Domain`, `Path`)
   reported by the provider, so `__Secure-` and custom-domain cookies
   actually die; providers that predate that hook fall back to
   prefix-derived attributes.

## Errors

Expected failures travel as `Result<T, E>` values with coded errors
(`SESSION_INVALID`, `USER_EXISTS`, `PROVIDER_ERROR`, …); only
programmer errors (bad config, corrupt storage rows) throw. Web
adapters map codes to status codes; core never touches HTTP. Loud
failures over silent fallbacks, always — a corrupt Auth.js row
throws `AdapterMappingError` (Better Auth's schema fail-fast is
`UnsupportedSchemaError`); it never becomes a quiet login failure.
