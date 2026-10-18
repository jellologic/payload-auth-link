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

## One role system: Payload roles

There is exactly one role authority: **the `roles` field on the
Payload user**. Provider role fields — notably Better Auth's
`admin` plugin, which adds a `role` column to its user table — are
ignored by design. Nothing in the plugin, the adapters, or the web
helpers ever reads them: `ProviderSession` carries no roles, and the
`roles` on every `Session` / `SessionUser` come only from the Payload
document. Granting someone the BA `admin` role grants them zero
Payload rights; removing their Payload `admin` role demotes them
even if the BA row still says `admin`. (BA's own admin endpoints may
consult the BA role before acting — for example to start an
impersonation — but that only gates the provider mechanic; the
resulting session still resolves to the target's Payload roles. If
you use those endpoints, keep the BA value set by hand for that
purpose; there is no sync in either direction, deliberately.)

**Where roles live.** You declare the vocabulary once in the plugin
options — `roles: ['admin', 'user']` plus a `defaultRole` that must
be one of them — validated fail-fast at config time as canonical
lowercase slugs (`parseRole` / the branded `Role` type in core). The
plugin injects a required, multi-select field with exactly those
options onto your users collection (name `roles`, remappable with
the `rolesField` option). JIT-provisioned users start with
`[defaultRole]`; after that you edit roles where you edit any
Payload data — the admin UI or the Local API. The field requires at
least one role, so an emptied array can't persist. Because the
session service reloads the Payload user fresh on every request, a
role change applies to the very next request on every provider and
session strategy — no re-login, no token refresh, no sync job.

**Who may be linked by email (the JIT-linking proof).** A verified
provider identity is attached by email only to a document PROVEN to
own that exact address: the plugin stores WHAT was proven
(`linkableEmail`, set automatically on plugin-managed and
role-manager creates, and updated by the provider-email resync) and
the `linkable` toggle. The proof holds only while the document's
email still equals `linkableEmail` — a self-service email change
invalidates it automatically (the change itself clears `linkable`,
`linkableEmail` and, on `auth.verify` hosts, Payload's `_verified`),
and the stranger's placeholder from a pre-created document never
matches. Payload's own `_verified` flag is never proof on its own:
Payload keeps it across email changes, so a verified document that
moved onto someone else's address would otherwise inherit their
identity. When a provider identity does link, Payload's local
sessions for that document are cleared — a local JWT issued before
the link dies on its next request. Email changes over REST on
documents with linked identities are role-manager-only (the
provider's own resync is unaffected), and self-service local
passwords on plugin-managed documents are stripped: one document
never holds two independently owned credentials. Documents created
outside the plugin — pre-upgrade rows, imports that skipped the
marker — are never JIT-linked until an operator resolves the
collision: after checking who created and owns the conflicting
document, renames or removes it, or grants the proof from a reviewed
list confirming the document is the address owner's own. Never from
`_verified` (which may predate an email change) and never from a
fresh verification mail alone: that proves who controls the address,
not who built the document — on a squatted document it would hand the
victim the squatter's document (see [upgrading](upgrading.md)). The migration runbook
sets both fields from provider-verified emails. Unproven documents
also cannot be created by end users: collection-level `create` on the
users collection defaults to role-manager-only, and collection-level
`read` defaults to self + role managers (no user enumeration), unless
the host declared those access functions itself. When the document
holds a local password too, every link logs a warning.

**Who may edit roles.** The injected `roles` field (and the
governance fields: `phone`, `suspendedUntil`, `suspendReason`) are
writable only by the **role-manager roles** — `roleManagerRoles`,
defaulting to `['admin']` and required at config time when no
`admin` role exists. Everyone else is denied at field level, so a
verified self-registered user can never grant themselves a role
(Payload's field-access default would otherwise allow any
authenticated user to write any field of any document). Users may
still read their own roles. `identities` is engine-managed: writes
are denied for every REST/admin caller, and reads are limited to
role managers. Payload's Local API with `overrideAccess` (which the
plugin's own engine paths use) is never restricted — this gates
REST and the admin panel only. The default admin-panel grant is the
role-manager roles too, not "any signed-in user"; declare your own
`access.admin` on the users collection to change it.

**How roles are consumed**, in enforcement order:

1. **Payload access control.** The `auth-link` strategy projects the
   session onto `req.user`, so your collection and field access
   functions read `req.user.roles` like any Payload-authenticated
   request. Plugin-owned authorization lives in
   `plugin/src/access.ts` (CSRF checks and the impersonation deny
   layer — the roles field denies create/update while an operator is
   impersonating and, on top of the role-manager rule, so an
   impersonated session can never become a role-escalation path).
2. **Server authorization** — `requireRoles` in
   `@payload-auth-link/web` (re-exported by the Next and Start
   adapters) verifies the live session and requires _every_ listed
   role, failing closed with `ForbiddenError`; see
   [Server authorization vs UI hiding](#server-authorization-vs-ui-hiding)
   below. `RequireRoles` / `useHasRoles` on the client are the same
   Payload roles, for hiding only.

**How capability policies layer on this** ([capabilities
guide](guide-capabilities.md)) — still by narrowing or scoping
Payload roles, never by importing a provider's:
`policies.requireMfaForRoles` treats a session without MFA
assurance as missing the listed Payload roles (projected out of the
session user, unknown assurance failing closed), and Payload-owned
organizations (decision D1) carry a role _per membership_, checked
by `requireOrgRole` alongside the global roles above. Provider-side
role stores (BA `admin.role`, organization-member roles) stay
storage-compatible data, never Payload authorization.

To make someone an admin: set `roles` on their Payload user. That
is the only step, on either provider.

## Session flow (read-time, no webhooks)

There are no webhooks and no background sync. Every read is live:

1. Request carries provider cookies.
2. The session service asks each registered provider in turn
   (`getSession`). Provider failures are logged and skipped — one
   provider down never breaks the others.
3. The first live session wins — precedence is the order of the
   `providers` array, so a browser signed in through two providers
   resolves to the first registered one. Expiry is checked against
   the injected clock with **no skew leeway**: a session expires
   exactly at `expiresAt`. Keep the plugin host and the provider's
   session store on synchronized clocks (NTP) — a hard requirement,
   since a leeway would accept sessions the provider already
   considers expired. A provider reporting an empty session id is a
   port-contract violation and resolves to 401, never a 500.
4. The linked Payload user is resolved (or JIT-provisioned), then
   reloaded fresh — role changes apply to the very next request.
5. The endpoint/strategy returns `{ user: { id, collection, email,
roles } }` (`SessionUser` — the versioned wire contract in
   `core/src/http.ts`).

The Payload strategy is read-only: it never refreshes provider state,
so login loops are impossible by construction. Failures at any step
resolve to anonymous (`{ user: null }` / 401), loudly logged (the default console logger; pass `nullLogger()` to mute).

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
