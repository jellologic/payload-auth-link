# Upgrading

Versioning rides [changesets](https://github.com/changesets/changesets):
every user-facing change ships a changeset, the release workflow
opens Version Packages PRs, and each package CHANGELOG records what
moved. This page covers the moves that need human attention —
especially database moves, where an unattended upgrade has historically
meant an unbootable app (see the per-adapter steps under each version
heading before you bump).

## Pre-1.0 policy

Minor versions may break: the wire contract (`SessionUser`, endpoint
paths, cookie semantics) is the stability anchor and changes only
with a migration note here; option shapes and internal ports may
evolve. Read the package CHANGELOGs on every bump.

The post-1.0 contract (what is public, semver per surface,
deprecation and security-fix policy) is in
[stability.md](stability.md); it takes effect at 1.0.

## Supported bands and the version assertion

The validated bands live in [compatibility.md](compatibility.md) and
equal the CI compat matrix ({floor, latest} per upstream). At wiring
time every package asserts the upstream versions it drives:

- the plugin checks `payload` (`supportedPayloadBand`),
- `provider-better-auth` checks `better-auth` (`supportedBetterAuthBand`),
- `provider-authjs` checks `@auth/core` (`supportedAuthJsBand`).

An out-of-band version throws `UnsupportedVersionError` (found vs
supported + a pointer here) **before any collection write** — an
unsupported upstream fails at startup with a typed, actionable error,
never as a raw SQL error or a missing-adapter `TypeError`
mid-request. When it fires: pin the upstream back inside the band
and wait for (or cut) a compat patch that widens the band after the
matrix proves the new version. Prerelease builds only ever match via
an explicit `exact` entry — canaries never float in through a range.

## plugin 0.11.x patches (after the hardening release)

**Upgrade impact:** no schema change; nothing to run on any adapter.

- `req.user.id` for provider sessions now has the database's own id type
  (a number on SQLite/Postgres). Code comparing it with `===` against a
  string id should compare `String(id)`; Payload's own relationship
  writes (v4's `createdBy`/`updatedBy`) now accept it.
- The users collection gains a `me` hook: for auth-link sessions
  presented as `Authorization: Bearer` (`admitChannels` with
  `'bearer'`), `GET /api/users/me` answers with the verified session's
  `exp` and never returns the provider token as `token` (it used to
  500). Cookie sessions and other strategies are unchanged.
- `authLinkServer(payload).revokeSession` with an Auth.js database
  session engine now throws for a handle that matches no session.

## plugin 0.11.0 / provider-better-auth 0.8.0 / web 0.3.0 / migrate 0.5.0 (hardening release)

One minor release across every package (core 0.7.0, next 0.4.0,
react 0.3.0, tanstack-start 0.3.0, provider-authjs 0.4.0 too). No
schema change. Read each section before you bump.

### Users-collection write defaults

**Upgrade impact:** no schema change; access defaults only.

1. **Users `update` and `delete` are no longer open to every signed-in
   user.** When your users collection declares no `access.update`, the
   plugin now allows a user to update only their own document (role
   managers: every document); with no `access.delete`, only role
   managers delete users. Neither is allowed while impersonating.
   Payload's own default (`Boolean(req.user)`) let any signed-in user
   (with JIT sign-up, anyone) rewrite or delete any user, including
   re-pointing a local admin's email and resetting its password. If
   you relied on the open default, declare the access you want
   explicitly.
2. **A non-manager only ever changes their own email**, even when your
   collection-level `update` is broader.
3. **`unlock` is role managers only** by default (it was any signed-in
   user).
4. **`migrate export --out` and the import manifest are written
   owner-only (0600)**, tightened before content lands. Manifest
   values are bound to their entry, and rollback restores only the
   fields the kit writes (`identities`, `roles`, `linkable`,
   `linkableEmail`, `updatedAt`).
5. **`sessionEndpoint` values with whitespace or control characters
   throw** `InvalidConfigError` (URL parsing would strip them and could
   resolve the path protocol-relative).

### Organization governance; `_verified` is not linking proof

**Upgrade impact:** no schema change. No column is added, removed,
or retyped (the users snapshot is unchanged; the memberships
collection only gains field access and hooks), so push and
migrations both have nothing to do on SQLite, Postgres, and MongoDB.
The changes are behavioural; read each before you bump.

1. **Payload's `_verified` no longer admits a document to JIT email
   linking on its own.** Only the plugin's `linkable` proof bound to
   the current address (`linkableEmail`) does — what
   [security-model.md](security-model.md) row 8 always documented.
   Payload keeps `_verified` across email changes (and its default
   field access lets any signed-in user write it), so a verified
   document re-pointed at someone else's address used to inherit
   their provider identity. **Operator step:** if you relied on
   `_verified` alone for pre-existing host accounts, grant the proof
   to the ones you trust. Audit first: before this release a
   self-service email change kept `_verified`, so only grant it where
   the address was verified AFTER its last change.

   ```ts
   const { docs } = await payload.find({
     collection: 'users',
     where: { and: [{ _verified: { equals: true } }, { linkable: { not_equals: true } }] },
     pagination: false,
     overrideAccess: true,
   })
   for (const doc of docs /* filtered by your audit */) {
     await payload.update({
       collection: 'users',
       id: doc.id,
       data: { linkable: true, linkableEmail: doc.email },
       overrideAccess: true,
     })
   }
   ```

   The migration importer (`@payload-auth-link/migrate`) already
   grants `linkable` + `linkableEmail` from verified emails and is
   unaffected. A refused link whose provisioning then collides with
   the existing document now logs
   `provisioning refused: the email is held by an existing document
that is not proven to own it` and answers a typed 401 (it used to
   surface as a storage error).

2. **A self-service email change resets the proof.** Changing a
   document's email in any write that is neither the plugin's
   provider-email resync nor a role manager's clears `linkable` and
   `linkableEmail`, and — on `auth.verify` hosts — `_verified`. Users
   who change their own email on a verify host must re-verify before
   local sign-in works again (Payload does not resend the
   verification mail by itself; trigger it from your app).

3. **Linking revokes earlier local sessions.** When a provider
   identity links to a document, Payload's `sessions` array for it is
   cleared (`auth.useSessions`, Payload's default), so a local JWT
   issued before the link is refused on its next request. Hosts with
   `useSessions: false` get the same outcome from the account-control
   gate, which now refuses `local-jwt` requests on provider-linked
   documents (401) unless `allowLocalCredentialsForLinkedDocs` is set.

4. **Organization governance.** With `organizations.enabled`:
   memberships can no longer change `organization` or `user` after
   create (REST writes to them are dropped; Local-API writes throw);
   role writes never exceed the caller's own org role (an `admin`
   cannot create, promote to, or edit an owner); the last active
   owner of an organization cannot be demoted or removed (`409`);
   `DELETE /api/organizations/:id` cascades the organization's
   memberships and invitations instead of failing; and every
   organization write, membership write, invite, and acceptance is
   refused (`403`) and audited while impersonating. Seed scripts that
   re-pointed memberships through the Local API must delete and
   re-create the row instead.

5. **Organization write scoping.** Also with `organizations.enabled`:
   - Bulk `PATCH`/`DELETE /api/organizations?where=…` only reaches
     organizations the caller manages (owns, for delete). A request
     body field no longer decides which organization authorizes the
     write.
   - Deleting an organization is owner-only. An org `admin` now gets
     `403`.
   - `verifiedDomains` can be written only by Payload role managers
     (`roleManagerRoles`), and not while impersonating. Org owners and
     admins who set domains through REST or the admin panel will see
     the field ignored. Review existing `verifiedDomains` entries once
     after upgrading, because before this release any organization
     creator could list any domain.
   - Removing or demoting an owner now writes the organization row
     first (it bumps `updatedAt`). This serializes concurrent owner
     removals.
   - Accepting an invitation after already joining the organization
     answers `409` instead of a storage validation error.

### Session verifier, logout, and redirect hardening

No schema change. Behavior changes that may need attention:

1. **`createSessionVerifier` requires `baseUrl` unless
   `NODE_ENV === 'development'`.** It used to fall back to the
   request's host headers on every runtime that was not `production`
   (test, staging, preview, unset). Those now throw
   `InvalidConfigError` at construction — pass `baseUrl` (or an
   absolute `sessionEndpoint`). In development the fallback ignores
   `X-Forwarded-Host`/`-Proto` unless you set `trustProxy: true`,
   only accepts `localhost`, `127.0.0.1`, and `[::1]` (extend with
   `allowedDevelopmentHosts`), and protocol-relative `sessionEndpoint`
   values throw. The verifier's fetch now times out after
   `timeoutMs` (default 5000) and no longer follows redirects; both
   fail closed. `resolveSessionUrl`'s host fallback now defaults to
   off, and `resolveOrigin` (core) honors forwarded headers only with
   `trustProxy`.
2. **`safeRedirectPath` returns the normalised path.** Dot segments
   resolve before the API-prefix and sign-in checks, so
   `/x/../api/...` and `/./sign-in` fall back, and a benign
   `/x/../account` comes back as `/account`.
3. **Logout expires more cookies.** `DELETE /api/auth-link/session`
   also expires Better Auth's `dont_remember` and cookie-cache
   `session_data` cookies, the `__Secure-`/plain counterpart of every
   name, and the configured `legacySessions` names. A logout that
   presents no session cookie (and no `Authorization`/`x-api-key`
   header) answers without querying any provider — still the
   idempotent `401` with the clearing cookies.
4. **Provider login view paths follow your config.** The break-glass
   form posts to `${routes.api}/${usersCollection}/login` and lands on
   `routes.admin`; set `admin.signInPath`/`admin.authBase` when your
   sign-in page or Better Auth mount differs from `/sign-in` and
   `/api/auth`. The import map needs no regeneration (same
   component, new props).
5. **React provider sequencing.** Only the newest session read writes
   state; `signOut` aborts in-flight reads. `fetchSession` accepts an
   optional `AbortSignal`.

## 0.10.x → 0.11.0 (recorded sign-in methods; opaque session handles)

Two changes to the server-session surface, both driven by the
post-release review (issues #79 and #80).

1. **Better Auth's own sign-in flows record their authentication
   method.** 0.10.1's assurance read the per-session
   `authenticationMethod` column, but only server-side mints wrote it —
   a user completing Better Auth's NATIVE two-factor sign-in got
   `mfa: 'unknown'` and `requireMfaForRoles` withheld their role. The
   provenance plugin now stamps the method on every sign-in flow it
   recognizes (`password`, `two-factor` on the verification endpoints,
   `oauth` callbacks, `magic-link`, `email-otp`, `passkey`); unknown
   paths still record nothing (fail closed). Apps on 0.10.1/0.7.1
   needing MFA roles through a custom step-up route can drop it after
   upgrading — the native flow now works. BA's 2FA-pending sign-in
   expires the session cookie, so a single-factor session is never
   relabelled: the second factor issues a FRESH session, recorded as
   `two-factor`.

2. **Session ids are opaque handles, never bearer tokens.**
   `listSessions` and `createSessionFor().sessionId` used to return
   the raw session token — a "sign out other sessions" page would have
   put a live credential for every session into page data. They now
   return the session ROW id; `revokeSession` resolves the id to the
   token server-side (BA's own logout internals, which revoke by
   token, are unaffected). `createSessionFor().token` is unchanged —
   the token still rides exactly where setting the cookie needs it.
   **`sessionCookie(token)` still takes the TOKEN** (the mint
   response's `token` field), not the id.

## 0.10.x → 0.10.1 (server-session API hardening; advisory GHSA-hxgq-9pww-59j4)

Four fixes to the server session API, all fail-closed.

1. **Minted sessions no longer claim MFA.** Session assurance now
   reads a per-session record of HOW the session came into being —
   the engine appends an internal plugin that adds one nullable
   `authenticationMethod` column to the session table (additive; rows
   that predate it read as "no recorded method"). A server-side mint
   records `server-mint` and reports `mfa: false` — it ran no 2FA
   challenge. The old read leaned on `user.twoFactorEnabled`
   (ENROLLMENT), so every mint for an enrolled user claimed a second
   factor that never ran. **`requireMfaForRoles` sites**: sign-in
   sessions now report `mfa: 'unknown'` until a flow records a
   method — the gate treats `'unknown'` as absent (fail-closed), so
   gated roles stay withheld for plain cookie sign-ins. To restore
   them, mint with the new `createSessionFor(userId, { mfaProof:
true })` — set it ONLY when the server has itself verified a
   second factor; the session then records `server-step-up` and
   reports `mfa: true`. **Schema note:** the engine adds the session
   column through Better Auth's own schema machinery; run your usual
   Payload push/migrations on upgrade (additive column, no data
   changes).
2. **One id type across mint/list/revoke — the session token.**
   `listSessions` and `createSessionFor` used to hand out session ROW
   ids while revocation deleted by TOKEN, so revoking a listed id
   deleted nothing and reported success. Both now return tokens (the
   id `createSessionFor` returns revokes directly), and revocation is
   verified in both directions: revoking an id with no session behind
   it is an ERROR (nothing was deleted), and a delete that leaves the
   row in place is an error too.
3. **The requested TTL is honored and the STORED expiry is audited.**
   The mint passed its expiry into Better Auth's `dontRememberMe`
   parameter slot (a truthy Date), so every minted session got the
   engine's default expiry (~24h) no matter what was requested — and
   the audit event recorded the requested value as if stored. The mint
   now passes the expiry through Better Auth's `override` (applied
   with `overrideAll`), and the audit event and returned `expiresAt`
   carry the expiry the provider actually stored.
4. **`'dev-only'` means development.** The `allowServerSessions`
   default enabled minting on every runtime that merely wasn't
   `production` — CI, test, staging, unset. It now enables minting
   ONLY when `NODE_ENV === 'development'`; every other runtime
   refuses with `ServerSessionsDisabledError`. Set `allowServerSessions:
true` explicitly where minting is intended outside development.

## 0.9.x → 0.10.0 (the server-session kit's correctness pass)

Fixes from the first production rehearsal (issues #68–#72). Three of
them change behaviour that previously "worked" by silently doing
nothing.

1. **`sessionCookie` is signed — and async.** Better Auth reads the
   session token cookie with `getSignedCookie` ONLY, so the
   server-session API's cookie must be `token.<HMAC signature>`.
   0.9.0 minted the raw token, which Better Auth refused (every
   bridge built on `createSessionFor().setCookie` or
   `authLinkServer.sessionCookie()` logged nobody in). The cookie is
   now built from the engine's own resolved context (secret, name,
   `Secure`/`SameSite`/`Path`/`Max-Age` attributes). **Type change:**
   `sessionCookie(token)` returns `Promise<string>` on
   `authLinkServer` and on the provider port — `await` it. A
   real-engine round trip (mint → setCookie → `getSession` resolves
   the user) pins the behaviour.

2. **`legacySessions` on the plugin now enforces agreement.** The
   plugin option never enabled anything — the provider ENGINE's
   `legacySessions` input is what honors legacy cookies. Wiring now
   throws `InvalidConfigError` when the plugin option is set but no
   engine declares a window, when the two disagree on `until` or
   `cookieNames`, or when a legacy cookie name collides with a
   current session cookie name. Engine-only configuration stays
   legal. If you set only the plugin option believing it bounded the
   window, move the window to `createBetterAuthEngine({
legacySessions })` (and keep the plugin option identical, if you
   want the assertion).

3. **`revokeAllForUser` revokes on every linked provider.** It used
   to walk only the first capable identity; a user linked to two
   providers kept the second provider's sessions. It now attempts
   every linked provider and throws if any fails.

4. **The provider login view actually renders.** The `loginView:
'provider'` registration was missing its `exportName`, so
   Payload's import map never resolved it (empty login page), and its
   provider link pointed at `/api/auth/sign-in`, which is not a
   Better Auth route. The view now registers as
   `@payload-auth-link/plugin/admin#ProviderLoginView` and signs in
   through Better Auth's own `POST /sign-in/email`; the break-glass
   local form is unchanged. **Apps enabling `admin: { loginView:
'provider' }` must regenerate the import map** (`payload
generate:importmap`) after upgrading — a stale map still renders
   an empty page.

5. **Stray debug output removed.** The server session API printed
   `DBG …` lines to stdout on every identity resolution; gone.

## 0.6.x → 0.7.0 (account controls on every strategy; provider-owned documents)

Three default-behaviour changes, all fail-closed. The full
credential-path matrix now lives in
[security-model.md](security-model.md).

1. **Suspension is enforced on every strategy, at request time.**
   Previously only the `auth-link` strategy checked `suspendedUntil`;
   a user with a local password (Payload's own `login` / local JWT /
   API key) kept working after being suspended. Now `beforeLogin`
   refuses the local sign-in (401), and a request-time gate on every
   collection and global refuses any request carrying a suspended
   account's local JWT or API key (401) — including `refresh-token`,
   and including GraphQL. Nothing to migrate; sites that suspended
   users get the behaviour the field always promised.

2. **`policies.requireMfaForRoles` now applies to local credentials.**
   Local sessions have no MFA proof, so a role listed in the policy is
   withheld from local-strategy sessions (JWT, API key) at request
   time — before access checks read the roles. Local login itself is
   NOT blocked; the session simply loses the gated role. The
   `/access` permission map is truthful for the users collection;
   host collections' maps can still overstate (their access functions
   are the host's) but no operation honors it.

3. **Provider-linked documents are provider-owned** (new default, new
   option `allowLocalCredentialsForLinkedDocs`, default `false`):
   once a document holds linked provider identities, local sign-in is
   refused (403) and the forgot/reset-password flow is refused (403,
   no token is issued) for it. A local password on such a document
   would bypass the provider's MFA, bans, rate limits, and
   revocation. Documents WITHOUT linked identities — operator
   accounts, imports not yet linked — keep local credentials and the
   recovery flow exactly as before. This affects the
   payload-auth migration runbook: an imported user's password works
   until their provider identity links; after that the provider owns
   the credential. Sites needing both credentials alive during a
   migration window set `allowLocalCredentialsForLinkedDocs: true`
   and remove it when the migration completes.

No schema changes; no backfill. The credential-path matrix test
(`integration-credential-paths.test.ts`) pins all three.

## 0.1.1 → 0.2.0

What changed in the database (and nothing else did — provider
collection shapes otherwise moved zero columns):

- **`users`** gains three optional governance fields: `phone`
  (text), `suspendedUntil` (date), `suspendReason` (text). All
  nullable and additive — safe on every adapter, every mode.
- **`aj-verification-tokens`** (Auth.js provider): `token` loses its
  standalone unique index; a new nullable unique `key` column
  identifies a token by its `(identifier, token-hash)` pair. This is
  the composite-key fix: the same OTP hash may now exist for two
  different identifiers. The `key` column is **nullable** — pre-fix
  releases shipped it `required`, which is what made upgraded
  databases unbootable (see below); 0.2.1+ accepts `NULL` keys and
  backfills lazily on write.
- **`ba-*` collections** (Better Auth provider): no shape change.

Verification tokens are **not** invalidated: existing rows keep
working (the adapter reads by `(identifier, token)` and tolerates
`NULL` keys). No data loss on any adapter.

**SQLite, dev-push (Payload `push: true`):** just boot the new
version. Adding a nullable column alters the table in place — no
data-loss prompt, no table rebuild. (0.2.0 exactly shipped `key` as
required; booting it hangs on drizzle's data-loss prompt and can
recreate the token table empty. Upgrade straight to 0.2.1+.)

**Postgres, dev-push:** same — the column adds in place and the
unique index swaps `token` → `key`. (0.2.0 exactly hung on the same
prompt; Postgres converged if you accepted, but the token table
emptied.)

**Production (migrations mode):** generate the migration yourself
(`payload.migrate:create`) and check it adds `key` as a **nullable**
column and drops the `token` unique index — `ADD COLUMN key TEXT`
without `NOT NULL`. On a non-empty table, a NOT NULL variant fails
outright (`column "key" contains null values`); a nullable one is a
no-loss step. See the [migrations recipe](#running-production-on-migrations-not-push).

**MongoDB:** schema drift cannot crash Mongo, but index lifecycle is
the trap: Payload's adapter never drops indexes, so the **stale
`token` unique index survives the upgrade** (silently keeping the
pre-0.2.0 "one row per token hash" constraint), and the added `key`
unique index builds in the background over rows without the field.
Fix with the idempotent reconciliation helper:

```ts
import { reconcileAuthJsMongoIndexes } from '@payload-auth-link/provider-authjs'

const report = await reconcileAuthJsMongoIndexes(payload)
// { status: 'reconciled', droppedStaleTokenIndex, backfilledKeys, keyIndex }
```

It backfills `key` (`JSON.stringify([identifier, tokenHash])`),
drops the stale `token` unique index, and reports (rather than
throws) when the `key` index build is still in flight. Run it once
per deployment after upgrading (idempotent; safe to re-run).
Already upgraded without it? The composite-key behavior silently
does not hold on your deployment until you run the reconciliation.

## 0.4.0 → 0.5.0 users, continued in 0.5.x → 0.6.0 (proof bound to the email)

Follow-up to the JIT-linking proof above: the `linkable` marker is now
bound to the email it was granted for (new `linkableEmail` field). The
proof holds only while the document email equals `linkableEmail`:

- Self-service email changes over REST on documents with linked
  identities are role-manager-only (stripped for non-managers), and
  self-service local passwords on plugin-managed documents are
  stripped — one document can no longer hold two independently owned
  credentials, and a local credential can no longer bypass Better
  Auth's MFA/bans/verification.
- The plugin's provider-email resync keeps the proof in step
  (repository `setEmail` moves both the email and the proof, with
  `overrideAccess`).
- Linking to a document that also holds a local password now warns
  (the hidden-field lookup that previously never fired is fixed).

**Backfill for existing `linkable: true` documents** (created by
0.5.0/0.5.1 without `linkableEmail`): set `linkableEmail = email` ONLY
where the email still matches the linked identity's email; treat
anything else as unproven (the admin users list shows which rows lack
the marker). Role managers can do it per user over REST; bulk
migrations via the Local API (see the migration runbook).

## 0.3.x → 0.5.0 (JIT-linking proof + users create/read defaults)

Two more fail-closed defaults on the users collection (see the
published advisory for the attack they close):

- **JIT linking requires proof of email ownership.** A verified
  provider identity is attached by email only to documents carrying
  the plugin's `linkable` marker (set automatically on
  plugin-managed and role-manager creates; role managers can toggle
  it) or Payload's own verified flag. Documents created outside the
  plugin start unproven: their returning users are refused (401, with
  a logged reason) until a role manager marks them linkable or the
  document is deleted. **Runbook note:** the payload-auth migration
  script marks imported users `linkable: true`.
- **Collection-level `create` defaults to role-manager-only** and
  **`read` to self + role managers** (no user enumeration) — both
  only where the host hasn't declared that access function itself.
  Hosts whose end users self-register through Payload REST/local
  forms (rather than through a provider) must declare
  `access: { create: ... }` or route registration through the
  provider.

Upgrade impact: default-behaviour change — non-managers can no
longer create users over REST or list other users; unproven
pre-existing documents are refused at JIT linking until marked.
Negative e2e specs cover the refusal, the proven/imported path, the
create block, and self-only listing on all six adapter/example
combos.

## 0.3.x → 0.4.0 (security default change)

The injected users-collection fields now fail closed
(security hardening). Previously, Payload's own defaults made every
authenticated user able to write every field of every user document —
including `roles`. The new default policy:

- **Writes** to `roles`, `phone`, `suspendedUntil`, `suspendReason`
  require the **role-manager roles** — the new `roleManagerRoles`
  option, defaulting to `['admin']`. If your configured `roles` have
  no `admin`, the plugin refuses to boot without an explicit
  `roleManagerRoles: [...]`. Editors holding a non-admin role must be
  named there or they lose the ability to edit roles in the admin
  panel.
- **Reads** of `suspendReason`, `suspendedUntil` and `identities` are
  role-manager only; `identities` writes are denied to REST and the
  admin panel entirely (the engine manages linking through the Local
  API, which is unaffected).
- The **admin panel** is no longer granted to "any signed-in user":
  the default grant is the role-manager roles. Declare
  `access: { admin: ... }` on your users collection to restore a
  wider policy — the plugin wraps your function with the
  impersonation deny and otherwise leaves it alone.
- Local-API writes (`overrideAccess`) — the plugin's engine paths and
  your own scripts — are never restricted by any of this.

If you depended on users editing their own profile fields, declare
those fields' access explicitly; the plugin never guesses a policy
for fields it did not inject. The negative behaviour is pinned by
`e2e/access.spec.ts` (non-admin escalation, admin-panel entry, field
stripping, manager writes) across all six adapter/example combos.

## 0.3.x → 0.4.0 (organization membership uniqueness)

The memberships collection gains a **compound unique index on
(user, organization)** (issue #21): two concurrent invite-accepts or
owner-bootstraps could previously both pass the check-then-insert and
land duplicate rows.

Upgrade impact:

- **Push mode (dev):** the new index is added on boot. Existing
  duplicate rows make the index build fail — dedupe first (keep the
  oldest row per `(user, organization)`), then boot.
- **Migrations mode:** generate the migration as usual; it must
  create the unique index AFTER your dedupe step. Creating a unique
  index over duplicates fails on SQLite and Postgres alike.
- Fresh installs are unaffected; the sequential duplicate checks
  remain (the index is the concurrency backstop, not the only guard).

Also in this line: `setEmail` now rewrites linked-identity rows that
carried the old address, so the admin view no longer shows a stale
identity email; `@payload-auth-link/next` exports
`checkAuthCookies(request, options)` — a composable form of the
optimistic middleware for apps that run their own `proxy.ts`
pipeline.

## 0.3.x → 0.4.0 (adopting existing roles fields; migration guide)

The plugin now **adopts** a compatible existing `roles` field on the
users collection instead of throwing: a Payload `select` with
`hasMany: true` whose options cover every configured role is taken
over — required-ness, the default, and the plugin's governed write
access are imposed; host options and labels survive. Incompatible
shapes fail at config time with the exact remediation, and
`rolesField: 'role'` remapping now works against an existing `role`
column. Coming from `payload-auth`? There is a runbook:
[migrating-from-payload-auth.md](migrating-from-payload-auth.md) — the
data move, the roles adoption, the `req.user` projection (it is the
session projection, not the full document), session/cookie policy,
and a script sketch.

Upgrade impact: config-time behavior — previously-throwing setups
with a compatible roles select now boot and adopt it; the adopted
field gains the role-manager write restriction (roleManagerRoles).

## 0.3.x → 0.4.0 (audible by default)

`authLink` now defaults to a **console logger** instead of a silent
one: session refusals (expired sessions, channels not admitted,
suspensions, provider errors, a session-shaped cookie that resolves
to nothing) and the impersonation audit print without
configuration. Consequences and opt-outs:

- To restore the old silence, pass `logger: nullLogger()` explicitly.
- Per-request "invalid session" residue (every logged-out page load
  hitting the session endpoint) logs at debug level, not warn —
  actionable refusals keep their warning, with reason, provider and
  channel.
- New `onAudit` option: a durable sink for impersonation audit
  events (called in addition to the logger). With an
  impersonation-capable provider, a silent logger and no `onAudit`,
  the plugin warns once at startup that audit events are dropped.

## 0.2.x → 0.3.0

Install-level changes — read before bumping:

- **`better-auth` and `@auth/core` moved from dependencies to
  peers.** The providers no longer install them for you. If you
  already import them (you almost certainly do — you configure the
  BA server or the Auth.js providers), add them explicitly:

  ```sh
  # Better Auth tree
  bun add better-auth@1.7          # validated band: >=1.7.6 <1.8.0
  # Auth.js tree
  bun add @auth/core@0.41          # validated band: >=0.41.0 <0.42.0
  ```

  Missing peers fail at install time with a clear "unmet peer" (npm)
  or auto-install-warn (bun) — not with a runtime module-not-found
  three frames deep. The narrow bands are the point: a fresh install
  can no longer resolve an upstream minor nobody validated. Widening
  is a compat patch away once the matrix proves the new version.

- **`payload` peers tightened to `^3.83.0 || 4.0.0-beta.0`.** 3.83.0
  is the bisected floor for the named-plugin and global-hook APIs the
  plugin uses; the v4 pin is the exact tested beta (no caret — v4
  canaries were silently inside the old range and broken).
- **Framework peers got honest floors:** `next` is now
  `^15.0.0 || ^16.0.0` (16 e2e-tested by the examples), and
  TanStack Start is `^1.140.2` (the first version with the
  `createMiddleware` types the adapter uses) with
  `@tanstack/react-router` `^1.170.0`.
- **Runtime version assertions** are live (see above). On a peer
  outside the band you get `UnsupportedVersionError` at boot —
  actionable, before any write.
- **Role-config safety:** removing a role from
  `authLink({ roles })` now stops granting it on the next session
  (stored values are filtered at read time), and the first boot
  after the change logs one aggregate warning naming the drifted
  values and affected user count. See the
  [role runbook](#changing-or-removing-roles) before trimming roles.

No database shape changes in this line: the collection snapshots are
byte-identical to 0.2.x (enforced by `bun run schema:check` from
here on — a PR that changes a shape must carry an `Upgrade impact:`
changeset section and an entry in this file, or CI fails).

## Rolling deploys and rollback (N and N−1)

The compatibility criterion, tested by the golden-DB suite on every
change: **the previous minor boots and serves core flows on the new
schema, and the new minor serves pre-migration rows.** Concretely,
during a rolling deploy or a rollback:

- 0.1.1 code on a 0.2.x database works — extra nullable columns are
  ignored, and old Auth.js token writes (`key` absent) are accepted
  by the nullable unique index. Rollback is data-safe.
- Caveat: an old pod cannot know fields it predates (e.g.
  `suspendedUntil`), so a suspended user keeps verifying on old pods
  until the rollout finishes. Finish rollouts promptly; that window
  is inherent to N/N−1.
- **Dev-push makes downgrades destructive** (Payload/drizzle prompts
  to delete the newer columns; accepting loses data, declining exits
  silently). Never roll back through a dev-push boot. Migrations
  mode boots old code read/write against the new schema safely
  (that is what the N−1 test proves).
- Schema changes follow expand → backfill → contract across two
  releases; a column that a previous minor cannot write against
  (NOT NULL without default, narrowed type) must never ship.

## Changing or removing roles

Roles are stored on user docs as plain slugs and validated for
**format** at the boundary, but grant only what the configured
`authLink({ roles })` allows (B11). When you remove or rename a
role, stored rows keep the old value until rewritten — so:

1. **Drain first.** Reassign every user holding the role to its
   replacement (admin panel or `payload.updateOne`) while the role
   is still configured.
2. **Then remove it** from `authLink({ roles })`.
3. **Boot and read the audit.** The first boot logs one aggregate
   warning — `N user doc(s) carry roles outside the configured set:
'editor' (2)` — if anything was missed. Sessions already stopped
   granting the removed role at that boot (reads filter it), and a
   user whose _only_ role was removed is denied a record entirely
   (never silently upgraded to the default role — same policy as
   corrupt roles).
4. Re-add the role to the config (temporarily) to drain properly if
   step 3 shows stragglers; clean rows keep the warning away on the
   next boot.

Renaming = add the new role, drain, remove the old one. The audit
runs on every boot (`onInit`) and costs one indexed query.

## Running production on migrations, not push

Dev-push (`push: true`) is for development: it makes destructive
choices interactively and makes downgrades lossy (above). Production
runs with `push: false` and explicit migrations:

1. Create the migration in your repo:

   ```sh
   payload.migrate:create   # or: bunx payload migrate:create
   ```

   Review the generated SQL before committing it. For the 0.1.1 →
   0.2.x move it must add `key` **nullable** (see above) and the
   optional governance columns — anything NOT NULL without a default
   is a bug in the migration, not in your database.

2. Run migrations as a deploy step, before new pods serve traffic:
   `payload.migrate` (or `bunx payload migrate`) in the release
   job. The expand→backfill→contract policy means migrations run
   cleanly while old-version pods still serve.
3. Keep the migration files in the repo — they are the record of
   how each release moves the database, and the artifact you attach
   to upgrade notes when you operate more than one environment.

The golden-DB tests (SQLite in `bun run check`; Postgres and Mongo
in the compat workflow) boot the previous release's seed under the
current code in both push and migrations modes, so a release that
would strand an upgraded database fails CI before it ships.

## 0.0.x → 0.1.0 (initial release)

First published line. No migration — but confirm before adopting:

- Packages are **ESM-only**. CJS `require()` of any entry (including
  `/cookies` subpaths) is unsupported; use ESM or dynamic import.
- The example's email-verification shortcuts
  (`requireEmailVerification: false`, immediate `emailVerified`
  stamps) are **local-dev-only**. Production must verify out-of-band.
- `payload.config.ts` collections for both providers are additive
  (`ba-*`, `aj-*`); the `users` extension adds `roles` +
  `identities` fields. No host migrations ship — your migration
  tooling owns schema changes (host-owned migrations only, per DNA).

## Session wire contract gains optional facts (PORT-4)

Additive only — no migration, and mixed versions keep working:

- **`SessionUser` and the plugin-level `Session` gain three optional
  fields**: `assurance` (`{ methods, mfa }`, how the session was
  proven), `actor` (`{ providerUserId }`, present only while an
  operator impersonates the user), and `organizationId` (the
  provider-native active tenant, when one is active). The session
  endpoint, the Payload auth strategy, the web verifier/`require*`
  helpers, and the React provider all carry them through.
- **Old payloads still parse.** A server that predates these fields
  simply omits them; clients see them as absent. Newer servers omit
  a field unless it is known — never `null`, never a fabricated
  default (a stray `null` for `actor`/`organizationId` is accepted
  and normalized to absent).
- **`'unknown'` assurance is data, not absence.** When the provider
  reported assurance but cannot tell the method or MFA state, the
  values serialize as `'unknown'`. Treat absent and `'unknown'`
  alike in policy: neither satisfies a requirement (fail closed) —
  but they stay distinguishable for diagnostics.
- **Malformed optional facts degrade, never nuke the user.** The
  client wire parser ignores unknown keys inside
  `assurance`/`actor` (forward compatibility with newer servers)
  and degrades a present-but-invalid optional
  fail-closed-for-policy (`assurance` to `'unknown'`,
  `actor`/`organizationId` to absent); core identity fields
  (`id`, `email`, `roles`) stay strict. An impersonation marker
  still cannot be laundered away server-side: authorization and
  audit use the plugin's own fail-closed extraction, where a
  present-but-malformed `actor` on `req.user` still denies and is
  audited as `actorKind: 'malformed-actor'`.

## Channel admission and impersonation completion (CAP-13a, CAP-8b)

- **`authLink({ admitChannels })` gates session channels.** It
  defaults to `['cookie']`: a live provider session presented on any
  other channel (`bearer`, `api-key`, `device`) is refused at
  verification with the typed `ChannelNotAdmittedError` (401),
  before any linking. Both shipped adapters report `cookie`, so
  existing behavior is unchanged. CSRF is unchanged too:
  state-changing endpoints still always require CSRF proof.
- **`Session.actor` and `SessionUser.actor` are now resolved.** The
  plugin looks the impersonating operator up by provider identity:
  a linked operator appears as
  `{ kind: 'payload-user', providerUserId, userId }` with the
  operator's Payload user id. An operator with no linked Payload
  user stays explicit: `{ kind: 'provider-only', providerUserId }`
  — fail-closed (the session still verifies and is audit-logged,
  but the provider id is never presented as a Payload id, and the
  unresolved state is logged as a warning). `parseSessionUser`
  accepts the legacy `{ providerUserId }` form and normalizes it to
  `provider-only`. `ProviderSession.actor` keeps the provider form.
- **Impersonated Payload operations are audited.** The plugin adds
  a `beforeOperation` hook to every collection and global that logs
  `impersonated operation` through `LoggerPort` with actor, target,
  operation, collection/global, and document id where named.
- **Impersonation is restricted by default (D5).** On the users
  collection the plugin now denies admin-panel access and writes to
  the roles field while an actor is present; reads are unaffected.
  For your own collections, `denyWhileImpersonating(ops?)` (plugin
  export) builds a matching `access` map — default denies `admin`,
  `create`, `update`, `delete`, and `unlock` while impersonating
  and allows reads — or gate on `isImpersonating(req)` inside your
  own access functions (fail-closed; `impersonationActorFromRequest`
  is for attribution only and returns `null` for a malformed actor
  that still denies).

## Hardening in the first release line (review backlog)

Behavior that tightened before first publish. Each change fails
closed, and none needs a data migration:

- **`authLink({ secret })` is deprecated and ignored.** Nothing in
  the plugin signs or encrypts: provider sessions are protected by
  the provider's own secret, and Payload auth by Payload's `secret`.
  The option stays optional so existing configs compile; delete it.
  `validateStartupConfig` (core) no longer accepts a `secret` key.
- **`safeRedirectPath` refuses sign-in and API destinations.** It
  falls back when the destination is the sign-in page (default
  `/sign-in`) or sits under `/api`. Pass
  `{ signInPath, apiPrefix }` to match custom mounts, or
  `{ signInPath: null }` where landing on sign-in is legitimate. It
  moved to core; `web`, `next` and `tanstack-start` re-export it
  unchanged.
- **`SignOutButton` narrows `redirectTo`** through
  `safeRedirectPath`. Off-origin and API destinations go to `/`.
- **`requireRoles` validates its role list first.** An invalid role
  (e.g. `'Admin'`) throws `InvalidRoleError`, and an empty list
  throws `InvalidConfigError`. Use `requireSessionUser` for "any
  signed-in user".
- **Wiring rejects illegal cookie attributes.** Provider session
  cookie names must be RFC 6265 tokens (checked at registration).
  Cookie `Domain`/`Path` values containing `;`, `,`, whitespace or
  control characters throw at serialization.
- **Auth.js `authorize` lowercases the email** exactly like
  registration, so `User@X.com` signs in. A corrupt stored
  `emailVerified` throws `AdapterMappingError`, and a gapped session
  chunk set is a failed read, never a joined token.
- **Clocks must be synchronized.** Session expiry has no skew
  leeway (see concepts).

## Future: WorkOS / Clerk adapters (post-v1)

Reserved registry ids, no packages yet. When they land they will be
new optional dependencies (`provider-workos`, `provider-clerk`)
following the same engine → port → collections shape — adopting one
is additive to the plugin options, never a rewrite.
