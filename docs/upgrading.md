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
