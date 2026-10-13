# Upgrading

Versioning rides [changesets](https://github.com/changesets/changesets):
every user-facing change ships a changeset, the release workflow
opens Version Packages PRs, and each package CHANGELOG records what
moved (starting at first publish — all packages are pre-release
`0.0.1` today). This page covers the moves that need human attention.

## Pre-1.0 policy

Minor versions may break: the wire contract (`SessionUser`, endpoint
paths, cookie semantics) is the stability anchor and changes only
with a migration note here; option shapes and internal ports may
evolve. Read the package CHANGELOGs on every bump once published.

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
