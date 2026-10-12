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
