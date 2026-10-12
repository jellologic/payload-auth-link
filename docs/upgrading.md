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

## Future: WorkOS / Clerk adapters (post-v1)

Reserved registry ids, no packages yet. When they land they will be
new optional dependencies (`provider-workos`, `provider-clerk`)
following the same engine → port → collections shape — adopting one
is additive to the plugin options, never a rewrite.
