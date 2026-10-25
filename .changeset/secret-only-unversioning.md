---
'@payload-auth-link/core': patch
'@payload-auth-link/migrate': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

Fix the 0.19.0 adopted-collection hardening scope (issue #164): the forced `versions: false` hit EVERY adopted collection, silently stripping versioning from business tables hosts legitimately version — production `organizations` with `versions: { drafts: true }` lost its approval-workflow history and `migrate:create` generated a destructive migration dropping `_organizations_v`. The engine now declares which adopted models are SECRET-bearing (sessions, verifications, accounts, API keys, jwks, two-factor, OAuth application/token tables) via a new `IdentityProviderPort.secretCollections` fact, and the plugin force-disables versioning on exactly those. Every other adopted collection — organizations, members, invitations, team models, users — keeps the host's `versions` untouched; the plugin only backfills a missing `readVersions` with the role-manager check there, which is the defense-in-depth part of the GHSA-hfm3 fix. The doctor's `versioned-provider-collections` check is scoped the same way, and its details point at `>= 0.19.1`. Upgrade note for 0.19.0 hosts: re-apply your `versions` config on non-secret adopted tables (0.19.0 stripped it at boot; 0.19.1 restores the host's choice) — no `_v` data was lost, only unwritten while on 0.19.0.
