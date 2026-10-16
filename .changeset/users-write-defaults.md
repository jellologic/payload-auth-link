---
'@payload-auth-link/plugin': minor
'@payload-auth-link/migrate': minor
'@payload-auth-link/web': minor
---

Close open write defaults on the users collection: with no host-declared access, `update` is now self-or-role-manager and `delete` is role-manager only (never while impersonating), instead of Payload's "any signed-in user". The injected email field lets a non-manager change only their own address, even under a broader host `update`. `migrate export --out` and import manifests are written owner-only (0600) before content lands; sealed manifest values are bound to their entry and rollback restores only the fields the kit writes. `validateSessionEndpoint` rejects whitespace and control characters.

Upgrade impact: no schema change. Hosts that relied on any signed-in user updating or deleting other users must declare that access explicitly; see docs/upgrading.md.
