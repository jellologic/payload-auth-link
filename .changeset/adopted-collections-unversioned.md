---
'@payload-auth-link/core': patch
'@payload-auth-link/migrate': patch
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': patch
---

Adopted provider collections no longer keep secret-bearing version copies (GHSA-hfm3-x63j-7fxp). In adopt mode the engine writes sessions, verifications, accounts and API keys through the host's Payload collections, and when those are versioned (the `versions: { drafts: false }` shape payload-auth apps commonly carry — any truthy `versions` value versions the collection) every write stored a full copy of the row: session tokens, verification identifiers (magic-link and password-reset tokens under Better Auth's default plain storage), credential hashes. Payload's default `readVersions` (`Boolean(req.user)`) then listed those copies to any signed-in principal — a guest too, where `admitAnonymous` is on.

**Upgrade impact:** the plugin now disables versioning at boot on every adopted provider collection except `users` (logged with each slug; the users collection stays the host's choice — close its `readVersions` there) and fills any missing `readVersions` with the role-manager check; `IdentityProviderPort` grows an optional `adoptedCollections` fact (the better-auth engine derives it from `schemaMap`), so hand-fronted providers can report their adopted slugs. No collection shape changes and no migration is required — but the `_v` rows written BEFORE this upgrade remain in the database (now unreachable through the API): purge them (drop the `<slug>_v` tables, or delete their rows). The migrate doctor flags versioned adopted provider collections as a blocker before the cutover and, on plugin 0.19.0+, as a warning demanding exactly that purge; the migration guide documents the `versions: { drafts: false }` trap.
