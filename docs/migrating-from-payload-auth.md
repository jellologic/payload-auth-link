# Migrating from `payload-auth`

`payload-auth` makes the Payload `users` collection **be** Better
Auth's user table: passwords and OAuth tokens live in `accounts`,
sessions in `sessions`, and the plugin rewrites the schema on BA
upgrades. `payload-auth-link` either **adopts** your existing
collections (zero row moves, #49) or **imports** the rows into its
own `ba-*` collections (#50) — both paths are runnable, reversible,
and CI-proven against a real payload-auth 1.9.4 database (the
fixture at `fixtures/`). This page is the runbook; every step is a
shipped command, not a sketch. The field report behind it is
[journey issue #60](https://github.com/jellologic/payload-auth-link/issues/60).

## The runbook at a glance

1. **Doctor** (read-only): `bunx @payload-auth-link/migrate doctor --config … --src …` — the exact blocker list.
2. **Choose the path**: **adopt** (#49, zero row moves — `schemaMap` serves BA models from your existing tables) or **import** (#50, reversible copy into `ba-*`). Same credentials both ways; hashes are portable.
3. **Migrate roles**: `roleValues` keeps stored values like `frontPlugin` untouched (#56); `projectRolesAs: 'stored'` keeps access checks comparing stored literals working.
4. **`req.user`**: opt into `reqUser: 'document'` if access functions read full-document fields (#57).
5. **Coexistence**: `legacySessions` keeps legacy payload-auth session cookies working inside a dated window (#51) — nobody is logged out.
6. **Cut over**: `from-payload-auth --apply` (importer; sessions carry by default), `verify`, watch the window, `finalize`.
7. **Codemods**: `codemod --src ./src [--write]` rewrites the named call sites; the opt-in `payload.betterAuth` shim covers the rest incrementally (#53).
8. **Server API**: `authLinkServer(payload)` replaces every `$context` internal bridge (#54).
9. **Admin**: `admin: { loginView: 'provider' }` restores /admin login through the provider, with the break-glass local form (#55).
10. **Off-ramp**: `export --database-url … --out …` — lossless JSONL of every auth table; uninstall is a tested operation (#58).

## Step 0: run the doctor (read-only preflight)

Before touching anything, get the exact list of what will break:

```sh
bunx @payload-auth-link/migrate doctor --config ./src/payload.config.ts --src ./src
```

It reads the config, the users collection, the Better Auth plugins,
your sources, and (with `--database-url` or `DATABASE_URL`) the
database — and reports version bands, plugin support, users-collection
collisions and role values, the 0.7.0 behaviour changes that will
bite, every call site that must migrate, and per-table row counts with
unverified users and orphans. `--json` gives tools the same findings
with stable machine codes; exit codes are `0` clean, `1` blockers,
`2` warnings only. Fix the blockers it names before writing anything —
every later step in this guide assumes the doctor's blocker list is
clear.

## What moves where

| payload-auth                                              | payload-auth-link                                                                                                                                    |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `users` (the BA user table)                               | `ba-users` (new rows, `baId` = old Payload user id) + your existing `users` (keep it; add the injected fields)                                       |
| `user_accounts`                                           | `ba-accounts` (same `providerId`/`accountId`; the `credential` password hash carries over verbatim)                                                  |
| `user_sessions` / `user_sessions?token`                   | `ba-sessions` — **carried by default** (`--sessions=drop` starts everyone fresh instead)                                                             |
| `verification` rows                                       | `ba-verifications` — carried verbatim; in-flight links keep working until they expire                                                                |
| organization / member / invitation / apikey / jwks tables | `ba-organizations` / `ba-members` / `ba-invitations` / `ba-apikeys` / `ba-jwks` — foreign keys rewritten from numeric Payload ids to the text `baId` |
| your `role` column on `users`                             | **adopted** (see below) — no rename, no second field                                                                                                 |

## Before you start

1. **Back up the database.** The migration writes new collections and
   rewrites foreign keys; it does not touch the old tables (drop them
   later, after a soak period).
2. **Versions.** Migrate on the validated band (compatibility.md):
   Payload 3.83+, better-auth `>=1.7.6 <1.8.0` as a **direct
   dependency** of your app (it is a peer here).
3. **Cookie prefix.** Better Auth scopes cookies with
   `advanced.cookiePrefix`. Keep the SAME prefix in the new engine's
   options and live sessions survive the deploy even before users
   re-sign-in (the session row moved, the cookie still names it).
   If you must change the prefix, expect a forced re-login and say so.

## The roles field is adopted, not duplicated

`payload-auth` sites read `role` in dozens of access functions.
`authLink` detects an existing compatible field at the configured
`rolesField` (default `roles`; remap with `rolesField: 'role'`) and
**adopts** it instead of throwing:

- compatible = Payload `select`, `hasMany: true`, options covering
  every configured role (extras like `staff` stay);
- adoption adds required-ness, the default, and the plugin's
  governed write access (role-manager roles only — see
  [upgrading](upgrading.md)); host labels and extra options survive;
- incompatible shapes fail at config time with the exact remediation.

Your access functions keep reading `req.user.role`-style fields only
if you remap them to the configured rolesField — plan that find/
replace once.

## The shape of `req.user`

`req.user` is the **session projection**:
`{ id, collection, email, roles, account, assurance?, actor?, organizationId? }`
— not the full user document. Fields like `name` or
`activeOrganization` are not on it. Read them through Payload's own
APIs (`req.payload.findByID({ collection: 'users', id: req.user.id })`
in access functions, `/api/users/me` on the client) or extend the
projection yourself. This is deliberate: the projection is stable
across providers and strategies.

## Keeping camelCase role values (e.g. `frontPlugin`) — no rename needed

payload-auth apps commonly carry camelCase select values — `user /
admin / staff / frontPlugin`. payload-auth-link roles are canonical
lowercase slugs inside the plugin; the **role value map** keeps the
stored form exactly as it is:

```ts
authLink({
  roles: ['user', 'admin', 'staff', 'front-plugin'],
  rolesField: 'role', // adopt the host select
  roleValues: { 'front-plugin': 'frontPlugin' }, // canonical → stored
})
```

Inside the plugin everything is canonical — `requireRoles(['front-plugin'])`,
`policies.requireMfaForRoles`, the role-manager checks. At the storage
edge — field reads, governed writes, and the injected select's
options — values are translated both ways, so the database never
changes and admin edits keep storing `frontPlugin`. Keys must be
declared roles and stored values must be unique; both fail at config
time.

`req.user` is the session projection by default (`{ id, collection,
email, roles }` plus assurance fields). Access functions reading other
fields off it keep working unchanged with
`authLink({ reqUser: 'document' })` — the full document loads once per
request and the projected, security-relevant fields stay authoritative
on top of it (#57).

`req.user.roles` carries canonical roles by default. Access functions
that compare the stored literal (`req.user.roles.includes('frontPlugin')`)
can keep working unchanged with
`projectRolesAs: 'stored'` — the MFA gate and role governance always
run on canonical roles regardless; this option shapes the projection
only. The doctor lists every non-canonical stored value so the map is
complete before you boot.

## The importer: `from-payload-auth` (#50)

The sketch below became a runnable, reversible CLI. In the NEW app
(the one booting payload-auth-link with its own `ba-*` collections on
the same database):

```sh
# 1. The plan. Dry run by default: planned counts per model,
#    unmappable rows, unverified users. Nothing is written.
bunx @payload-auth-link/migrate from-payload-auth \
  --config ./src/payload.config.ts --database-url $DATABASE_URL

# 2. The copy. Writes the ba-* rows through Payload's Local API,
#    records every created row and field change in the manifest
#    (./payload-auth-link-migration.json), and never touches the
#    source tables.
bunx @payload-auth-link/migrate from-payload-auth \
  --config ./src/payload.config.ts --database-url $DATABASE_URL --apply

# 3. The check. Counts per model, one target row per source user,
#    every credential account resolving to its user with its hash,
#    every API key and member/invitation resolving. Non-zero exit on
#    any mismatch.
bunx @payload-auth-link/migrate verify \
  --config ./src/payload.config.ts --database-url $DATABASE_URL

# 4. The undo (any time before finalize). Deletes exactly the rows the
#    manifest created and restores every captured field value.
bunx @payload-auth-link/migrate rollback --config ./src/payload.config.ts

# 5. The point of no return. Marks the manifest finalized; only now
#    are the legacy tables eligible to be dropped — in a separate,
#    later migration. Nothing is dropped for you.
bunx @payload-auth-link/migrate finalize
```

What it copies: users (with `linkable` + `linkableEmail` granted from
VERIFIED emails only — unverified users are reported and never
linked), credential accounts with their password hashes VERBATIM,
OAuth accounts with their tokens, magic-link verifications, API keys
with hash/prefix/metadata/rate-limit state, jwks, and the organization
plugin's rows (orgs, members, invitations) with references remapped.
`--sessions=carry` (the default) copies the session table so nobody is
logged out — keep the same `advanced.cookiePrefix` and the existing
cookies keep working; `--sessions=drop` starts everyone fresh instead.

It is idempotent and resumable: every target row carries a
deterministic `baId` derived from the source id, so a re-run after a
crash finds its own earlier rows and skips them. Unmappable data
(orphaned references) aborts the run — nothing is silently skipped.

The importer's target slugs default to `ba-users`, `ba-accounts`,
`ba-sessions`, `ba-verifications`, `ba-apikey`, `ba-jwks`,
`ba-organization`, `ba-member`, `ba-invitation`; pass `--slugs` (JSON)
if your engine wiring overrides them.

## Session and verification policy

- **Sessions carry by default.** `--sessions=carry` (the default)
  copies `user_sessions` into `ba-sessions`; keep the same
  `advanced.cookiePrefix` and nobody is logged out. `--sessions=drop`
  starts everyone fresh instead — if you drop sessions or change the
  prefix, announce the forced re-login in your release notes.
- **Verification tokens carry.** In-flight verification links keep
  working until they expire; nothing is lost.
- **Sessions after cutover:** new sessions are `ba-sessions` rows;
  old `user_sessions` rows are inert. Keep the old tables until a
  soak period passes, then drop them.
- **Rollback:** the old tables are untouched, so rolling back is a
  deploy revert — new sign-ups since cutover exist only in `ba-*`
  rows and would need the script reversed.
- **Local passwords die when the provider identity links.** A
  migrated user's carried-over password keeps working until their
  `ba-accounts` row links to the Payload document; from that moment
  the document is provider-owned — local sign-in and the
  forgot/reset-password flow are refused for it (GHSA-f4hj: a local
  password would bypass the provider's MFA, bans, and revocation).
  That is the intended end state; users sign in through the
  provider. If your cutover needs both credentials alive for a
  window, set `allowLocalCredentialsForLinkedDocs: true` in the
  plugin options and remove it when the window closes. Break-glass
  operator accounts (no linked identities) are unaffected.

## Verify before cutover

- sign in with an existing **password** (hash carried over);
- sign in with each **OAuth** provider you used;
- an admin can still edit roles (the adopted field is governed —
  your admin role must be in `roleManagerRoles`, which defaults to
  `['admin']`);
- suspended/banned users still bounce (copy `banned`/`banReason`/
  `banExpires` onto the Payload user's governance fields or your own);
- the admin users list shows roles + linked identities.
