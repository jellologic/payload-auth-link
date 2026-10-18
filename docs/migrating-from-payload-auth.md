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
2. **Choose the path**: **adopt** (#49, zero row moves — `schemaMap` serves BA models from your existing tables, then `adopt-prelink` links each user to their document) or **import** (#50, reversible copy into `ba-*`). Same credentials both ways; hashes are portable.
3. **Migrate roles**: `roleValues` keeps stored values like `frontPlugin` untouched (#56); `projectRolesAs: 'stored'` keeps access checks comparing stored literals working.
4. **`req.user`**: opt into `reqUser: 'document'` if access functions read full-document fields (#57).
5. **Coexistence**: `legacySessions` keeps legacy payload-auth session cookies working inside a dated window (#51) — nobody is logged out.
6. **Cut over**: `from-payload-auth --apply` (importer; sessions carry by default), `verify`, watch the window, `finalize --config …`.
7. **Codemods**: `codemod --src ./src [--write]` rewrites the named call sites (AST-matched, alias- and `import type`-aware); the opt-in `payload.betterAuth` shim covers the rest incrementally (#53).
8. **Server API**: `authLinkServer(payload)` replaces every `$context` internal bridge (#54).
9. **Admin**: `admin: { loginView: 'provider' }` restores /admin login through the provider, with the break-glass local form (#55). It registers a Payload admin component, so REGENERATE your import map after enabling it (`payload generate:importmap`) — a stale map renders an empty login page. The view's break-glass endpoint (`${routes.api}/${usersCollection}/login`) and post-login destination (`routes.admin`) follow your Payload config; set `admin.signInPath` (default `/sign-in`) and `admin.authBase` (default `/api/auth`, where the app serves Better Auth) when yours differ.
10. **Off-ramp**: `export --database-url … --out …` — lossless JSONL of every auth table ([which ones](#the-off-ramp-export); `--source-map` for renamed layouts, `--tables` to narrow it); uninstall is a tested operation (#58).

## Step 0: run the doctor (read-only preflight)

Before touching anything, get the exact list of what will break:

```sh
bunx @payload-auth-link/migrate doctor --config ./src/payload.config.ts --src ./src
```

It reads the config, the users collection, the Better Auth plugins,
your sources, and (with `--database-url` or `DATABASE_URL`) the
database — and reports version bands, plugin support (including
schema-adding plugin calls hiding in non-config helper files), users
collection collisions and role values, the 0.7.0 behaviour changes
that will bite, every call site that must migrate, and per-table row
counts with unverified users and orphans. A config that cannot even be
IMPORTED (the mid-upgrade state) is a `config-unloadable` blocker, not
a crash — the static scans still run and still catch what the load
cannot (an `oidcProvider(`/`mcp(` call is flagged as removed in
better-auth 1.7). `--json` gives tools the same findings with stable
machine codes; exit codes are `0` clean, `1` blockers, `2` warnings
only. Fix the blockers it names before writing anything — every later
step in this guide assumes the doctor's blocker list is clear.

**Run it with a production-shaped environment.** The doctor IMPORTS
your config module, so it needs every variable the config reads at
import time — `PAYLOAD_SECRET`, `DATABASE_URL`, your provider client
ids/secrets, any `NEXT_PUBLIC_*` value the config dereferences. A
missing variable usually throws during the import, and the report
degrades to a `config-unloadable` blocker plus static scans only. Load
the env file the app boots with first (`set -a; . ./.env.production;
set +a`, or your secret manager's equivalent); a read replica's URL is
fine for `--database-url`.

Run it twice: against the payload-auth app's config (the source — what
breaks), and against the TARGET config once payload-auth-link is wired
in. On the target, the plugin's own injected users fields
(`identities`, `linkable`, …) are recognized as the plugin's and never
reported as collisions, and the database checks below become blockers
when the target cannot hold source state.

What the database section flags for the importer (issue #88):

| Code                                               | Meaning                                                                                                                                                                                                                                                                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `banned-users` / `target-cannot-hold-bans`         | Better Auth admin-plugin bans exist. They carry onto `ba-users` only when the target engine declares `admin()`; on a target without it the doctor blocks and the importer refuses.                                                                                                    |
| `anonymous-users` / `target-cannot-hold-anonymous` | Anonymous-plugin users exist; they need `anonymous()` on the target (or delete them first). The plugin refuses anonymous sessions by design — they never JIT-link.                                                                                                                    |
| `oauth-tables-not-carried`                         | `oauth_*` tables (OAuth/OIDC-provider plugin) exist. The importer does **not** copy them: re-register clients on `@better-auth/oauth-provider` (its own schema migration) before dropping the legacy tables.                                                                          |
| `generic-oauth-providers`                          | `genericOAuth()` is declared (imported from `better-auth/plugins` or a subpath such as `better-auth/plugins/generic-oauth`). Its providers live in config, not the database: carry every entry into the new engine, or those users' sign-in strands (their `accounts` rows do carry). |

On the TARGET config the doctor also checks the adopt-mode wiring:

| Code                      | Meaning                                                                                                                                                                                                                                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `adopt-local-strategy-on` | Blocker. Adopt mode serves Better Auth's users from your `users` collection while Payload's local strategy is ON there: Payload then requires a password on every create, so every NEW user fails (email sign-up 422, anonymous sign-in 500 "field is invalid: password"). Set `auth: { disableLocalStrategy: true }` (see adopt mode below). |

**Custom table slugs.** If your layout renamed the payload-auth tables
(the production field report: `user_accounts`, `user_sessions`), say so
explicitly with `--source-map` — the doctor, the importer, `verify`,
and `export` all take it:

```sh
--source-map '{"accounts":"user_accounts","sessions":"user_sessions"}'
```

A `null` value records a model as not installed (`"organizations":null`)
and skips it by config. Without a map, a missing source table is a
blocker that names the table and suggests `--source-map` — nothing is
silently read as empty.

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

## Adopt mode (#49): serve Better Auth from your existing tables

Adopt mode moves no rows: the engine's `schemaMap` points each Better
Auth model at the payload-auth collection that already holds it, and
`idStrategy: 'payload'` makes the Payload document id the Better Auth
id.

```ts
createBetterAuthEngine({
  getPayload,
  idStrategy: 'payload',
  autoDeclare: true,
  schemaMap: {
    user: { slug: 'users' },
    session: {
      slug: 'sessions',
      fields: { userId: 'user', activeOrganizationId: 'activeOrganization' },
    },
    account: { slug: 'accounts', fields: { userId: 'user' } },
    verification: { slug: 'verifications' },
    organization: { slug: 'organizations' },
    member: { slug: 'members', fields: { organizationId: 'organization', userId: 'user' } },
    invitation: {
      slug: 'invitations',
      fields: { organizationId: 'organization', inviterId: 'inviter' },
    },
    // @better-auth/api-key 1.7.x names the key owner `referenceId` —
    // the name payload-auth's column already has — so map the slug
    // only. (`fields: { userId: 'referenceId' }` is a 1.6-era map and
    // is wrong on 1.7.)
    apikey: { slug: 'apiKeys' },
    jwks: { slug: 'jwks' },
  },
  options: {/* your Better Auth options: same secret, same advanced.cookiePrefix */},
})
```

**Keep the SAME Better Auth secret.** payload-auth passes no `secret`
to Better Auth, so it ran on `BETTER_AUTH_SECRET` / `AUTH_SECRET` (or,
outside production, Better Auth's development default). The `jwt`
plugin encrypts the `jwks` private keys with that secret: an engine
booted with a different one fails every session read that signs a JWT
("Failed to decrypt private key"), and the session cookies stop
verifying. Pass the old value as the engine's `options.secret`.

Add the plugin's additive users columns before boot (identities,
linkable, linkableEmail, phone, suspension — a migration or `push`).

**Turn Payload's local strategy OFF on the adopted users collection.**
In adopt mode Better Auth CREATES its users in that collection, and
with the local strategy on, Payload requires a password on every
create: every new user fails (email sign-up returns 422, anonymous
sign-in 500 "field is invalid: password"). payload-auth apps that set
`disableDefaultPayloadAuth: true` already have it off; otherwise set
it on the collection:

```ts
{ slug: 'users', auth: { disableLocalStrategy: true }, fields: [/* … */] }
```

Operators then reach `/admin` through the provider
(`admin: { loginView: 'provider' }`). The doctor run against the
TARGET config reports `adopt-local-strategy-on` as a blocker until
this is done.

### Pre-link the users: `adopt-prelink`

Adopt mode serves the Better Auth side, but the plugin side still has
no link between a Better Auth user and its Payload document: without
one, the first provider sign-in goes through JIT linking, which links
an existing document only on the verified-email proof (`linkable` true
with `linkableEmail` equal to the document email). `adopt-prelink`
writes exactly what the importer writes on the host users:

- ONE `better-auth` identity per user (`providerUserId` = the document
  id — the Better Auth user id under `idStrategy: 'payload'`); other
  providers' identity rows are kept;
- `linkable: true` + `linkableEmail` for users whose `emailVerified`
  is true (grant-only; `--verified-field` names another checkbox).

```sh
# Plan (dry run, nothing written)
bunx @payload-auth-link/migrate adopt-prelink --config ./src/payload.config.ts
# Write, recording the manifest (./payload-auth-link-prelink.json)
bunx @payload-auth-link/migrate adopt-prelink --config ./src/payload.config.ts --apply
# Undo exactly
bunx @payload-auth-link/migrate rollback --config ./src/payload.config.ts \
  --manifest ./payload-auth-link-prelink.json
```

Re-running is safe (already-linked users are skipped); a user already
carrying a `better-auth` identity for a DIFFERENT id aborts the run
with nothing written. The manifest follows the importer's rules
(below). After `--apply`, verified and unverified users alike resolve
to their ORIGINAL document on their next sign-in.

`finalize --config ./src/payload.config.ts --manifest
./payload-auth-link-prelink.json` closes the pre-link the same way it
closes an import: rollback is refused afterwards. In adopt mode there
are no legacy tables to drop — the payload-auth tables ARE the live
Better Auth tables; never drop them.

### Adopt is live traffic on the old tables

There is no copy to roll back to: from the first request, Better Auth
reads and WRITES the payload-auth tables — new sessions, updated
users — and it deletes an expired `sessions` row whenever a lookup
meets one. Plan rollback as a database restore (snapshot before the
deploy) plus `rollback --manifest` for the pre-link fields, never as
"the old rows are untouched".

## The importer: `from-payload-auth` (#50)

The sketch below became a runnable, reversible CLI. In the NEW app
(the one booting payload-auth-link with its own `ba-*` collections on
the same database) — running it against the untouched payload-auth
app's config refuses immediately with a naming check, because there
are no target collections to write to (#75):

```sh
# 1. The plan. Dry run by default: planned counts per model,
#    unmappable rows, unverified users. Nothing is written.
bunx @payload-auth-link/migrate from-payload-auth \
  --config ./src/payload.config.ts --database-url $DATABASE_URL

# 2. The copy. Writes the ba-* rows through Payload's Local API,
#    records every created row and field change in the manifest
#    (./payload-auth-link-migration.json — see "The manifest" below),
#    and never touches the source tables.
bunx @payload-auth-link/migrate from-payload-auth \
  --config ./src/payload.config.ts --database-url $DATABASE_URL --apply

# 3. The check. EXACT counts per model (zero never skips; every model
#    in --source-map is either counted or explicitly null-mapped), one
#    target row per source user resolving through one better-auth
#    identity, every credential account resolving to its user with its
#    hash, every API key and member/invitation resolving. Non-zero
#    exit on any mismatch.
bunx @payload-auth-link/migrate verify \
  --config ./src/payload.config.ts --database-url $DATABASE_URL

# 4. The undo (any time before finalize). Deletes exactly the rows the
#    manifest created — only ever in the import's own ba-* collections —
#    and restores every captured field value.
bunx @payload-auth-link/migrate rollback --config ./src/payload.config.ts

# 5. The point of no return. Boots the app, records the finalize in its
#    database, and re-signs the manifest as finalized; rollback is
#    refused from here on. Only now are the legacy tables eligible to
#    be dropped — in a separate, later migration. Nothing is dropped.
bunx @payload-auth-link/migrate finalize --config ./src/payload.config.ts
```

What it copies: users — each with ONE pre-linked `better-auth` identity
resolving to their `ba-users` row, so a provider sign-in (now or after
a later email verification) lands on the ORIGINAL Payload document,
while `linkable` + `linkableEmail` stay granted from VERIFIED emails
only (that gate is email-ownership proof, not identity resolution) —
plus credential accounts with their password hashes VERBATIM, OAuth
accounts with their tokens, magic-link verifications, API keys with
hash/prefix/metadata/rate-limit state, jwks, and the organization
plugin's rows (orgs, members, invitations) with references remapped.
`--sessions=carry` (the default) copies the session table so nobody is
logged out — keep the same `advanced.cookiePrefix` and the existing
cookies keep working; `--sessions=drop` starts everyone fresh instead.

Better Auth plugin state carries too (issue #88): admin-plugin
`banned` / `banReason` / `banExpires` and the stored roles (as Better
Auth's comma-separated `role`) when the target engine declares
`admin()`, and `isAnonymous` when it declares `anonymous()`. A banned
or anonymous source user whose state the target cannot hold aborts
the run before any write — a banned user never imports unbanned. Row
`createdAt`/`updatedAt` carry for every model whose source table has
them (accounts, sessions, verifications, API keys, jwks, orgs,
members, invitations). OAuth-provider tables (`oauth_*`) are NOT
carried — see the doctor table above.

It is idempotent and resumable: every target row carries a
deterministic `baId` derived from the source id, so a re-run after a
crash finds its own earlier rows and skips them. It is also fail
closed: the run PROBES every mapped source model's table and required
columns first, and a missing one aborts before anything is read or
written — pass `--source-map` (above) for renamed layouts or to record
a model as not installed. Unmappable data (orphaned references) aborts
the run — nothing is silently skipped.

### The manifest: where it goes, what it holds, when to delete it

`--apply` writes the manifest to `./payload-auth-link-migration.json`
in the CURRENT DIRECTORY unless `--manifest` names another path —
point it somewhere access-controlled. It records created row ids and
the PRIOR value of every host field the run changed (`identities`,
`linkable`, `linkableEmail`, `roles` where present, and the document's
`updatedAt`). No value is stored in the clear: prior values are sealed
with AES-256-GCM under a key derived from the app's `PAYLOAD_SECRET`,
so `rollback` must run against the same app with the same secret. The
file is written with mode `0600`.

The manifest is also **signed** (version 3): an HMAC-SHA256 over the
whole file — `finalized` included — keyed from the same secret.
Rollback deletes rows and restores fields with `overrideAccess`, so an
edited manifest must not be able to steer it. `rollback`, `finalize`,
and any resumed `--apply` or `adopt-prelink` refuse a manifest that
fails the check, before writing anything. Independently of the
signature:

- **Rollback deletes only the importer's own rows.** Every created
  row must sit in one of the import's target collections (the `ba-*`
  slugs, or the `--slugs` the import ran with — pass the same ones to
  `rollback`) under the model its entry names, and a row still present
  must carry the deterministic `baId` the importer gave it. Anything
  else — a host collection, another model's slug, a row that took the
  id since — refuses the whole rollback before the first delete. An
  `adopt-prelink` manifest creates no rows, so one that lists any is
  refused.
- **`finalize` is recorded in the database.** It boots the app (so it
  takes `--config`, like `rollback`), writes a one-way marker into
  Payload's built-in key-value store (the `payload-kv` collection;
  `payload_kv` on SQL adapters), then re-signs the manifest as
  finalized. Every later `rollback` and resumed `--apply` checks the
  marker as well, so neither an edited flag nor a restored
  pre-finalize copy of the manifest reopens the migration. If the
  store is unavailable (its table was never created), `finalize` fails
  with the manifest unchanged — run your Payload migrations and re-run
  it.

Manifests from older kits:

- **Version 1/2 (before 0.6.0)** carry no signature. If you are
  mid-migration with one, and sure nobody has edited it,
  `--allow-unsigned-manifest` accepts it — but a rollback then only
  restores sealed field values and deletes nothing. To also DELETE the
  rows it lists (and restore a version-1 manifest's plaintext values),
  review its `created` entries and add `--allow-unsigned-deletes`; the
  scoping rules above still apply. The next write signs the manifest.
- **Version 3 from migrate 0.6.0** is signed, but that signature did
  not cover `finalized`. It still works for a resumed `--apply` and
  for `finalize`; `rollback` asks for `--allow-unsigned-manifest` to
  vouch that it was never finalized. Any write re-signs it under the
  current scheme. A manifest already finalized stays finalized.

Keep it until you have run `finalize` AND your soak window has passed
(rollback needs it); then delete it.

### What rollback restores, exactly

`rollback` deletes every row the manifest created and restores every
captured host field to its value from BEFORE the first `--apply` (only
the first capture per field is kept, so any number of `--apply` passes
still roll back to the pre-import state) — `users.updated_at`
included. It then RESETS the manifest (no rows, no field writes), so a
later `--apply` starts fresh instead of building on stale entries.

A row that is already gone is fine — the goal is "absent". A delete
that FAILS (a foreign key from one of your tables, a hook, a
permission) is an error: rollback names each row it could not delete
and why, exits non-zero, restores no field value, and keeps the
manifest as it was. Fix the cause and re-run `rollback`; the rows it
already deleted then count as absent.

One thing it cannot restore: the forward Local API write re-creates
hasMany child rows (the `users_role` table behind a `role` select)
with new row ids. Their values and order are identical; only the
surrogate `id` column differs. Nothing references those ids, but if
you diff the table, diff `(parent_id, order, value)`. A second
`--apply` does not touch them again: the importer writes a host user
only when a value actually differs (identity, roles, linking proof),
so a re-run over imported users leaves their rows byte-identical —
`updated_at`, `linked_at`, and the child-row ids included.

### What the importer normalises

The copy is verbatim except for these normalisations:

- **Empty strings become absent (`NULL`)** on optional text columns:
  an account's `scope`, `password`, `access_token`, `refresh_token`,
  `id_token`; a session's `ip_address` and `user_agent`; a user's
  `image` (and `ban_reason`); an API key's `name`, `start`, `prefix`,
  `permissions`, `metadata`; an organization's `logo` / `metadata`; a
  member's or invitation's `role` / `status`. Better Auth reads both
  the same; an exact column diff shows `''` → `NULL`. The reverse
  holds for required columns: a missing user `name` or API-key
  `config_id` is stored as `''`.
- **`ba_users.updated_at` is the import time**, not the source row's
  `updated_at`: Payload stamps it on create. `created_at` carries, and
  the other models carry both timestamps.
- **Host roles use the field configured on `authLink`** (`rolesField`,
  e.g. `role`): the importer, `rollback`, and `verify` read it from the
  booted config, so the roles check runs on `role` layouts too.

### The off-ramp export

`export` writes every auth table as lossless JSONL (one
`{"table", "row"}` object per line, every column as stored). "Every
auth table" means, against what the database actually holds:

1. each mapped model's table — payload-auth's layout, or your
   `--source-map` (renamed tables exported under their own names, a
   `null` model skipped). These are REQUIRED: a mapped table that does
   not exist exits `1` and names it — on a renamed layout, pass the
   same `--source-map` the importer took;
2. their child tables when present (`<table>_*`: `users_role`,
   `users_identities`, `users_sessions`, `organizations_tags`, `_rels`
   tables), plus payload-auth's other Better Auth plugin tables when
   present (`admin_invitations`, `two_factors`, `passkeys`,
   `sso_providers`, `organization_roles`, `teams`, `team_members`,
   `device_code`, `subscriptions`);
3. every `ba_*` (payload-auth-link engine) and `oauth_*` (OAuth
   provider) table present.

`--tables` replaces the whole set with an exact list (a missing name
exits `1`). Progress lines go to stderr, so stdout is pure JSONL when
no `--out` is given.

### `verify` after go-live

`verify` is a cutover check. Its session check counts only the
IMPORTED rows — every unexpired source session must be present — and
reports sessions created since the import (and expired imported
sessions Better Auth already cleaned up) as information, never as a
failure. The other models keep EXACT counts, so new sign-ups after
go-live make `verify` report more `ba-users` than the source: run it
right after the copy, before you open traffic.

### Email verification after the import

An unverified user is imported pre-linked by identity but without the
linking proof. When they verify later, the plugin receives Better
Auth's update and grants the bound proof (`linkable` +
`linkableEmail`) on their document. If your users collection keeps
payload-auth's own `emailVerified` checkbox, set
`authLink({ emailVerifiedField: 'emailVerified' })` and the plugin
also sets it `true` on that verification. It sets it `false` only when
a self-service email change resets the linking proof (the mirror no
longer vouches for the new, unproven address).

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
- suspended/banned users still bounce (the importer carries
  `banned`/`banReason`/`banExpires` onto `ba-users` when the engine
  declares `admin()`, so Better Auth refuses them; mirror bans onto the
  plugin's `suspendedUntil` too if Payload-local paths matter);
- the admin users list shows roles + linked identities.
