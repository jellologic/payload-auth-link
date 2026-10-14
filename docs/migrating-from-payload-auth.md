# Migrating from `payload-auth`

`payload-auth` makes the Payload `users` collection **be** Better
Auth's user table: passwords and OAuth tokens live in
`user_accounts`, sessions in `user_sessions`, and the plugin
rewrites the schema on BA upgrades. `payload-auth-link` keeps Better
Auth rows in dedicated `ba-*` collections keyed by a text `baId`,
while Payload owns `users`. There is no compatibility layer
(deliberately — see MISSION.md), but the data move is mechanical.
This page is the runbook; the script sketch below is a starting
point, not a turnkey migration — review it against your schema.

## What moves where

| payload-auth                                              | payload-auth-link                                                                                                                                    |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `users` (the BA user table)                               | `ba-users` (new rows, `baId` = old Payload user id) + your existing `users` (keep it; add the injected fields)                                       |
| `user_accounts`                                           | `ba-accounts` (same `providerId`/`accountId`; the `credential` password hash carries over verbatim)                                                  |
| `user_sessions` / `user_sessions?token`                   | `ba-sessions` — **dropped**; everyone signs in again (say so in your release notes)                                                                  |
| `verification` rows                                       | `ba-verifications` — droppable; in-flight emails re-send                                                                                             |
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

## Migration script (sketch)

The script below is a **sketch**, not a shipped tool: review it
against your schema, run it with a dry-run flag of your own, and keep
the backup. (The `linkable: true` marks in step 3 are what allow JIT
email linking for imported users — without the marker, a returning
user's first provider sign-in is refused until a role manager marks
them.)

Run this ONCE from the new app (Payload Local API, `overrideAccess`
everywhere). Read the old tables directly (same database) or from an
export. Order matters: users → accounts → links → plugin models.

```ts
import { getPayload } from 'payload'
import config from './payload.config'

const payload = await getPayload({ config })

// 1. Users: one ba-users row per old user; baId = the old id.
for (const old of oldUsers) {
  await payload.create({
    collection: 'ba-users',
    data: {
      baId: String(old.id), // text id: the old Payload id
      email: old.email,
      name: old.name ?? '',
      emailVerified: old.emailVerified === true,
      createdAt: old.createdAt,
      updatedAt: old.updatedAt,
      // plugin fields you used on payload-auth (e.g. twoFactorEnabled,
      // isAnonymous) map onto your customFields declarations 1:1
    },
    overrideAccess: true,
  })
}

// 2. Accounts: password hashes and OAuth tokens carry over verbatim.
for (const account of oldAccounts) {
  await payload.create({
    collection: 'ba-accounts',
    data: {
      baId: crypto.randomUUID(),
      accountId: String(account.accountId), // OAuth subject id
      providerId: account.providerId, // 'credential', 'google', ...
      userId: String(account.userId), // -> ba-users.baId (the old id)
      password: account.password, // credential hash: unchanged
      accessToken: account.accessToken ?? undefined,
      // ...remaining token columns you used
    },
    overrideAccess: true,
  })
}

// 3. Identity links: pre-populate users.identities[] so the first
// sign-in does not depend on JIT email linking.
for (const old of oldUsers) {
  const links = oldAccounts.filter((a) => String(a.userId) === String(old.id))
  await payload.update({
    collection: 'users',
    id: old.id,
    data: {
      roles: old.role ?? ['user'], // your adopted roles field
      linkable: true, // PROOF of email ownership (required for JIT linking)
      identities: links.map((a) => ({
        providerId: a.providerId === 'credential' ? 'better-auth' : a.providerId,
        providerUserId: String(a.userId),
        email: old.email,
        linkedAt: new Date().toISOString(),
      })),
    },
    overrideAccess: true,
  })
}

// 4. Plugin models: rewrite foreign keys to baId text ids.
for (const member of oldMembers) {
  await payload.create({
    collection: 'ba-members',
    data: {
      baId: crypto.randomUUID(),
      organizationId: orgIdMap.get(String(member.organizationId))!,
      userId: String(member.userId),
      role: member.role,
      createdAt: member.createdAt,
    },
    overrideAccess: true,
  })
}
// ...invitations, apikeys (referenceId), jwks the same way.
```

## Session and verification policy

- **Sessions are dropped.** `user_sessions` do not migrate; every
  user signs in again on the new stack. That is the documented
  policy — announce it. (Cookie-prefix continuity can make even that
  unnecessary — see above.)
- **Verification tokens are dropped.** In-flight verification emails
  re-send; nothing else is lost.
- **Sessions after cutover:** new sessions are `ba-sessions` rows;
  old `user_sessions` rows are inert. Keep the old tables until a
  soak period passes, then drop them.
- **Rollback:** the old tables are untouched, so rolling back is a
  deploy revert — new sign-ups since cutover exist only in `ba-*`
  rows and would need the script reversed.

## Verify before cutover

- sign in with an existing **password** (hash carried over);
- sign in with each **OAuth** provider you used;
- an admin can still edit roles (the adopted field is governed —
  your admin role must be in `roleManagerRoles`, which defaults to
  `['admin']`);
- suspended/banned users still bounce (copy `banned`/`banReason`/
  `banExpires` onto the Payload user's governance fields or your own);
- the admin users list shows roles + linked identities.
