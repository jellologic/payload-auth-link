# payload-auth fixture app (issue #59)

Generates the **payload-auth 1.9.x fixture database** — the contract
every migration feature (#49 adopt, #50 importer, #51 coexistence, #52
doctor) is tested against. The committed dump in
[`fixtures/dumps/`](../dumps/) was produced by **running payload-auth
1.9.4 itself** (Better Auth 1.6.30) against Postgres; no row is
hand-written.

## Contents of the fixture

| Requirement (#59)                              | Where it lands                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| email+password users, verified and unverified  | `users` rows alice/carol (verified), bob/dave (unverified)                                        |
| OAuth accounts                                 | `accounts` rows: `google`, `generic-oauth`                                                        |
| magic-link verifications                       | `verifications` (unexpired)                                                                       |
| organization plugin + host fields              | `organizations`/`members`/`invitations`; host `billing` group, `tags` array, `owner` relationship |
| API keys with metadata                         | `api_keys` (`ci-key`, `read-only`)                                                                |
| camelCase role value in a `hasMany` role field | `users_role` value `frontPlugin`                                                                  |
| active sessions                                | `sessions` (all unexpired)                                                                        |
| `jwks`                                         | signing key from the `jwt` plugin                                                                 |

Legacy cookie names: `advanced.cookiePrefix: 'bl'` — the fixture's
session cookie is `bl.session_token` / `__Secure-bl.session_token`
(#51 coexistence).

## Regenerating the dump

Requires Docker (`pal-pg` on :5433) — the same container the local
`bun run test:fixture` expects:

```sh
docker start pal-pg
docker exec pal-pg psql -U postgres -c 'DROP DATABASE IF EXISTS pal_fixture'
cd fixtures/payload-auth-app
DATABASE_URL=postgres://postgres:payload@localhost:5433/pal_fixture bun scripts/seed.ts
docker exec pal-pg pg_dump -U postgres --no-owner --no-privileges --clean --if-exists --inserts \
  pal_fixture > ../dumps/payload-auth-1.9.4.sql
```

Commit the new dump. `bun run test:fixture` pins the row counts, role
values, hash shape, and host fields, so a regenerated dump that drifts
from the contract fails CI.

## Deliberate payload-auth quirks the seed documents

- **Creator member role encoding.** BA 1.6 sends the organization
  creator's member role as an array; payload-auth stringifies it into
  the single-select column as `'["owner"]'`, which BA's own permission
  checks then fail to parse. The seed normalizes that one row so the
  invitation flow (payload-auth's own code) runs; the fixture keeps
  the `invitations.role` value exactly as payload-auth wrote it.
- **`acceptInvitation` is unavailable**: BA 1.6's organization adapter
  calls `adapter.incrementOne`, which payload-auth's adapter does not
  implement (BA 1.7 made the method optional with a fallback). The
  seed adds the member directly. Our own engine must keep
  `incrementOne` in the optional tail of its adapter contract — see
  `packages/provider-better-auth/src/__tests__/adapter-contract.test.ts`.
- **`pg_dump --inserts`**: the committed dump uses INSERT statements
  (not COPY) and drops the `\restrict` meta-command, so the `pg`
  driver can load it without psql.
