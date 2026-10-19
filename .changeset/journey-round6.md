---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/migrate': minor
---

The payload-auth → payload-auth-link journey (#60): adopt-mode sign-ups resolve, migration writes are tellable, the cookie shape matches the docs, and the admin panel keeps forgot/reset.

- **plugin** (issue #124): in adopt mode (`idStrategy: 'payload'`, user model adopted), a user who signs up after the cutover now resolves to their own document on first request — the JIT link attaches the engine-created row by id (no email proof needed: nobody but the engine can mint a document with that id) and writes the identities row `adopt-prelink` writes for pre-cutover users; a new create hook normalizes the roles field (a scalar from Better Auth stores as the array shape, an absent value gets the default role). Before this, every post-cutover sign-up held a valid provider session with `req.user` null and no role.
- **plugin** (issue #121): `admin: { loginView: 'provider' }` now ships `ProviderForgotPasswordView` and `ProviderResetPasswordView` — the same flag registers all three provider views, driving the provider's own reset flow, so linked admins keep a forgot/reset path after moving off payload-auth (payload-auth injects those views; Payload's local flow stays refused for linked docs by design). One honest residual: Payload's router hard-codes the two-segment `/admin/reset/:token` screen (v3 and v4-beta), so the reset view serves `/admin/reset?token=…` — which the forgot view's redirect sets, and ProviderLoginView links to the forgot view.
- **plugin/core** (issue #125): `authLinkServer.sessionCookie(token)` returns the signed VALUE `token.<signature>` as documented (it returned a whole `Set-Cookie` line, which never verifies in a request `Cookie` header); the full line for responses stays on `createSessionFor(...).setCookie` and the provider port's new `sessionCookieLine`.
- **migrate** (issue #123): every host write the kit makes (`--apply`, `adopt-prelink --apply`, rollback restores) carries `context: { [MIGRATION_CONTEXT]: { op } }`, so host hooks can skip outbound side effects (CRM, email, webhooks, indexing); the doctor warns when the users collection declares such hooks.
- Breaking-with-the-docs note for engine users: a wrong-password `sign-in/email` through the Better Auth engine answers 400 `INVALID_EMAIL_OR_PASSWORD` (payload-auth's local strategy answered 401).

`Upgrade impact:` no database schema change. The regenerated
`snapshots/schema/plugin-users.json` diff is the users collection's
hook array gaining the roles-normalizing `beforeChange` hook — no
field, column, or index changes — so `payload push` and generated
migrations have nothing to do on SQLite, Postgres, or MongoDB.
Operators on adopt mode get the fix on upgrade with no data steps;
hosts whose users-collection hooks inspect `req.context` can skip
migration writes via `@payload-auth-link/migrate`'s exported
`MIGRATION_CONTEXT` key.
