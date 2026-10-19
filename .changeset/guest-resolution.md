---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/migrate': patch
---

Adopt mode can resolve guest (anonymous) sessions to their own document: `authLink({ admitAnonymous: true })` (issue #126).

- **plugin** (new option): `admitAnonymous` lets an anonymous Better Auth session resolve to the guest's OWN host document in adopt mode (`idStrategy: 'payload'`, user model adopted) — payload-auth resolved guests, and apps built on it let guests own data through that document (`created_by`-style columns). The wiring refuses the option outside adopt mode. The resolved projection carries `anonymous: true` on `req.user` and on the session endpoint's JSON; the document's own roles govern `roles`. Guests are still never provisioned: a session whose row is gone is refused, not created.
- **core**: `Session` and `SessionUser` gain the optional `anonymous: true` marker; `ensureLinkedUser` takes `admitAnonymous` and resolves the opted-in guest through the provider-owned-id link (adopt mode), refusing a missing row.
- **migrate**: the doctor's `anonymous-users` warning and the "behaviour changes that will bite" list name the adopt-mode opt-in instead of leaving the refusal absolute.
