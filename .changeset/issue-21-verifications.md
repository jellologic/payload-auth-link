---
'@payload-auth-link/plugin': minor
'@payload-auth-link/next': minor
---

Verified fixes from the code-read sweep (issue #21):

- **Organization membership uniqueness.** The memberships collection
  gains a compound **unique index on `(user, organization)`**: two
  concurrent invite-accepts (or owner-bootstrap hooks) could
  previously both pass the check-then-insert and land duplicate rows.
  Existing databases with duplicates must dedupe before the index
  builds (see docs/upgrading.md).
- **`setEmail` keeps identity rows in step.** Changing a user's email
  now rewrites linked-identity rows that carried the old address, so
  the admin users view no longer shows a stale identity email.
- **Role-config audit is bounded and its truncation note is
  reachable.** The startup audit no longer passes `pagination: false`
  (which ignored the 500-doc limit and made the truncation message
  unreachable); the note now fires when more users exist than were
  scanned.
- **Impersonation in custom endpoints: proven, not assumed.** The
  "is `req.user` populated here?" doubt is settled by a test — the
  organization-create endpoint's impersonation deny fires on a real
  impersonated session.
- **`checkAuthCookies(request, options)`** (next): composable form of
  the optimistic middleware — returns the 303 sign-in redirect or
  `null` — for apps that run their own `proxy.ts` (Next 16) /
  `middleware.ts` pipeline.

Upgrade impact: new unique index on the memberships collection
(dedupe existing duplicates first — per-adapter notes in
docs/upgrading.md); `setEmail` now also writes the `identities` array
when address-bearing rows change; the startup role audit's query
shape changes (bounded, paginated).
