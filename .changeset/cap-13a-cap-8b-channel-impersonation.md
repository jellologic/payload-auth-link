---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/web': minor
'@payload-auth-link/react': minor
---

Channel admission (CAP-13a) and impersonation completion (CAP-8b).

- The plugin gains `admitChannels` (default `['cookie']`): a live
  provider session presented on a non-admitted channel (`bearer`,
  `api-key`, `device`) is refused at verification with the new typed
  `ChannelNotAdmittedError` (401) before any linking, and
  verification stops at the presenting provider. Channels are
  observed, not asserted: Better Auth reports `'bearer'` when the
  session arrives via an `Authorization: Bearer [REDACTED]` header without
  the session cookie (denied by the default policy), and Auth.js
  reports `'cookie'` because it only reads cookie-presented
  sessions. CSRF is unchanged in this phase.
- `Session.actor` / `SessionUser.actor` are now the resolved
  `ResolvedSessionActor` discriminated union: `payload-user` (with
  the operator's Payload `userId`, resolved through
  `UserRepository.findByProviderIdentity`) or `provider-only` (no
  linked Payload user — fail-closed: still audited and restricted,
  never presented as a Payload id, logged as a warning).
  `parseSessionUser` accepts the legacy `{ providerUserId }` form
  and normalizes it to `provider-only`; `ProviderSession.actor`
  keeps the provider form.
- Every authenticated Payload collection/global operation performed
  while impersonating is audit-logged through `LoggerPort`
  (`impersonated operation`: actor, target, operation,
  collection/global, document id) via plugin-installed
  `beforeOperation` hooks, so denied attempts are audited too.
- Default impersonation restrictions (D5): the plugin denies
  admin-panel access and roles-field writes on the users collection
  while an actor is present (reads allowed), and exports
  `denyWhileImpersonating(ops?)`, the fail-closed
  `isImpersonating(req)` / `impersonationStateFromRequest(req)`
  server extraction (a present-but-malformed `actor` still denies
  and audits; authorization never routes through the client wire
  parser), plus `impersonationActorFromRequest` for attribution, so
  builders can apply the same default — deny admin and writes,
  allow reads — to their own collections.

See `docs/upgrading.md`.
