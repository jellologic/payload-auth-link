---
'@payload-auth-link/plugin': minor
---

Security hardening: the plugin's account controls now apply to EVERY
strategy (GHSA-f4hj — suspension and the MFA policy were enforced only
on the `auth-link` strategy, and Payload's forgot/reset-password flow
ran past the 0.6.0 password-write strip, so a suspended user could
keep access through a self-minted local password).

- **Suspension is enforced on every strategy, at request time.**
  `beforeLogin` refuses the local sign-in for a suspended account
  (401), and a request-time gate on every collection and global
  refuses any request carrying a suspended account's local JWT or API
  key (401) — including `refresh-token` and GraphQL — with a fresh
  read of `suspendedUntil`, so the control lands the moment an
  operator sets it.
- **`policies.requireMfaForRoles` applies to local credentials.**
  Local sessions have no MFA proof, so the listed roles are withheld
  from local-strategy sessions (JWT, API key) before any access check
  reads them. Local login is not blocked; the session loses the role.
- **Provider-linked documents are provider-owned** (new
  `allowLocalCredentialsForLinkedDocs` option, default `false`):
  local sign-in is refused (403) and the forgot/reset-password flow
  is refused (403, no token issued) for documents holding linked
  identities — a local password there would bypass the provider's
  MFA, bans, rate limits, and revocation. Documents without linked
  identities (operator accounts, imports not yet linked) keep local
  credentials and password recovery.
- **New committed credential-path matrix** (`docs/security-model.md`)
  plus a table-driven test walking every path for a suspended user, a
  non-manager attempting role/email/password writes, and an
  unproven-email link.

Upgrade impact: no schema changes and no backfill. Default-behaviour
changes only — see `docs/upgrading.md` (0.6.x → 0.7.0): suspended
accounts now lose local credentials too; provider-linked documents no
longer accept local sign-in or self-service password reset unless
`allowLocalCredentialsForLinkedDocs: true` is set (migration-window
escape hatch; remove it when the window closes).
