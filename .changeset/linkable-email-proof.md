---
'@payload-auth-link/plugin': minor
---

Security hardening: the JIT-linking proof is now bound to the email
it was granted for (GHSA-8524 — the 0.5.0 `linkable` marker survived
a self-service email change, so a pre-created document re-proven for
an attacker-chosen password could be moved to a victim's email and
JIT-linked to them).

- **New `linkableEmail` field**: the email the proof was granted for.
  The proof holds only while the document email equals it; any email
  change that is not the plugin's own provider-email resync
  invalidates linking automatically.
- **Email changes over REST on documents with linked identities are
  role-manager-only** (stripped for non-managers). Payload's own
  `auth.verify` can re-prove an address if the host enables it.
- **Self-service local passwords on plugin-managed documents are
  stripped** for non-managers: a provider-provisioned user can no
  longer mint a Payload local credential that bypasses Better Auth's
  MFA, bans, rate limits, and verification. Role managers keep
  password writes; hosts who declare their own password field access
  keep it.
- **The link-time local-password warning now actually fires** (the
  hidden-field lookup was silently failing).
- The provider-email resync keeps the proof bound: repository
  `setEmail` moves the email and the proof together with
  `overrideAccess`.

Upgrade impact + backfill: existing `linkable: true` documents
(created by 0.5.0/0.5.1 without `linkableEmail`) are treated as
unproven. Backfill `linkableEmail = email` ONLY where the email still
matches the linked identity's email; treat anything else as unproven.
Role managers can set it per user over REST; the migration runbook's
script marks both fields for imported users. Negative e2e specs cover
the full advisory chain on all six adapter/example combos.
