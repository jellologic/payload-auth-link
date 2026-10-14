---
'@payload-auth-link/plugin': minor
---

Security hardening: JIT email linking now requires proof of email
ownership, and the users collection's `create`/`read` defaults fail
closed (GHSA-98hq-hh6v-2p2r — pre-account hijack: any authenticated
user could pre-create a Payload user with a victim's email and their
own password; when the victim later signed up through the provider,
JIT linking attached the verified identity to that attacker-created
document, and the attacker logged in with the password they chose).

- **New `linkable` field** on the users collection: the JIT-linking
  proof. Set automatically on plugin-managed creates (verified
  provider identity) and role-manager creates; role managers can
  toggle it. Documents created outside the plugin start unproven and
  are never JIT-linked until marked. Payload's own verified flag
  (`auth.verify`) also proves ownership.
- **Collection-level `create` on the users collection defaults to
  role-manager-only** (plus the impersonation deny), and **`read`
  defaults to self + role managers** (removing user enumeration) —
  both only where the host hasn't declared that access function.
- Linking to a document that also holds a local password logs a
  warning (one document, two credential owners).
- `findByEmail` (email-based resolution) returns unproven documents
  as absent, with a logged reason, so a verified identity is refused
  (401) rather than attached.

Upgrade impact: default-behaviour change. Non-managers can no longer
create users over REST or list other users; pre-existing documents
from before this release are unproven and need `linkable: true` (a
role-manager write, or the migration runbook's step 3) before their
owner's first provider sign-in links. Hosts whose end users
self-register through Payload REST must declare
`access: { create: ... }` on the users collection. Negative e2e
specs + integration tests pin the refusal, the proven/imported path,
the create block, and self-only listing on all six
adapter/example combos.
