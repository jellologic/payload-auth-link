---
'@payload-auth-link/plugin': minor
---

JIT email linking no longer treats Payload's `_verified` flag as proof of email ownership, and proof never survives an unproven email change.

- `findByEmail` admits a pre-existing document only when it carries the plugin's `linkable` proof bound to its current address (`linkableEmail`), as docs/security-model.md row 8 documents. Payload keeps `_verified` across email changes (and its default field access lets any signed-in user write it), so a verified, unlinked document whose owner changed its email to someone else's address could previously be linked to that person's provider identity.
- An email change made neither by the plugin's provider-email resync nor by a role manager clears `linkable` and `linkableEmail` — and `_verified` on `auth.verify` hosts — in the same write.
- Linking an identity clears Payload's local `sessions` array for the document (`auth.useSessions`, Payload's default), so a local JWT issued before the link is refused afterwards; on hosts without `useSessions`, the account-control gate refuses `local-jwt` requests on provider-linked documents (401) unless `allowLocalCredentialsForLinkedDocs` is set.
- Provisioning that collides with an existing, unproven document holding the same email is a logged, typed refusal (401, `provisioning refused: …` through the logger) instead of a storage error; Payload's "already registered" auth-collection check now maps to `UserExistsError` like the unique-index violation.

Upgrade impact: no schema change — no column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Operator step: hosts that relied on `_verified` alone to JIT-link pre-existing accounts must grant `linkable` + `linkableEmail` to the accounts they trust (snippet and audit guidance in docs/upgrading.md); the migration importer already does this for verified imports. Users who change their own email on an `auth.verify` host must re-verify before local sign-in.
