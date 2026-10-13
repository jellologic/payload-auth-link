---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
---

Generalized linking policy (PORT-3): core adds a declared
`LinkingPolicy` discriminated union (`verified-email`, the default,
plus opt-in `verified-email-or-phone`) with `defaultLinkingPolicy`, a
strict `linkingPolicySchema`, and `parseLinkingPolicy`.
`ensureLinkedUser` accepts an optional `linkingPolicy`; omitted or
`verified-email` preserves the previous verified-email behavior
exactly. The opt-in branch links a phone-only identity carrying a
verified phone claim to an _existing_ user resolved through the new
optional `UserRepository.findByPhone` port method — it never
provisions, and every phone-only refusal is
`UnverifiedIdentityError`. Anonymous identities never link under any
policy — intentionally including when the identity was previously
linked (D3): the anonymous gate runs before the already-linked fast
path, so an anonymous session for a linked identity is refused, not
verified. The plugin accepts a validated `linkingPolicy` option and
passes it through to the session service; `verified-email-or-phone`
additionally requires every registered provider to declare the
`'phone'` capability (PORT-2 `assertCapabilities`, enforced at
wiring) and currently fails fast at wiring because the Payload users
collection has no phone field (and the repository no `findByPhone`)
until CAP-9.
