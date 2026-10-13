---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/web': minor
'@payload-auth-link/react': minor
---

Session wire contract gains optional facts (PORT-4): plugin-level
`Session` and the `SessionUser` wire shape now carry optional
`assurance` (`methods`/`mfa`), `actor` (`{ providerUserId }`, only
while impersonating), and `organizationId` (only when a
provider-native tenant is active). The plugin projects them from the
provider session onto the session endpoint response and the Payload
auth strategy user; the web verifier and `require*` helpers and the
React provider pass them through. Back-compatible by construction:
payloads without the fields still parse, producers omit a field
unless it is known, and a reported `assurance` serializes even when
its values are `'unknown'` — consumers must treat absent and
`'unknown'` alike as not satisfied (fail closed). The client wire
parser is forward-compatible: unknown keys inside
`assurance`/`actor` are ignored and a present-but-malformed
optional degrades fail-closed-for-policy (`assurance` to
`'unknown'`, `actor`/`organizationId` to absent) instead of failing
the whole user, while core identity fields stay strict. Server-side
authorization/audit never use that parser: the plugin's fail-closed
server extraction treats a present-but-malformed `actor` on
`req.user` as impersonating (deny + audit). See `docs/upgrading.md`.
