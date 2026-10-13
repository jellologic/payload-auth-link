---
'@payload-auth-link/provider-better-auth': patch
---

`@better-auth/api-key` support, verified and probed (issue #16): the
satellite works end to end once the `apikey` model is declared —
create/list through BA's endpoints, `x-api-key` requests resolve
through the plugin session, and Payload REST sees the user behind the
key (invalid keys 401). The committed schema probe now includes the
satellite (like `@better-auth/passkey`), so BA bumps that change its
schema fail the probe, not a user's boot; the compat matrix runs it
via the BA axis. Docs: troubleshooting and compatibility stop calling
the satellite unsupported; the capabilities guide gains an API-keys
recipe (declaration, `enableSessionForAPIKeys`, `admitChannels`), the
security posture — a key session carries its owner's Payload roles,
so an admin's key is an admin credential — and the MFA note
(`requireMfaForRoles` stays withheld from key sessions, which report
`assurance.mfa: false`). `examples/basic` wires the satellite and a
new e2e spec covers create → session → Payload REST → invalid key.

Upgrade impact: none for existing databases. Adopting API keys is
opt-in: declare the model, enable key sessions, admit the channel.
