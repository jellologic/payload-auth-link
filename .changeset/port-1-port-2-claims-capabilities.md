---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
---

Core session vocabulary and declared capabilities (PORT-1/PORT-2):
`ProviderSession` now carries `identity` claims
(`VerifiedClaim<Email>`/`VerifiedClaim<PhoneNumber>` plus `anonymous`),
`assurance` (`methods`/`mfa`, `'unknown'` when the provider cannot
tell), a required `actor`, `organizationId`, and a `channel`
(`'cookie' | 'bearer' | 'api-key' | 'device'`; one-time tokens present
as `bearer`, there is no `'one-time'` channel). The flat
`email`/`emailVerified` fields remain as deprecated aliases of the
email claim for one minor, and linking now reads the claim. Core adds
the branded E.164 `PhoneNumber` with `parsePhoneNumber`, plus
`UnsupportedCapabilityError`, `UnverifiedIdentityError`, and
`MfaRequiredError`. `IdentityProviderPort` gains a required
`capabilities: ReadonlySet<Capability>` and an optional
`revokeUserSessions`. **Breaking for custom adapters (compile
time):** existing `IdentityProviderPort`/`ProviderSession`
implementations will not compile until they declare `capabilities`
and return the new required session fields (`identity`,
`assurance`, `actor`, `organizationId`, `channel`). This ships as a
minor under the pre-1.0 policy in `docs/upgrading.md` (minors may
break option shapes and internal ports; the wire contract is the
stability anchor). Core also adds `assertCapabilities(provider,
required)`, which throws `UnsupportedCapabilityError` at wiring when
a capability a policy needs is undeclared, and the plugin enforces
it (e.g. a phone linking policy requires `'phone'`). Better
Auth fills the email claim, `mfa` from `user.twoFactorEnabled` when
declared (else `'unknown'`), `organizationId` from
`session.activeOrganizationId` when declared (else `null`), declares
`'impersonation'` only when the Better Auth admin plugin is
actually installed (observed `channel`: `'bearer'` for
Authorization-header presentation without the session cookie, else
`'cookie'`), and reports `methods: 'unknown'` (no per-session
method upstream). Auth.js fills the email claim with `methods`/`mfa`
`'unknown'` and declares no capabilities yet.
