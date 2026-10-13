---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
'@payload-auth-link/react': minor
'@payload-auth-link/web': minor
---

Capabilities Phases 3–7 (PLAN-CAPABILITIES): passwordless, OAuth,
passkeys, MFA policy, suspend, phone, guests, organizations, SSO.

Core: session-policy primitives (`effectiveRoles`, `mfaSatisfied`,
`isSuspendedAt`, `emailDomainAllowed`), `UserSuspendedError`,
`UserRecord.phone`/`suspendedUntil`, guest principals and their wire
envelope (`SessionGuest`), verified-phone linking fallback for
placeholder-email sign-ups, and optional multi-session port methods.

Plugin: `policies.requireMfaForRoles` (roles withheld without MFA
proof, `mfaRequired` on the wire), governance fields (`phone`,
`suspendedUntil`, `suspendReason`) with verify-time suspension and
best-effort provider revocation, `verified-email-or-phone` linking
wired end to end (`findByPhone`/`setPhone`), guest sessions on the
session endpoint, Payload-owned organizations (`organizations:
{ enabled: true }` — collections, manager access, invite/accept
endpoints, `requireOrgRole`), SSO verified-domain enforcement
(`organizations.ssoProviders`), multi-session logout sweep, and
channel-aware CSRF (admitted bearer skips the origin check).

Better Auth: capabilities derived from installed plugins
(magic-link, email-otp, oauth, one-tap, passkey, mfa, phone,
anonymous), phone and placeholder-email claim mapping (SIWE and
anonymous identities are guests, never email claims),
`revokeUserSessions`, multi-session enumeration for logout, and a
fix: `ba-users.name` no longer rejects the empty-string names
Better Auth's passwordless flows create.

Auth.js: capabilities derived from configured providers (email →
magic-link, oauth/oidc → oauth, database sessions →
revoke-user-sessions, implemented for the database strategy), plus
CAP-2/CAP-4 recipes — `generateEmailOtpCode`,
`buildEmailOtpCallbackUrl`, `verifyGoogleIdToken`, and
`createGoogleOneTapAuthorize`.

React/web: `guest` on the auth context with `fetchSession`,
`requireRoles({ requireMfa: true })` throwing typed
`MfaRequiredError` (including for withheld-role step-ups).
