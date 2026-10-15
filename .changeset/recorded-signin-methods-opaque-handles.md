---
'@payload-auth-link/core': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

Better Auth's native sign-in flows record their authentication method, and session ids become opaque handles (issues #79 and #80).

- **`requireMfaForRoles` works through Better Auth's own 2FA again (#79).** 0.10.1's assurance read the per-session `authenticationMethod` column, but only server-side mints wrote it — a user completing BA's native two-factor sign-in got `mfa: 'unknown'` and their MFA-gated role stayed withheld. The provenance plugin now stamps the method on every recognized sign-in flow (`password`, `two-factor` on the verification endpoints, `oauth` callbacks, `magic-link`, `email-otp`, `passkey`); BA's 2FA-pending sign-in expires the session cookie, so a single-factor session is never relabelled — the second factor issues a FRESH session recorded as `two-factor`. Unknown paths still record nothing (fail closed).
- **Session ids are opaque handles, never bearer tokens (#80).** `listSessions` and `createSessionFor().sessionId` return the session row id instead of the raw token — a devices page could otherwise expose one live credential per session into page data, logs, and error reports. `revokeSession` resolves the handle server-side and keeps its verified-deletion semantics; BA's own logout internals (which revoke by token) are unaffected. `createSessionFor().token` and `sessionCookie(token)` are unchanged — the token still rides exactly where setting the cookie needs it.

Upgrade impact: no stored data changes (the column exists since 0.10.1). Behavior: MFA-gated roles through BA's native 2FA are restored without a custom step-up route; consumers that treated `listSessions` ids as tokens must switch to the opaque handles (revocation accepts both shapes).
