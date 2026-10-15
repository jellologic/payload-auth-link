---
'@payload-auth-link/provider-better-auth': patch
---

The session-provenance recording is success-gated: a FAILED sign-in or verification never relabels the session's authentication method.

Better Auth's endpoint hooks run even when the endpoint returned an error response — its verify-totp RETURNS a 401 for a wrong code instead of unwinding the chain — so the recording hook ran on failures too. A wrong 2FA code from a non-MFA session on an MFA-enabled account could therefore relabel that session `two-factor`, unlocking MFA-gated roles without any valid second factor. The hook now mirrors Better Auth's own `getEndpointResponse` success contract (200 body required; non-2xx responses and APIErrors record nothing), so only successful requests write the method.

Upgrade impact: none stored — behavior only, and strictly narrower (failed requests record nothing, as they always should have).
