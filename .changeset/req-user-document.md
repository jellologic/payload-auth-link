---
'@payload-auth-link/plugin': minor
---

Opt-in full user document on `req.user` (issue #57):
`authLink({ reqUser: 'document' })` (default `'projection'`).

Access functions coming from payload-auth read fields off the full
document (`req.user.activeOrganization`, `req.user.name`, …); under
the default projection those read `undefined` and access decisions
drift silently. With `reqUser: 'document'` the full document loads
once per request through the `req.context` memo — for cookie sessions
in the strategy and for local JWT/API-key sessions in the request
gate — while the security-relevant projected fields stay
authoritative on top of it: `roles` after the MFA projection,
`actor`/impersonation markers, suspension.
