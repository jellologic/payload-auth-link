---
'@payload-auth-link/core': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

The server session API is hardened: minted sessions carry explicit, recorded assurance; one id type across mint/list/revoke with verified deletion; the requested TTL is honored and the stored expiry audited; `'dev-only'` means development.

- **Assurance reads a per-session record, not an enrollment flag.** The engine appends an internal Better Auth plugin adding one nullable `authenticationMethod` session field; mints record `server-mint` (no 2FA challenge ran — `mfa: false`), a server-vouched step-up records `server-step-up` (`mfa: true`). The old read leaned on `user.twoFactorEnabled`, so every mint for a 2FA-enrolled user claimed a second factor that never ran. Sign-in sessions without a recorded method report `mfa: 'unknown'`, which the MFA gate treats as absent (fail-closed) — restore gated roles via `createSessionFor(userId, { mfaProof: true })`, only where the server verified the second factor itself. `authLinkServer.sessionCookie`/`createSessionFor().setCookie` unchanged in shape.
- **`revokeSession` consumes the ids `listSessions` and `createSessionFor` hand out** (the session token — previously they returned row ids while revocation deleted by token, so revokes deleted nothing and reported success), and is verified: an id with no session behind it, or a delete that leaves the row in place, is an error.
- **Mint TTL honored and audited honestly.** The expiry was landing in Better Auth's `dontRememberMe` slot (every mint got ~24h regardless of the request, with the audit recording the requested value as if stored); it now goes through Better Auth's `override`, and the audit event and returned `expiresAt` carry the STORED expiry (`createSessionFor` result gains nothing breaking; providers report `storedExpiresAt`).
- **`'dev-only'` (the `allowServerSessions` default) enables minting ONLY on `NODE_ENV === 'development'`** — previously on everything except `'production'`, which silently armed minting in CI, test and staging.

Upgrade impact: the engine's session table gains one additive, nullable column through Better Auth's own schema machinery — run the usual Payload push/migrations; no data changes. Behaviour: MFA-gated roles are withheld for sessions with no recorded method until a `mfaProof` mint or a method-recording flow; `'dev-only'` now refuses minting outside development (set `allowServerSessions: true` explicitly). CI/test code that relied on the old default must opt in.
