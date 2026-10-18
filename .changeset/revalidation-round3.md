---
'@payload-auth-link/core': minor
'@payload-auth-link/web': minor
'@payload-auth-link/react': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/next': minor
'@payload-auth-link/tanstack-start': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
'@payload-auth-link/migrate': minor
---

One minor across every package: the re-validation of 0.13.0 (#113) and three advisories.

- **plugin** (GHSA-mjvh-7vmj-pg2p):
  - a suspended or provider-owned account's Payload API key or local JWT now resolves no user at authentication, so it is anonymous on every surface: other collections, upload file routes, custom endpoints, `payload.auth()`, preferences and `/access`;
  - a renamed `suspendedUntilField` is now honoured;
  - an unproven email change also resets the `emailVerifiedField` mirror;
  - impersonated session provisioning and organization reads are audited;
  - an unmapped role is dropped, not passed through raw.
- **provider-better-auth**:
  - two-factor step-ups share the sign-in lockout, and enrolling a first factor is no longer MFA proof (GHSA-38wx-69j6-cgm7);
  - an emailed OTP after an inbox-based sign-in doesn't count as MFA unless `twoFactorOtpChannelIndependent: true`;
  - raw session tokens are removed from Better Auth's HTTP JSON (`exposeSessionTokens: true` keeps them), and `/revoke-session` accepts a listed session `id`;
  - logout clearing cookies carry the configured cookie `Domain`;
  - adopt mode works with Payload's local strategy on, and every adopted collection is validated.
- **provider-authjs**: a builder `session` callback can no longer leak the database session token at any depth.
- **migrate** (GHSA-crrr-3cg7-f6jw):
  - manifests (v4) are bound to their database and run, and unsigned manifests are never re-signed;
  - rollback refuses when any finalize marker exists or the marker store can't be read;
  - plaintext restores need `--allow-plaintext-restore`;
  - the linking proof from `emailVerified` is opt-in (`--grant-linkable-from-verified`);
  - `verify` explains adopt mode;
  - the doctor derives the source map and reports `adopt-local-strategy-on` as a warning.
- **Tests and e2e**: exact status assertions, higher coverage floors, and settled navigations in e2e (no WebKit module-load noise).

Upgrade impact: no database schema change; push and migrations have nothing to do on SQLite, Postgres or MongoDB. The users collection gains only an `afterRead` hook (the credential gate). The operator and client steps are in `docs/upgrading.md`:

- dead local credentials now get the anonymous answer (often 403, or `/users/me` with `user: null`) instead of 401;
- step-up UIs must handle 429 `ACCOUNT_TEMPORARILY_LOCKED`;
- users who just enrolled keep MFA-gated roles withheld until a 2FA sign-in or a step-up with the enrolled factor;
- clients reading the session `token` from Better Auth's JSON need `exposeSessionTokens: true`, and `revokeSession` should take the listed `id`;
- `onAudit` sinks may see `operation: 'linkIdentity'` and `'read'`;
- migrate 0.7.0 manifests need `--allow-unbound-manifest` against the same database, and pre-0.7.0 manifests can only be rolled back or finalized;
- adopted session collections need an `authenticationMethod` text field for MFA provenance.
