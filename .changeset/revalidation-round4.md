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

One minor across every package: the re-validation of 0.14.0 (#116) and three advisories.

- **provider-better-auth** (GHSA-xgx5-2cj5-x548):
  - a factor enrolled or revealed after a session began never steps that session up, so self-enrolment is not MFA proof;
  - the step-up lockout reserves each attempt before checking it, so concurrent bursts stop at the budget;
  - `get-totp-uri`, `generate-backup-codes`, `enable` and `disable` need an MFA session once a factor exists (403 `TWO_FACTOR_SESSION_REQUIRED`);
  - an emailed OTP is not MFA on sign-in either unless `twoFactorOtpChannelIndependent: true`, and OTP-only users lock;
  - session-token redaction is default-deny, covering `/two-factor/verify-*` and `/admin/list-user-sessions`.
- **plugin** (GHSA-j68x-qjr5-vqv9): `authLinkServer.verifyApiKey` returns `null` for a suspended owner or an identity with no linked Payload user; impersonated email/phone re-syncs are audited, and concurrent first touches audit once.
- **migrate** (GHSA-xw9m-ph95-84rx):
  - seals are bound to their database and run;
  - unsigned manifests are refused on 0.8+ databases for rollback and finalize;
  - clones are detected (Postgres fingerprint, `--environment-id`), with `--new-database-identity` / `--database-moved`;
  - one open run at a time, transactional rollback, `verify` in adopt mode, `adopt-prelink` keeps `updated_at`, doctor wording fixes and the `adopt-session-no-authentication-method` warning.
- **provider-authjs**: `engine.ts` fully covered; exact status assertions.
- **Examples and e2e**: the reference `/api/step-up` forwards Better Auth's session instead of minting `mfaProof`; ECONNRESET retry for idempotent e2e reads.

Upgrade impact: no database schema change; push and migrations have nothing to do on SQLite, Postgres or MongoDB (new Better Auth rows use the existing `verification` model, migrate facts the existing `payload-kv` records). The operator and client steps are in `docs/upgrading.md`:

- after enrolling, users sign in again with the factor to get MFA-gated roles;
- step-up UIs must handle 403 `TWO_FACTOR_SESSION_REQUIRED` on factor management;
- email-OTP-only deployments no longer satisfy `requireMfaForRoles` unless `twoFactorOtpChannelIndependent: true`;
- `verifyApiKey` keys for never-linked provider users now return `null`;
- migrate operators should set `--environment-id` per environment; unsigned manifests no longer work on 0.8+ databases.
