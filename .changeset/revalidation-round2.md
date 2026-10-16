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

One minor across every package, from the re-validation of 0.12.0 (#110). This release:

- **plugin**:
  - linking a provider identity clears the document's Payload API key, and API keys on provider-linked documents are refused unless `allowLocalCredentialsForLinkedDocs` is set;
  - the linking-proof grant guidance is corrected, and collision refusals now point to resolving the collision;
  - impersonated organization endpoint calls always answer the audited 403;
  - `authLinkServer(payload)` works across bundler module copies (TanStack Start).
- **provider-authjs**: the session endpoint returns an allowlisted shape (`user` name/email/image/id/emailVerified, plus `expires`) on both session strategies.
- **provider-better-auth**:
  - logout expires the chunked cookie-cache and `account_data` cookies;
  - a correct second factor on an existing session deterministically marks it MFA-proven;
  - `not_in` keeps NULL rows, and case-insensitive `eq` matches non-ASCII text on SQLite;
  - `verifyApiKey` refuses organization-owned and orphaned keys (`UnsupportedApiKeyOwnerError`).
- **migrate**:
  - the manifest signature covers `finalized`, and `finalize` records a one-way marker in the app database;
  - rollback deletes only the import's own target rows, and a failed delete exits non-zero;
  - unsigned manifests cannot delete without `--allow-unsigned-deletes`;
  - `export --source-map` is added, and `verify` uses the configured roles field;
  - a second `--apply` is a true no-op, and there are new doctor checks.
- **Tests and CI**:
  - coverage is now measured on sources, with per-file floors;
  - the vitest inline patterns are anchored;
  - several security-matrix rows are pinned on real engines;
  - the examples type-check with generated Payload types in CI.

Upgrade impact: no schema change, and nothing to run for push or migrations on any adapter. The operator steps are in `docs/upgrading.md`:

- move service integrations off linked users' API keys;
- `finalize` now needs `--config`;
- pass `--slugs` to `rollback` when the import used custom slugs;
- clients that read `sessionToken`, `userId` or `id` from the Auth.js session JSON must expose those fields from their own `session` callback.
