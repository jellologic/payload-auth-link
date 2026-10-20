# @payload-auth-link/provider-authjs

## 0.8.4

### Patch Changes

- Updated dependencies [[`253d05a`](https://github.com/jellologic/payload-auth-link/commit/253d05ac943d3926cf2d165e4a1ac60a3ffbc1c3)]:
  - @payload-auth-link/core@0.13.0

## 0.8.3

### Patch Changes

- Updated dependencies [[`f75c921`](https://github.com/jellologic/payload-auth-link/commit/f75c9212cbbfa2a59c6d4b84b3ab9a1ef4381aed)]:
  - @payload-auth-link/core@0.12.2

## 0.8.2

### Patch Changes

- Updated dependencies [[`6ee27be`](https://github.com/jellologic/payload-auth-link/commit/6ee27be17c014ebcb850694cac03bca07a46d6a8)]:
  - @payload-auth-link/core@0.12.1

## 0.8.1

### Patch Changes

- Updated dependencies [[`d7650b5`](https://github.com/jellologic/payload-auth-link/commit/d7650b579c67f6d1b7759bcac66006266a1b5d0f)]:
  - @payload-auth-link/core@0.12.0

## 0.8.0

### Minor Changes

- [#117](https://github.com/jellologic/payload-auth-link/pull/117) [`4779b2a`](https://github.com/jellologic/payload-auth-link/commit/4779b2aba7f858af5b5ffd0f79266652965090af) Thanks [@jellologic](https://github.com/jellologic)! - One minor across every package: the re-validation of 0.14.0 ([#116](https://github.com/jellologic/payload-auth-link/issues/116)) and three advisories.

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

### Patch Changes

- Updated dependencies [[`4779b2a`](https://github.com/jellologic/payload-auth-link/commit/4779b2aba7f858af5b5ffd0f79266652965090af)]:
  - @payload-auth-link/core@0.11.0

## 0.7.0

### Minor Changes

- [#114](https://github.com/jellologic/payload-auth-link/pull/114) [`f66a032`](https://github.com/jellologic/payload-auth-link/commit/f66a032aeb7673e46df63e809808c54b6ebbeec7) Thanks [@jellologic](https://github.com/jellologic)! - One minor across every package: the re-validation of 0.13.0 ([#113](https://github.com/jellologic/payload-auth-link/issues/113)) and three advisories.

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

### Patch Changes

- Updated dependencies [[`f66a032`](https://github.com/jellologic/payload-auth-link/commit/f66a032aeb7673e46df63e809808c54b6ebbeec7)]:
  - @payload-auth-link/core@0.10.0

## 0.6.0

### Minor Changes

- [#111](https://github.com/jellologic/payload-auth-link/pull/111) [`75212b3`](https://github.com/jellologic/payload-auth-link/commit/75212b36d96c5d9b5cdad29c842809b65c2a87db) Thanks [@jellologic](https://github.com/jellologic)! - One minor across every package, from the re-validation of 0.12.0 ([#110](https://github.com/jellologic/payload-auth-link/issues/110)). This release:

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

### Patch Changes

- Updated dependencies [[`75212b3`](https://github.com/jellologic/payload-auth-link/commit/75212b36d96c5d9b5cdad29c842809b65c2a87db)]:
  - @payload-auth-link/core@0.9.0

## 0.5.0

### Minor Changes

- [#108](https://github.com/jellologic/payload-auth-link/pull/108) [`b718ac4`](https://github.com/jellologic/payload-auth-link/commit/b718ac4fe66266b28eb4decd895b0f15452bdbf5) Thanks [@jellologic](https://github.com/jellologic)! - One minor across every package. It follows a re-validation of every published security advisory against the current source, and closes the adjacent gaps that pass found.

  - **migrate: signed manifests** (follow-up to GHSA-p76j-5qwx-rpwx). The 0.5.0 fix sealed each captured value. Two edits were still accepted:
    - a plaintext `before` entry on any allowlisted field, `roles` included;
    - extra `created` rows, which rollback deletes with `overrideAccess`.

    Manifests are now version 3, with an HMAC-SHA256 over the whole file keyed from `PAYLOAD_SECRET`. `rollback`, and a resumed `--apply` / `adopt-prelink`, refuse a manifest that fails the check. Older unsigned manifests need `--allow-unsigned-manifest` once.

  - **plugin: users `readVersions` default.** When the host leaves it unset, it is now role managers only. Before, `/api/users/versions` listed every user's versions, emails included, to any signed-in user on a users collection with `versions` enabled.
  - **plugin: `roleValues` on local sessions.** The role-manager check and the `requireMfaForRoles` strip now compare canonical roles. A local session holding a mapped MFA-policy role kept it without MFA, and a local admin stored under a mapped value was not a role manager.
  - **Release path:** moved to `changesets/action` v2.1.2 ([#102](https://github.com/jellologic/payload-auth-link/issues/102)). Version PR commits and release tags are pushed through the GitHub API at the CI-tested SHA.
  - **Lint:** a new rule forbids `console.*` and `process.stdout`/`stderr` in package sources, outside the logger sink and the migrate CLI. This keeps the debug writes removed by GHSA-hxgq-9pww-59j4 from coming back.
  - **Dependencies:** Payload 3.91.0 is the tested `latest` on v3; the peer range is unchanged. The remaining `bun audit` findings are triaged in `SECURITY.md`, and none reaches a published package.

  Upgrade impact: no schema change, and nothing to run for push or migrations on any adapter. Operator steps are in `docs/upgrading.md`: pass `--allow-unsigned-manifest` once if you are mid-migration with a manifest written by migrate ≤ 0.5.x. A host that relied on non-managers reading user versions must declare `access.readVersions`.

### Patch Changes

- Updated dependencies [[`b718ac4`](https://github.com/jellologic/payload-auth-link/commit/b718ac4fe66266b28eb4decd895b0f15452bdbf5)]:
  - @payload-auth-link/core@0.8.0

## 0.4.1

### Patch Changes

- [#97](https://github.com/jellologic/payload-auth-link/pull/97) [`45e27c1`](https://github.com/jellologic/payload-auth-link/commit/45e27c1583563cad35197d7a772259053f2888d2) Thanks [@jellologic](https://github.com/jellologic)! - `revokeSession` on a database-session Auth.js engine now fails when no session matches the handle, instead of reporting success. `authLinkServer(payload).revokeSession` no longer stops at an Auth.js provider that revoked nothing, so a session held by another registered provider is still revoked.

## 0.4.0

### Minor Changes

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`93177a7`](https://github.com/jellologic/payload-auth-link/commit/93177a7ee4b9661675bcd4ff4f76bb9909e376c1) Thanks [@jellologic](https://github.com/jellologic)! - `revokeUserSessions` (database sessions — `authLinkServer.revokeAllForUser`
  on Auth.js) now fails loudly instead of reporting success while
  sessions stay alive: Payload's bulk delete resolves with per-row
  `errors` rather than rejecting, so a partial delete used to pass
  silently. The engine now throws when any row failed to delete, and
  re-counts the user's session rows afterwards and throws if any remain.

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`60deb7d`](https://github.com/jellologic/payload-auth-link/commit/60deb7db81c1a74c9a3b0bc5c60f52e4c61f0c79) Thanks [@jellologic](https://github.com/jellologic)! - Release and supply-chain hardening ([#85](https://github.com/jellologic/payload-auth-link/issues/85)).

  - Every package tarball now ships the MIT `LICENSE` (previously no
    tarball carried it).
  - Releases publish only after the full CI workflow passes on the exact
    commit, from a dedicated `npm-publish` environment, with npm
    provenance. Local publishing is refused outside an explicit,
    documented emergency override.
  - `@payload-auth-link/migrate`: the published `.d.ts` no longer
    references `pg`, so consumers type-checking with
    `skipLibCheck: false` no longer fail with TS7016 (no `@types/pg`
    needed). `openSource` and the source readers (`probeSourceLayout`,
    `countTables`, `readSourceUsers`, `readFlatRows`, `findOrphans`) now
    type their client as the new exported structural `SourceClient`
    (`query` + `end`); a `pg.Client` still satisfies it. Code that used
    `openSource()`'s result as a full `pg.Client` must narrow to those
    two methods or open its own `pg` client.
  - `@payload-auth-link/migrate`: the TypeScript compiler API is loaded
    lazily, only by the `codemod` command; importing the package or
    running `doctor`/import/export no longer loads it.

  Upgrade impact: none for stored data or schemas (no collection shape
  changed). Type-level only for `@payload-auth-link/migrate` API
  consumers, as described above.

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71) Thanks [@jellologic](https://github.com/jellologic)! - Harden the server-side session verifier's origin resolution.

  - `createSessionVerifier` now requires `baseUrl` (or an absolute `sessionEndpoint`) unless `NODE_ENV` is exactly `'development'`; unset, `test`, `staging`, `preview`, and `production` all throw `InvalidConfigError` at construction.
  - In development, the host fallback ignores `X-Forwarded-Host`/`X-Forwarded-Proto` unless the new `trustProxy` option is set, accepts only `http`/`https`, and only resolves to hosts in `allowedDevelopmentHosts` (default `localhost`, `127.0.0.1`, `[::1]`). Rejections fail closed and are reported through `onError`.
  - Protocol-relative and non-http `sessionEndpoint` values throw at construction (new `validateSessionEndpoint` export).
  - The verifier fetch aborts after `timeoutMs` (default 5000, new `defaultSessionVerifierTimeoutMs` export) and does not follow redirects; both fail closed.
  - `resolveSessionUrl`'s host fallback now defaults to off and takes a host policy; core's `resolveOrigin` gains `trustProxy` and `allowedHosts` and validates the scheme and host. The Auth.js engine keeps reading forwarded headers explicitly for its in-process session read.
  - `packages/next/README.md`: the middleware snippet resolves cookie names with `getBetterAuthSessionCookieNames` (so `__Secure-` names match on https) and ships a matcher.

  Upgrade impact: no schema change. Apps constructing a verifier without `baseUrl` outside `NODE_ENV=development` must pass `baseUrl`; dev setups behind a local proxy set `trustProxy: true` (and `allowedDevelopmentHosts` for non-loopback dev hosts). See `docs/upgrading.md`.

### Patch Changes

- Updated dependencies [[`60deb7d`](https://github.com/jellologic/payload-auth-link/commit/60deb7db81c1a74c9a3b0bc5c60f52e4c61f0c79), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71)]:
  - @payload-auth-link/core@0.7.0

## 0.3.5

### Patch Changes

- Updated dependencies [[`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94)]:
  - @payload-auth-link/core@0.6.2

## 0.3.4

### Patch Changes

- Updated dependencies [[`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe)]:
  - @payload-auth-link/core@0.6.1

## 0.3.3

### Patch Changes

- Updated dependencies [[`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c)]:
  - @payload-auth-link/core@0.6.0

## 0.3.2

### Patch Changes

- Updated dependencies [[`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c)]:
  - @payload-auth-link/core@0.5.0

## 0.3.1

### Patch Changes

- Updated dependencies [[`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008)]:
  - @payload-auth-link/core@0.4.0

## 0.3.0

### Minor Changes

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - `reconcileAuthJsMongoIndexes(payload)`: an idempotent one-time fix
  for upgraded MongoDB deployments. Payload's mongo adapter never
  drops indexes, so after the 0.1.1 → 0.2.x composite-token change
  the stale `token` unique index kept enforcing the old one-row-per-
  hash constraint, and the new `key` unique index built over rows
  without the field. The helper backfills `key`
  (`JSON.stringify([identifier, tokenHash])`), drops the stale
  `token` index, and reports the `key` index state ('created' |
  'present' | 'failed') without throwing while a build is in flight.
  Covered by the env-gated Mongo golden test; run it once per
  deployment after upgrading (see docs/upgrading.md).

  Upgrade impact: MongoDB only. Already upgraded without it? The
  composite-key behavior silently does not hold on your deployment
  until you run the reconciliation. Fresh installs need nothing.

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Version-range honesty (upgrade-resilience Phase 1): declared ranges
  now equal the CI-tested bands, and unvalidated upstreams fail at
  boot, typed, before any database write.

  - **`better-auth` and `@auth/core` are peer dependencies.** The
    providers no longer install them transitively; install the version
    you configure (validated bands: `better-auth >=1.7.6 <1.8.0`,
    `@auth/core >=0.41.0 <0.42.0`). Floors are bisected: BA 1.7.6
    (adapter `modelKey` types), @auth/core 0.41.0.
  - **`payload` peers tighten to `^3.83.0 || 4.0.0-beta.0`** (3.83.0
    is the named-plugin/global-hook floor; the v4 entry is the exact
    tested beta — canaries were silently inside the old caret). The
    plugin's runtime band matches the manifest.
  - **Framework peers get honest floors**: `next` `^15.0.0 || ^16.0.0`
    (both majors typechecked, 16.4 e2e-tested), TanStack Start
    `^1.140.2` (first `createMiddleware` types) with react-router
    `^1.170.0`.
  - **Runtime assertions at wiring time**: the providers check their
    upstream's installed version (`supportedBetterAuthBand`,
    `supportedAuthJsBand`, `assertBetterAuthVersion`,
    `assertAuthJsCoreVersion` exported; core adds
    `readInstalledVersion`) and throw `UnsupportedVersionError`
    before any collection write; unreadable manifests warn once and
    skip, never guess.
  - CI: a scheduled/dispatchable `compat` workflow proves
    {floor, latest} per upstream plus the golden Postgres/Mongo
    upgrade tests, with a non-blocking canary for drift; dependabot
    keeps installed versions moving as reviewed PRs.

  Upgrade impact: none for the database. Install-level: add explicit
  `better-auth` / `@auth/core` installs when adopting the providers
  (the READMEs show the lines); payload below 3.83.0 and prerelease
  payload canaries are no longer accepted. See docs/upgrading.md
  § 0.2.x → 0.3.0.

### Patch Changes

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Upgrade-safe collection shapes (upgrade-resilience Phase 0). Booting
  these versions on a database seeded by 0.1.1 no longer hangs,
  crashes, or destroys rows:

  - Auth.js: `aj-verification-tokens.key` is no longer DB-level
    `required` — it stays unique (NULLs tolerated by SQLite and
    Postgres) and is written and read by the adapter, backfilled
    lazily. Adding the column on push is an in-place ALTER, not a
    table rebuild; seeded tokens survive and stay consumable.
  - Better Auth: `ba-users.name` keeps its DB-level NOT NULL (the
    physical column is unchanged, so SQLite never rebuilds the table)
    while BA's `name: ""` writes are accepted via field-level
    validation.
  - Golden-DB upgrade tests now boot the 0.1.1 seed on current code
    in push and migrations modes on SQLite, Postgres, and MongoDB,
    in both upgrade and rollback directions.

  Upgrade impact: none for fresh installs. For 0.1.1 databases, see
  docs/upgrading.md § 0.1.1 → 0.2.0 — SQLite/Postgres push boots
  cleanly; migrations mode requires `key` nullable in the generated
  migration; MongoDB needs the one-time index reconciliation
  (`reconcileAuthJsMongoIndexes`, shipped alongside). No verification
  tokens are invalidated.

- Updated dependencies [[`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd), [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd)]:
  - @payload-auth-link/core@0.3.0

## 0.2.0

### Minor Changes

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Make Auth.js verification-token uniqueness composite on `(identifier, token)` instead of `token` alone: `aj-verification-tokens` gains a unique composite `key` field (the same pattern accounts already use) and `token` is no longer uniquely indexed by itself, so identical token hashes — for example two concurrent 6-digit email OTP codes for different addresses — can coexist, while creating the same `(identifier, token)` pair twice is rejected. `useVerificationToken` still looks up by identifier and token together and remains single-use, and rows written before the `key` field existed remain consumable. Hosts own the database migration for the new field, as with any collection change.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Add per-engine risky account-linking validation at wiring (CAP-12). Both engines gain `logger` and `strictLinking` options: risky settings log a loud `LoggerPort` warning naming the setting by default and throw `InvalidConfigError` under `strictLinking: true`. Better Auth flags `account.accountLinking.trustedProviders` entries without per-provider `requireEmailVerification` (including dynamic trusted-provider functions it cannot verify statically), `allowDifferentEmails: true`, `requireLocalEmailVerified: false`, and `updateUserInfoOnLink: true` — which the engine now also forces off so a link can never rewrite `email`/`emailVerified` in this composition. Auth.js flags any provider with `allowDangerousEmailAccountLinking: true` (the D6 trust combination still always throws). Payload linking keeps requiring a verified email either way.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - CAP-14 identity lifecycle foundation: core `IdentityEvent` union and
  `applyIdentityEvent` use-case. Verified provider email changes sync to
  Payload (D9); unverified changes are ignored. Provider unlink/delete
  removes only the identity row via the new required
  `UserRepository.unlinkIdentity` — the Payload user always remains.
  Adapters may expose `IdentityProviderPort.onIdentityEvent`; the plugin
  subscribes at `onInit`. Custom `UserRepository` implementations must
  add `unlinkIdentity` (pre-1.0 minor break for port implementers).

  Both provider adapters now translate lifecycle hooks: Better Auth
  `databaseHooks` (user update/delete, account delete; builder hooks
  preserved, plus `revokeSessionsOnPasswordReset` defaults on) and
  Auth.js `events` (`updateUser`, `linkAccount` — upstream never fires
  unlink/delete events, so Auth.js emits no unlink/delete facts).

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Add the `trustProviderEmailVerification` engine option (D6): an allow-list of OAuth/OIDC provider ids whose asserted `email_verified === true` stamps the adapter user's `emailVerified` through `updateUser`, so trusted OAuth sign-ups can pass the plugin's verified-email gate. Nothing is stamped by default, for non-allow-listed providers, or when `email_verified` is false/absent, and combining a trusted provider with `allowDangerousEmailAccountLinking` now fails fast with `InvalidConfigError`. Also exports `createAuthLinkEvents` and `AuthLinkTrustOptions`.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Capabilities Phases 3–7 (PLAN-CAPABILITIES): passwordless, OAuth,
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

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Core session vocabulary and declared capabilities (PORT-1/PORT-2):
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

### Patch Changes

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Impersonation audit hole closed (CAP-8a): Better Auth's
  `session.impersonatedBy` now reaches the port as the new optional
  `ProviderSession.actor` (`{ providerUserId }`, `null` for plain
  sessions; Auth.js always reports `null`), the plugin audit-logs every
  verified use of an impersonated session through `LoggerPort` with the
  operator and target ids, and plugin logout also expires Better Auth's
  `admin_session` cookie via the new optional `logoutCookieNames` port
  field (`getBetterAuthLogoutCookieNames`). All additions are optional
  and backward compatible.
- Updated dependencies [[`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4), [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4)]:
  - @payload-auth-link/core@0.2.0

## 0.1.1

### Patch Changes

- [#4](https://github.com/jellologic/payload-auth-link/pull/4) [`04f8e49`](https://github.com/jellologic/payload-auth-link/commit/04f8e49d79567d3e85b7d34cb91e840f7d9efd74) Thanks [@jellologic](https://github.com/jellologic)! - Packaging fixes found by verifying 0.1.0 from a clean consumer install:

  - next: `dist` imported `next/headers`, `next/navigation` and
    `next/server` without `.js`, so the adapter crashed under plain
    Node ESM (`ERR_MODULE_NOT_FOUND`). The imports now carry `.js`, and
    lint enforces it.
  - plugin: `@payload-auth-link/plugin/admin` imports `@payloadcms/ui`
    but never declared it. It is now an optional peer dependency (only
    the `/admin` subpath needs it, and Payload apps already have it).
  - all: compiled tests (`dist/**/__tests__`) no longer ship in the
    tarballs (0.1.0 `core` carried 56 test files).
  - all: every package now ships a README, so its npm page explains the
    package, install line with peers, exports, and guides instead of
    "No README data found!".

  This is the first release CI publishes through npm trusted publishing,
  with provenance.

- Updated dependencies [[`04f8e49`](https://github.com/jellologic/payload-auth-link/commit/04f8e49d79567d3e85b7d34cb91e840f7d9efd74)]:
  - @payload-auth-link/core@0.1.1

## 0.1.0

### Minor Changes

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085) Thanks [@jellologic](https://github.com/jellologic)! - Enterprise review hardening.

  Security fixes:

  - Logout now expires session cookies with their live attributes
    (`Secure`, `Domain`, `Path`) reported by each provider through the
    new optional `IdentityProviderPort.sessionCookieClearOptions` hook,
    so `__Secure-` and custom-domain cookies actually die. Providers
    that predate the hook fall back to prefix-derived attributes
    (`expiringCookieOptions`).
  - New `safeRedirectPath` guard in `@payload-auth-link/next`: the
    post-login `redirect` param is attacker-controlled input and must
    never reach the router unvalidated (open redirect).
  - New server authorization helpers `requireSessionUser` /
    `requireRoles` in `@payload-auth-link/next` (throw
    `SessionInvalidError` / `ForbiddenError` by default; pass
    `redirect()` / `notFound()` as handlers). `RequireRoles` is
    UI-hiding only and must never gate content.
  - Auth.js credentials `authorize` burns a dummy scrypt verification
    for unknown emails and hashless rows, closing the
    user-enumeration timing oracle.
  - Session reads anchor to the configured `baseUrl`/`AUTH_URL` origin
    whenever set; the request-host fallback is local-development only
    (host headers are client-spoofable and session cookies are
    forwarded to that origin).

  Strictness and consistency:

  - Better Auth `AdapterOperationError` now extends `AuthLinkError`
    (code `ADAPTER_OPERATION_FAILED`) like its Auth.js twin; it moved
    from `adapter.js` to `errors.js` (barrel import unchanged).
  - Slug overrides validate at wiring time in both providers
    (`resolveSlugs`: non-empty, known models) and collections reject
    slug collisions (`assertUniqueSlugs`), including custom-model
    slugs against core slugs; new `customModelSlug` helper.
  - Shared core building blocks replace nine local copies:
    `isRecord` / `isNonEmptyString` / `toDate` guards,
    `runProviderOperation` port-call wrapper, `denyAllAccess` system
    collection default, `secureCookiePrefix` / `hostCookiePrefix`
    constants. The Edge-safe `/cookies` subpaths keep local literals
    (runtime-import-free) pinned to core by tests.
  - `CookieOptions` gains `partitioned`; `SessionVerifier` is now a
    named export.

### Patch Changes

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8) Thanks [@jellologic](https://github.com/jellologic)! - Close the low-severity review backlog. Every change fails closed; see
  docs/upgrading.md.

  - core: `safeRedirectPath` moves to core with a destination policy
    that refuses the sign-in page and `/api` (`SafeRedirectOptions`).
    New exports: `isCookieName` and `SafeRedirectOptions`. Cookie
    `Domain`/`Path` values that could inject attributes or split
    headers throw. Provider registration rejects illegal session cookie
    names. `validateStartupConfig` drops the unused `secret`.
  - plugin: `secret` is deprecated and ignored. An empty provider
    session id is a 401, not a 500. Logout already sweeps every
    provider (PAR-7).
  - web: `requireRoles` validates its roles (`InvalidRoleError`, and
    `InvalidConfigError` for an empty list). It re-exports
    `SafeRedirectOptions`.
  - react: `SignOutButton` narrows `redirectTo`. `AuthLinkProvider`
    syncs a changed `initialUser` (value-compared, so a client sign-out
    is never undone by an equal snapshot).
  - next, tanstack-start: re-export the whole web surface through one
    shared statement, so adapters cannot drift (now includes
    `SafeRedirectOptions`).
  - provider-authjs: `authorize` lowercases the email. A corrupt
    `emailVerified` throws `AdapterMappingError`. Gapped session chunk
    sets are malformed.
  - provider-better-auth: adapter rows assert `baId` and date fields,
    and throw `AdapterOperationError` on storage drift.

- Updated dependencies [[`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085)]:
  - @payload-auth-link/core@0.1.0
