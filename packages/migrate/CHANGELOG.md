# @payload-auth-link/migrate

## 0.11.1

### Patch Changes

- [#129](https://github.com/jellologic/payload-auth-link/pull/129) [`6ee27be`](https://github.com/jellologic/payload-auth-link/commit/6ee27be17c014ebcb850694cac03bca07a46d6a8) Thanks [@jellologic](https://github.com/jellologic)! - Adopt mode can resolve guest (anonymous) sessions to their own document: `authLink({ admitAnonymous: true })` (issue [#126](https://github.com/jellologic/payload-auth-link/issues/126)).

  - **plugin** (new option): `admitAnonymous` lets an anonymous Better Auth session resolve to the guest's OWN host document in adopt mode (`idStrategy: 'payload'`, user model adopted) — payload-auth resolved guests, and apps built on it let guests own data through that document (`created_by`-style columns). The wiring refuses the option outside adopt mode. The resolved projection carries `anonymous: true` on `req.user` and on the session endpoint's JSON; the document's own roles govern `roles`. Guests are still never provisioned: a session whose row is gone is refused, not created.
  - **core**: `Session` and `SessionUser` gain the optional `anonymous: true` marker; `ensureLinkedUser` takes `admitAnonymous` and resolves the opted-in guest through the provider-owned-id link (adopt mode), refusing a missing row.
  - **migrate**: the doctor's `anonymous-users` warning and the "behaviour changes that will bite" list name the adopt-mode opt-in instead of leaving the refusal absolute.

- Updated dependencies [[`6ee27be`](https://github.com/jellologic/payload-auth-link/commit/6ee27be17c014ebcb850694cac03bca07a46d6a8)]:
  - @payload-auth-link/core@0.12.1
  - @payload-auth-link/next@0.8.2

## 0.11.0

### Minor Changes

- [#127](https://github.com/jellologic/payload-auth-link/pull/127) [`d7650b5`](https://github.com/jellologic/payload-auth-link/commit/d7650b579c67f6d1b7759bcac66006266a1b5d0f) Thanks [@jellologic](https://github.com/jellologic)! - The payload-auth → payload-auth-link journey ([#60](https://github.com/jellologic/payload-auth-link/issues/60)): adopt-mode sign-ups resolve, migration writes are tellable, the cookie shape matches the docs, and the admin panel keeps forgot/reset.

  - **plugin** (issue [#124](https://github.com/jellologic/payload-auth-link/issues/124)): in adopt mode (`idStrategy: 'payload'`, user model adopted), a user who signs up after the cutover now resolves to their own document on first request — the JIT link attaches the engine-created row by id (no email proof needed: nobody but the engine can mint a document with that id) and writes the identities row `adopt-prelink` writes for pre-cutover users; a new create hook normalizes the roles field (a scalar from Better Auth stores as the array shape, an absent value gets the default role). Before this, every post-cutover sign-up held a valid provider session with `req.user` null and no role.
  - **plugin** (issue [#121](https://github.com/jellologic/payload-auth-link/issues/121)): `admin: { loginView: 'provider' }` now ships `ProviderForgotPasswordView` and `ProviderResetPasswordView` — the same flag registers all three provider views, driving the provider's own reset flow, so linked admins keep a forgot/reset path after moving off payload-auth (payload-auth injects those views; Payload's local flow stays refused for linked docs by design). One honest residual: Payload's router hard-codes the two-segment `/admin/reset/:token` screen (v3 and v4-beta), so the reset view serves `/admin/reset?token=…` — which the forgot view's redirect sets, and ProviderLoginView links to the forgot view.
  - **plugin/core** (issue [#125](https://github.com/jellologic/payload-auth-link/issues/125)): `authLinkServer.sessionCookie(token)` returns the signed VALUE `token.<signature>` as documented (it returned a whole `Set-Cookie` line, which never verifies in a request `Cookie` header); the full line for responses stays on `createSessionFor(...).setCookie` and the provider port's new `sessionCookieLine`.
  - **migrate** (issue [#123](https://github.com/jellologic/payload-auth-link/issues/123)): every host write the kit makes (`--apply`, `adopt-prelink --apply`, rollback restores) carries `context: { [MIGRATION_CONTEXT]: { op } }`, so host hooks can skip outbound side effects (CRM, email, webhooks, indexing); the doctor warns when the users collection declares such hooks.
  - Breaking-with-the-docs note for engine users: a wrong-password `sign-in/email` through the Better Auth engine answers 400 `INVALID_EMAIL_OR_PASSWORD` (payload-auth's local strategy answered 401).

  `Upgrade impact:` no database schema change. The regenerated
  `snapshots/schema/plugin-users.json` diff is the users collection's
  hook array gaining the roles-normalizing `beforeChange` hook — no
  field, column, or index changes — so `payload push` and generated
  migrations have nothing to do on SQLite, Postgres, or MongoDB.
  Operators on adopt mode get the fix on upgrade with no data steps;
  hosts whose users-collection hooks inspect `req.context` can skip
  migration writes via `@payload-auth-link/migrate`'s exported
  `MIGRATION_CONTEXT` key.

### Patch Changes

- Updated dependencies [[`d7650b5`](https://github.com/jellologic/payload-auth-link/commit/d7650b579c67f6d1b7759bcac66006266a1b5d0f)]:
  - @payload-auth-link/core@0.12.0
  - @payload-auth-link/next@0.8.1

## 0.10.0

### Minor Changes

- [#120](https://github.com/jellologic/payload-auth-link/pull/120) [`6e31a18`](https://github.com/jellologic/payload-auth-link/commit/6e31a1885dcead23129dfdc7e9dec82a13bdd272) Thanks [@jellologic](https://github.com/jellologic)! - Re-validation follow-ups (issue [#119](https://github.com/jellologic/payload-auth-link/issues/119)): the doctor closes its last blind spot, and two refusals read straight.

  - **The doctor blocks on a missing `payload_kv` table** (`payload-kv-table-missing`): a production database whose app never ran the Payload migration creating Payload's key-value store passed every other check and surfaced only as an `--apply`-time refusal. When the config under inspection installs payload-auth-link (the database `--apply` writes to) and the table is absent, the doctor now names it up front, with the fix (`payload migrate`).
  - **Rollback refusals name the flag's source**: a manifest marked `finalized` is refused with "the manifest is marked finalized (the finalize command writes that flag into the manifest file)" instead of the ambiguous "the migration is finalized" — the refusal was always correct, but an operator who never ran finalize could not tell where the mark came from.
  - `finalize failed:` gained its missing space, matching every other command's error prefix.

## 0.9.0

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
  - @payload-auth-link/next@0.8.0

## 0.8.0

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
  - @payload-auth-link/next@0.7.0

## 0.7.0

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
  - @payload-auth-link/next@0.6.0

## 0.6.0

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
  - @payload-auth-link/next@0.5.0

## 0.5.0

### Minor Changes

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`a01ac10`](https://github.com/jellologic/payload-auth-link/commit/a01ac10ddb12338ea46203118c16ca6c2257dedf) Thanks [@jellologic](https://github.com/jellologic)! - Fixes from the real-data payload-auth → payload-auth-link rehearsal (issue [#88](https://github.com/jellologic/payload-auth-link/issues/88)).

  **provider-better-auth** — `authLinkServer(payload).verifyApiKey` resolves valid `@better-auth/api-key` 1.7.x keys. The satellite names the owner `referenceId`; the port demanded `userId` and threw "key block is missing its user id" for every valid key. `referenceId` is read first, `userId` is the fallback.

  **plugin** — a provider verification of the address a linked user ALREADY carries (the post-import verification) now grants the bound linking proof (`linkable` + `linkableEmail`); it used to change nothing. New `emailVerifiedField` option names a host checkbox (e.g. payload-auth's `emailVerified`) the plugin sets `true` on that verification; it must be a checkbox declared on the users collection (wiring throws otherwise).

  **migrate**

  - Every command prints and terminates: `from-payload-auth`, `verify`, `rollback`, and `finalize` log their outcome (`--json` prints one JSON document), and the booted Payload is destroyed with its Postgres pool closed — `@payloadcms/db-postgres` leaks a checked-out client that kept the CLI alive forever.
  - Rollback is exact after any number of `--apply` passes: only the FIRST captured prior value per field is kept, `users.updated_at` is restored, and rollback resets the manifest so a re-apply starts fresh. Plan totals are per pass and no longer double.
  - The manifest stores no email in the clear: prior values are sealed with AES-256-GCM under the app's `PAYLOAD_SECRET` (manifest version 2; version-1 manifests still roll back), and the file is written mode 0600.
  - `verify` scopes the session check to imported rows: sessions created after cutover and expired imported sessions Better Auth cleaned up are reported, not failed.
  - The importer carries Better Auth admin/anonymous state (`banned`, `banReason`, `banExpires`, `role`, `isAnonymous`) when the target declares those plugins, and refuses the run when a banned/anonymous user's state cannot be held. Row `createdAt`/`updatedAt` carry for accounts, sessions, verifications, API keys, jwks, orgs, members, and invitations.
  - New `adopt-prelink` command (dry run by default, `--apply` + manifest, undone by `rollback --manifest`): one `better-auth` identity per adopted user plus the verified-email linking proof — the step adopt mode needed but did not ship.
  - Doctor: no false `injected-field-collision` on a target config where the plugin is already installed; flags banned users, anonymous users (blockers when the target cannot hold them), `oauth_*` tables (not carried), and `genericOAuth` providers.

  Upgrade impact: none on shipped collection shapes — no `ba-*` or plugin-injected users field changed (the bans/anonymous fields come from Better Auth's own plugins via `autoDeclare` when you declare them). Operators: run `rollback` with the same `PAYLOAD_SECRET` that ran `--apply`; delete the manifest after `finalize` and your soak window.

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

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`0adba41`](https://github.com/jellologic/payload-auth-link/commit/0adba4178662fb899760cf3708b548ba7874fb36) Thanks [@jellologic](https://github.com/jellologic)! - Close open write defaults on the users collection: with no host-declared access, `update` is now self-or-role-manager and `delete` is role-manager only (never while impersonating), instead of Payload's "any signed-in user". The injected email field lets a non-manager change only their own address, even under a broader host `update`. `migrate export --out` and import manifests are written owner-only (0600) before content lands; sealed manifest values are bound to their entry and rollback restores only the fields the kit writes. `validateSessionEndpoint` rejects whitespace and control characters.

  Upgrade impact: no schema change. Hosts that relied on any signed-in user updating or deleting other users must declare that access explicitly; see docs/upgrading.md.

### Patch Changes

- Updated dependencies [[`60deb7d`](https://github.com/jellologic/payload-auth-link/commit/60deb7db81c1a74c9a3b0bc5c60f52e4c61f0c79), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71)]:
  - @payload-auth-link/core@0.7.0
  - @payload-auth-link/next@0.4.0

## 0.4.3

### Patch Changes

- Updated dependencies [[`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94)]:
  - @payload-auth-link/core@0.6.2
  - @payload-auth-link/next@0.3.4

## 0.4.2

### Patch Changes

- [`e09d20c`](https://github.com/jellologic/payload-auth-link/commit/e09d20c10e25c038628c896e601e5d09cc2ca8b6) Thanks [@jellologic](https://github.com/jellologic)! - The importer fails fast on the wrong config, and the doctor's signal is clean (issue [#75](https://github.com/jellologic/payload-auth-link/issues/75), from the real-data re-verification).

  - **The importer refuses configs that declare no payload-auth-link target collections BEFORE booting** — an untouched payload-auth app's config has no `ba-*` collections to write to, and the failed run used to park forever on the boot's live database pool (0% CPU, no output, never exits). It now refuses at the config-module read with the fix in the message, the Payload boot runs under a 120s watchdog, and a failed CLI exits the process outright. The guide states plainly that the importer runs against the TARGET config.
  - **Doctor plugin detection requires a Better Auth import and skips test files**: a security-tail test mentioning `mcp(` no longer blocks the doctor (the app used Payload's own MCP plugin), and `admin(` in prose or another package's API is noise, not a plugin. The unverified-users warning now matches the imported-identity semantics ([#69](https://github.com/jellologic/payload-auth-link/issues/69)): imported unverified users are pre-linked and resolve on their next sign-in after verifying — no operator action required.
  - **Node parity**: vitest inlines the CSS-bearing `@payloadcms/ui` chain and stubs CSS (an externalized `react-image-crop` stylesheet crashed some Node runtimes with `Unknown file extension ".css"`), and CI adds a Node 20/22/24 matrix running the suite under each runtime.

  Upgrade impact: none stored — the pre-flight runs before any database access; CLI behavior on an untouched config changes from an indefinite hang to a fast named failure with exit 1.

## 0.4.1

### Patch Changes

- Updated dependencies [[`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe)]:
  - @payload-auth-link/core@0.6.1
  - @payload-auth-link/next@0.3.3

## 0.4.0

### Minor Changes

- [#73](https://github.com/jellologic/payload-auth-link/pull/73) [`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c) Thanks [@jellologic](https://github.com/jellologic)! - The migration kit fails closed, matches real payload-auth layouts, and links imported users so they can actually sign in (issues [#68](https://github.com/jellologic/payload-auth-link/issues/68)–[#71](https://github.com/jellologic/payload-auth-link/issues/71), found running the kit against a production payload-auth database with custom slugs and 17% unverified users).

  - **Fail-closed source layout ([#68](https://github.com/jellologic/payload-auth-link/issues/68)).** The importer, `verify`, the exporter and the doctor no longer hardcode payload-auth's default table names or skip missing tables silently: a missing expected table or column is a blocker (exit 1, nothing written) naming the table and the new `--source-map '{"accounts":"user_accounts","sessions":"user_sessions"}'` override. `verify` is strict — exact per-model equality, zero never skips, extra target rows fail — and the api-key orphan check probes `reference_id` (better-auth's real column) with a `user_id` fallback. `export --tables` reports missing tables and exits non-zero instead of exporting a lossy "lossless" file.
  - **Imported users can sign in ([#69](https://github.com/jellologic/payload-auth-link/issues/69)).** The importer pre-links every imported user (verified or not, credential-only included) with `{ providerId: 'better-auth', providerUserId: <their ba-users id> }` — the identity the plugin actually looks up — so a user who verifies after the import resolves to their original document instead of being stranded. The verification gate still governs `linkable` proofing; `verify` now checks every imported user's identity resolves.
  - **Codemods match real usage ([#70](https://github.com/jellologic/payload-auth-link/issues/70)).** Rewritten on the TypeScript compiler API: `getPayloadAuth` from `'payload-auth'` or `'payload-auth/better-auth'` with any argument, `getSession({ headers: … })` in any shape, aliased imports, `import type` — and every reference the rules cannot rewrite is reported under manual follow-up (nothing silently ignored). `typescript` is now a regular dependency.
  - **The doctor runs where people will use it ([#71](https://github.com/jellologic/payload-auth-link/issues/71)).** `better-auth` is no longer a peer (installing the kit no longer upgrades the app's better-auth and breaks it); an unloadable config becomes a `config-unloadable` blocker with a static-analysis report instead of a crash (including the mid-upgrade `oidcProvider` state); plugin detection scans the whole `--src` tree (admin, anonymous, magicLink, nextCookies, genericOAuth, …) and names files; CLI errors are prefixed with the command name.

  Upgrade impact: none stored — source tables are read, never written. Behavior: runs that silently imported zero credential accounts from custom-slug layouts now abort with the exact fix in the message; re-run `doctor`, then the importer with `--source-map` if your slugs differ. `codemod --write` now persists rewrites for the patterns it actually matches.

### Patch Changes

- Updated dependencies [[`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c)]:
  - @payload-auth-link/core@0.6.0
  - @payload-auth-link/next@0.3.2

## 0.3.1

### Patch Changes

- [#66](https://github.com/jellologic/payload-auth-link/pull/66) [`a23a0c6`](https://github.com/jellologic/payload-auth-link/commit/a23a0c6a793ebc7d5b933780b3f6f4191b791bcf) Thanks [@jellologic](https://github.com/jellologic)! - The migrate CLI's `codemod --write` now writes the rewritten content to disk — it previously wrote the original file back, so `--write` reported the files as rewritten while changing nothing. `codemod`, `export` and `finalize` also no longer require `--config`, matching their documented usage (`codemod` needs `--src`, `export` needs `--database-url`, `finalize` is manifest-only).

  Upgrade impact: none — schema, options, and the programmatic `applyCodemods` result gain an additive `after` field only. CLI users running `codemod --write` get the rewrite they were promised; no stored data is touched.

## 0.3.0

### Minor Changes

- [`8d2dfc4`](https://github.com/jellologic/payload-auth-link/commit/8d2dfc4b9aef0c57c8f84ba6f39d82bd9a9ea2dd) Thanks [@jellologic](https://github.com/jellologic)! - Codemods + temporary `payload.betterAuth` compatibility shim (issue [#53](https://github.com/jellologic/payload-auth-link/issues/53)).

  `bunx @payload-auth-link/migrate codemod --src ./src` rewrites the
  named payload-auth call-site patterns (`getPayloadAuth()`,
  `payload.betterAuth.api.getSession({ headers })`,
  `toNextJsHandler(payload.betterAuth)`) and reports what needs a human
  decision — nothing is half-rewritten. Dry run by default; `--write`
  rewrites.

  `createBetterAuthCompatShim(payload)` is the opt-in
  `payload.betterAuth`-shaped accessor backed entirely by the supported
  server API — same suspension gate, same MFA projection, same audit
  sink, no back door — with one deprecation warning per process. The
  doctor counts remaining shim call sites.

- [`a7bf621`](https://github.com/jellologic/payload-auth-link/commit/a7bf62112ae818d6c287d4dbe809aac51f92c08f) Thanks [@jellologic](https://github.com/jellologic)! - Off-ramp (issue [#58](https://github.com/jellologic/payload-auth-link/issues/58)): `bunx @payload-auth-link/migrate export
--database-url URL [--out file.jsonl]` exports every auth table
  losslessly as JSONL — every column (plugin-injected fields,
  credential hashes, role child rows) typed as stored, re-importable
  without transformation. The uninstall path is a supported operation
  with a CI-validated test (plugin removed → users/content intact on
  the same database) and documentation of every plugin-injected field.

### Patch Changes

- Updated dependencies [[`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c)]:
  - @payload-auth-link/core@0.5.0
  - @payload-auth-link/next@0.3.1

## 0.2.0

### Minor Changes

- [#62](https://github.com/jellologic/payload-auth-link/pull/62) [`dd8f6a5`](https://github.com/jellologic/payload-auth-link/commit/dd8f6a54e50fc0f6f83ca04c75a860a34226b141) Thanks [@jellologic](https://github.com/jellologic)! - New package: the migration kit's CLI, starting with the read-only
  `doctor` preflight (issue [#52](https://github.com/jellologic/payload-auth-link/issues/52)).

  ```sh
  bunx @payload-auth-link/migrate doctor --config ./src/payload.config.ts --src ./src
  ```

  Reports version bands, Better Auth plugin support, users-collection
  collisions and role values, the 0.7.0 behaviour changes that bite,
  source call sites that must migrate, and (with a database URL) row
  counts, unverified users, and orphans. `--json` + exit codes
  (`0` clean / `1` blockers / `2` warnings / `3` usage) make it CI-able;
  every finding carries a stable machine code. See
  docs/migrating-from-payload-auth.md ("Step 0: run the doctor").

- [#63](https://github.com/jellologic/payload-auth-link/pull/63) [`e7baac6`](https://github.com/jellologic/payload-auth-link/commit/e7baac6472dcd08f04156c07b0b9af4d0bcb5de2) Thanks [@jellologic](https://github.com/jellologic)! - The runnable, reversible importer (issue [#50](https://github.com/jellologic/payload-auth-link/issues/50)):
  `bunx @payload-auth-link/migrate from-payload-auth`.

  Dry run by default (planned counts per model, unmappable rows,
  unverified users); `--apply` copies users, credential accounts (hashes
  verbatim), OAuth tokens, verifications, API keys, jwks and the
  organization plugin's rows into the payload-auth-link collections,
  granting `linkable`/`linkableEmail` from VERIFIED emails only and —
  with the default `--sessions=carry` — carrying the session table so
  nobody is logged out. Every created row and field change lands in the
  manifest; `verify` checks both sides (non-zero exit on any mismatch),
  `rollback` undoes exactly the manifest, `finalize` marks the point of
  no return. Idempotent and resumable; the source tables are never
  modified.

  `Upgrade impact:` none — the CLI is additive and the source tables stay
  untouched until you drop them yourself after `finalize`.
