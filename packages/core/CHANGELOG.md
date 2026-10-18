# @payload-auth-link/core

## 0.11.0

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

## 0.10.0

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

## 0.9.0

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

## 0.8.0

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

## 0.7.0

### Minor Changes

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

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71) Thanks [@jellologic](https://github.com/jellologic)! - Web-layer fixes (issue [#87](https://github.com/jellologic/payload-auth-link/issues/87)).

  - `safeRedirectPath` resolves dot segments (including percent-encoded ones) before the API-prefix and sign-in checks and returns the normalised path, so `/x/../api/...` and `/./sign-in` fall back.
  - `AuthLinkProvider` sequences session reads: only the newest read writes state, and `signOut` aborts in-flight reads so a late response can no longer restore a signed-out session. `fetchSession` accepts an optional `AbortSignal`.
  - Logout (`DELETE /api/auth-link/session`) also expires Better Auth's `dont_remember` and cookie-cache `session_data` cookies, the `__Secure-`/plain counterpart of each name, and the configured `legacySessions` names (`getBetterAuthLogoutCookieNames` returns the additional names).
  - A logout presenting no session cookie and no `Authorization`/`x-api-key` header answers without querying any provider (same idempotent response, cookies still expired).
  - The provider admin login view derives its break-glass endpoint (`${routes.api}/${usersCollection}/login`) and post-login destination (`routes.admin`) from the Payload config; new `admin.signInPath` and `admin.authBase` plugin options cover the app sign-in link and the Better Auth mount.
  - Docs: `__Host-` cookie setup for single-host deployments.

  Upgrade impact: no schema change, no push or migration needed on any adapter. Operators with a non-default sign-in page or Better Auth mount set `admin.signInPath` / `admin.authBase`. See `docs/upgrading.md`.

## 0.6.2

### Patch Changes

- [#81](https://github.com/jellologic/payload-auth-link/pull/81) [`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94) Thanks [@jellologic](https://github.com/jellologic)! - Better Auth's native sign-in flows record their authentication method, and session ids become opaque handles (issues [#79](https://github.com/jellologic/payload-auth-link/issues/79) and [#80](https://github.com/jellologic/payload-auth-link/issues/80)).

  - **`requireMfaForRoles` works through Better Auth's own 2FA again ([#79](https://github.com/jellologic/payload-auth-link/issues/79)).** 0.10.1's assurance read the per-session `authenticationMethod` column, but only server-side mints wrote it — a user completing BA's native two-factor sign-in got `mfa: 'unknown'` and their MFA-gated role stayed withheld. The provenance plugin now stamps the method on every recognized sign-in flow (`password`, `two-factor` on the verification endpoints, `oauth` callbacks, `magic-link`, `email-otp`, `passkey`); BA's 2FA-pending sign-in expires the session cookie, so a single-factor session is never relabelled — the second factor issues a FRESH session recorded as `two-factor`. Unknown paths still record nothing (fail closed).
  - **Session ids are opaque handles, never bearer tokens ([#80](https://github.com/jellologic/payload-auth-link/issues/80)).** `listSessions` and `createSessionFor().sessionId` return the session row id instead of the raw token — a devices page could otherwise expose one live credential per session into page data, logs, and error reports. `revokeSession` resolves the handle server-side and keeps its verified-deletion semantics; BA's own logout internals (which revoke by token) are unaffected. `createSessionFor().token` and `sessionCookie(token)` are unchanged — the token still rides exactly where setting the cookie needs it.

  Upgrade impact: no stored data changes (the column exists since 0.10.1). Behavior: MFA-gated roles through BA's native 2FA are restored without a custom step-up route; consumers that treated `listSessions` ids as tokens must switch to the opaque handles (revocation accepts both shapes).

## 0.6.1

### Patch Changes

- [`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe) Thanks [@jellologic](https://github.com/jellologic)! - The server session API is hardened: minted sessions carry explicit, recorded assurance; one id type across mint/list/revoke with verified deletion; the requested TTL is honored and the stored expiry audited; `'dev-only'` means development.

  - **Assurance reads a per-session record, not an enrollment flag.** The engine appends an internal Better Auth plugin adding one nullable `authenticationMethod` session field; mints record `server-mint` (no 2FA challenge ran — `mfa: false`), a server-vouched step-up records `server-step-up` (`mfa: true`). The old read leaned on `user.twoFactorEnabled`, so every mint for a 2FA-enrolled user claimed a second factor that never ran. Sign-in sessions without a recorded method report `mfa: 'unknown'`, which the MFA gate treats as absent (fail-closed) — restore gated roles via `createSessionFor(userId, { mfaProof: true })`, only where the server verified the second factor itself. `authLinkServer.sessionCookie`/`createSessionFor().setCookie` unchanged in shape.
  - **`revokeSession` consumes the ids `listSessions` and `createSessionFor` hand out** (the session token — previously they returned row ids while revocation deleted by token, so revokes deleted nothing and reported success), and is verified: an id with no session behind it, or a delete that leaves the row in place, is an error.
  - **Mint TTL honored and audited honestly.** The expiry was landing in Better Auth's `dontRememberMe` slot (every mint got ~24h regardless of the request, with the audit recording the requested value as if stored); it now goes through Better Auth's `override`, and the audit event and returned `expiresAt` carry the STORED expiry (`createSessionFor` result gains nothing breaking; providers report `storedExpiresAt`).
  - **`'dev-only'` (the `allowServerSessions` default) enables minting ONLY on `NODE_ENV === 'development'`** — previously on everything except `'production'`, which silently armed minting in CI, test and staging.

  Upgrade impact: the engine's session table gains one additive, nullable column through Better Auth's own schema machinery — run the usual Payload push/migrations; no data changes. Behaviour: MFA-gated roles are withheld for sessions with no recorded method until a `mfaProof` mint or a method-recording flow; `'dev-only'` now refuses minting outside development (set `allowServerSessions: true` explicitly). CI/test code that relied on the old default must opt in.

## 0.6.0

### Minor Changes

- [#73](https://github.com/jellologic/payload-auth-link/pull/73) [`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c) Thanks [@jellologic](https://github.com/jellologic)! - The server-session API's cookie is actually signed, and the server API is stricter about providers (issues [#68](https://github.com/jellologic/payload-auth-link/issues/68)–[#72](https://github.com/jellologic/payload-auth-link/issues/72) correctness pass, found in the first production rehearsal).

  - **`sessionCookie(token)` now returns `Promise<string>`** on `authLinkServer(payload)` and the provider port, and emits Better Auth's SIGNED form (`token.<HMAC>` — BA reads the session cookie with `getSignedCookie` only, so 0.9.0's raw-token cookie resolved no session). The cookie is built from the engine's own resolved context: secret, cookie name, and the real `Secure`/`SameSite`/`Path`/`Max-Age` attributes. `createSessionFor().setCookie` carries the signed value; await the call.
  - **`revokeAllForUser` and `listSessions` walk every linked provider**, not just the first capable identity — with two linked providers, the second provider's sessions were neither listed nor revoked.
  - **`sessionCookie(token)` refuses ambiguity**: with several cookie-transport providers registered it throws instead of silently signing with the wrong one (`createSessionFor` remains the unambiguous path).
  - **`legacySessions` on the plugin now enforces agreement** with the engine's window at config time (`InvalidConfigError` on missing, disagreeing, or colliding windows; engine-only configuration stays legal — the engine input is what acts).
  - **`admin: { loginView: 'provider' }` renders**: the registration gains its `exportName` and the view signs in through Better Auth's `POST /sign-in/email` (the old `/api/auth/sign-in` link was never a route), with a two-factor-aware response and a path for social-only accounts. Requires a cookie-transport provider (config-time error otherwise), and **apps enabling it must regenerate the Payload import map** (`payload generate:importmap`).

  Upgrade impact: type-level — `await sessionCookie(…)` at call sites; behavior-level — hosts that set only the plugin's `legacySessions` option must move the window to the engine input (the plugin option now asserts it); hosts using `loginView: 'provider'` regenerate the import map. No collection shapes change; no stored data is touched.

## 0.5.0

### Minor Changes

- [`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c) Thanks [@jellologic](https://github.com/jellologic)! - Supported server session API (issue [#54](https://github.com/jellologic/payload-auth-link/issues/54)): `authLinkServer(payload)` —
  `getSession` (same rules as the strategies), `createSessionFor` (audited,
  refused for suspended users, gated by `allowServerSessions`:
  `'dev-only'` default | `true` | `false`), `listSessions`,
  `revokeSession`, `revokeAllForUser`, `verifyApiKey`, and
  `sessionCookie` — so apps never touch Better Auth internals or
  hand-sign cookies. Provider capability-gated (`server-session-create`,
  `server-session-list`, `api-key-verify`); Better Auth implements all
  three, Auth.js reports none and the server API refuses with typed
  errors. `Upgrade impact:` none — additive.

## 0.4.0

### Minor Changes

- [#28](https://github.com/jellologic/payload-auth-link/pull/28) [`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008) Thanks [@jellologic](https://github.com/jellologic)! - The plugin is audible by default (issue [#15](https://github.com/jellologic/payload-auth-link/issues/15)): `authLink({ logger })`
  now defaults to a **console logger** instead of the silent one, so
  session refusals (expired, channel not admitted, suspended,
  provider errors, a session-shaped cookie that resolves to nothing)
  and the impersonation audit actually land somewhere without
  configuration. `nullLogger()` remains the explicit opt-out.

  - Core adds `consoleLogger()` (info/warn/error to the matching
    console level, fields as a JSON suffix, debug stays silent) and
    `isSilentLogger()`.
  - New `onAudit` option: a durable sink called with every
    impersonation audit event, in addition to the logger — "audited"
    should survive log rotation. With an impersonation-capable
    provider, a silent logger, and no `onAudit`, the plugin warns once
    at startup through the console that audit events are being
    dropped.
  - The per-request "verification failed: invalid session" residue
    (every anonymous request) moved to debug level; every actionable
    refusal keeps its warning with reason, provider, and channel.
  - README's impersonation row now says what auditing means.

  Upgrade impact: default-behaviour change — servers will print
  warnings for refused sessions by default. Pass
  `logger: nullLogger()` to restore silence; pass `onAudit` to make
  the impersonation audit durable.

## 0.3.0

### Minor Changes

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

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Type-safe upgrade alarms and schema interoperability (upgrade-resilience Phase 3b):

  - Core: `authMethods` exported as the single source for `AuthMethod` and the session wire enum; `sessionChannels` is now a const tuple with `SessionChannel` derived from it; `LinkingPolicy` derives from `linkingPolicySchema`. Union/schema drift now fails typecheck instead of degrading sessions at runtime.
  - Core: `parseSessionUser` accepts `ParseSessionUserOptions.onDegrade` with a typed `SessionUserDegradeReason`, so producer/consumer version skew (e.g. an unknown auth method from a newer server) is observable instead of silent. Default behavior is unchanged.
  - Core: every exported Zod schema is pinned as a Standard Schema v1 (`@standard-schema/spec` added); Zod and Effect Schema compose through `~standard`. Effect interop is covered by a CI test with `effect` as a devDependency only. The `zod: ^4.0.0` floor and a consumer TypeScript floor of 5.5 are now probe-proven and documented.
  - Plugin: stored-row mapping warnings aggregate once per kind per logger instead of once per corrupt row.
  - Better Auth provider: exhaustive `assertNever` guards on custom-field types and where operators, so new upstream variants fail CI typecheck.
  - Repo gates: public-API `.d.ts` snapshots (`bun run api:check`) and a `skipLibCheck: false` consumer fixture (`bun run consumer:check`) now run in `bun run check`.

## 0.2.0

### Minor Changes

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Channel admission (CAP-13a) and impersonation completion (CAP-8b).

  - The plugin gains `admitChannels` (default `['cookie']`): a live
    provider session presented on a non-admitted channel (`bearer`,
    `api-key`, `device`) is refused at verification with the new typed
    `ChannelNotAdmittedError` (401) before any linking, and
    verification stops at the presenting provider. Channels are
    observed, not asserted: Better Auth reports `'bearer'` when the
    session arrives via an `Authorization: Bearer [REDACTED]` header without
    the session cookie (denied by the default policy), and Auth.js
    reports `'cookie'` because it only reads cookie-presented
    sessions. CSRF is unchanged in this phase.
  - `Session.actor` / `SessionUser.actor` are now the resolved
    `ResolvedSessionActor` discriminated union: `payload-user` (with
    the operator's Payload `userId`, resolved through
    `UserRepository.findByProviderIdentity`) or `provider-only` (no
    linked Payload user — fail-closed: still audited and restricted,
    never presented as a Payload id, logged as a warning).
    `parseSessionUser` accepts the legacy `{ providerUserId }` form
    and normalizes it to `provider-only`; `ProviderSession.actor`
    keeps the provider form.
  - Every authenticated Payload collection/global operation performed
    while impersonating is audit-logged through `LoggerPort`
    (`impersonated operation`: actor, target, operation,
    collection/global, document id) via plugin-installed
    `beforeOperation` hooks, so denied attempts are audited too.
  - Default impersonation restrictions (D5): the plugin denies
    admin-panel access and roles-field writes on the users collection
    while an actor is present (reads allowed), and exports
    `denyWhileImpersonating(ops?)`, the fail-closed
    `isImpersonating(req)` / `impersonationStateFromRequest(req)`
    server extraction (a present-but-malformed `actor` still denies
    and audits; authorization never routes through the client wire
    parser), plus `impersonationActorFromRequest` for attribution, so
    builders can apply the same default — deny admin and writes,
    allow reads — to their own collections.

  See `docs/upgrading.md`.

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

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Impersonation audit hole closed (CAP-8a): Better Auth's
  `session.impersonatedBy` now reaches the port as the new optional
  `ProviderSession.actor` (`{ providerUserId }`, `null` for plain
  sessions; Auth.js always reports `null`), the plugin audit-logs every
  verified use of an impersonated session through `LoggerPort` with the
  operator and target ids, and plugin logout also expires Better Auth's
  `admin_session` cookie via the new optional `logoutCookieNames` port
  field (`getBetterAuthLogoutCookieNames`). All additions are optional
  and backward compatible.

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

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Generalized linking policy (PORT-3): core adds a declared
  `LinkingPolicy` discriminated union (`verified-email`, the default,
  plus opt-in `verified-email-or-phone`) with `defaultLinkingPolicy`, a
  strict `linkingPolicySchema`, and `parseLinkingPolicy`.
  `ensureLinkedUser` accepts an optional `linkingPolicy`; omitted or
  `verified-email` preserves the previous verified-email behavior
  exactly. The opt-in branch links a phone-only identity carrying a
  verified phone claim to an _existing_ user resolved through the new
  optional `UserRepository.findByPhone` port method — it never
  provisions, and every phone-only refusal is
  `UnverifiedIdentityError`. Anonymous identities never link under any
  policy — intentionally including when the identity was previously
  linked (D3): the anonymous gate runs before the already-linked fast
  path, so an anonymous session for a linked identity is refused, not
  verified. The plugin accepts a validated `linkingPolicy` option and
  passes it through to the session service; `verified-email-or-phone`
  additionally requires every registered provider to declare the
  `'phone'` capability (PORT-2 `assertCapabilities`, enforced at
  wiring) and currently fails fast at wiring because the Payload users
  collection has no phone field (and the repository no `findByPhone`)
  until CAP-9.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Session wire contract gains optional facts (PORT-4): plugin-level
  `Session` and the `SessionUser` wire shape now carry optional
  `assurance` (`methods`/`mfa`), `actor` (`{ providerUserId }`, only
  while impersonating), and `organizationId` (only when a
  provider-native tenant is active). The plugin projects them from the
  provider session onto the session endpoint response and the Payload
  auth strategy user; the web verifier and `require*` helpers and the
  React provider pass them through. Back-compatible by construction:
  payloads without the fields still parse, producers omit a field
  unless it is known, and a reported `assurance` serializes even when
  its values are `'unknown'` — consumers must treat absent and
  `'unknown'` alike as not satisfied (fail closed). The client wire
  parser is forward-compatible: unknown keys inside
  `assurance`/`actor` are ignored and a present-but-malformed
  optional degrades fail-closed-for-policy (`assurance` to
  `'unknown'`, `actor`/`organizationId` to absent) instead of failing
  the whole user, while core identity fields stay strict. Server-side
  authorization/audit never use that parser: the plugin's fail-closed
  server extraction treats a present-but-malformed `actor` on
  `req.user` as impersonating (deny + audit). See `docs/upgrading.md`.

- [#12](https://github.com/jellologic/payload-auth-link/pull/12) [`2eced30`](https://github.com/jellologic/payload-auth-link/commit/2eced3044f96a02bbc0f57f61345a958054030f4) Thanks [@jellologic](https://github.com/jellologic)! - Add the provider conformance kit at the new test-only subpath export `@payload-auth-link/core/testing` (PORT-5): `assertProviderConformance` / `checkProviderConformance` take a port factory plus scenario drivers and assert session-shape narrowing and verified-claim semantics (including the deprecated `email`/`emailVerified` aliases matching the claim), declared capabilities matching behavior (`revokeUserSessions` exists iff `'revoke-user-sessions'` is declared, declared `'impersonation'`/`'mfa'` must be observable), actor propagation, channel reporting, and revoke semantics — with an explicit `best-effort` revoke mode for stateless JWT transports. It is framework- and test-framework-free, re-validates sessions at runtime, and both provider adapters now run it in their test suites. No runtime behavior changes.

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

## 0.1.0

### Minor Changes

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
