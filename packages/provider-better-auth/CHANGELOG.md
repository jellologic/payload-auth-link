# @payload-auth-link/provider-better-auth

## 0.9.0

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

## 0.8.0

### Minor Changes

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`ae95855`](https://github.com/jellologic/payload-auth-link/commit/ae9585520a61ee1f874944f38c84cd5b1822a726) Thanks [@jellologic](https://github.com/jellologic)! - The Better Auth adapter now refuses (`UnsupportedOperatorError`) a
  case-insensitive `eq` combined with an `OR` connector instead of
  silently returning too few rows: the exactness post-filter ran over the
  whole result, dropping rows the other `OR` branch admitted. Found by a
  new differential suite that runs the adapter against Better Auth's
  `memoryAdapter`. Better Auth core issues no such query; plugin or app
  code that did now gets a loud error. String sort collation is now
  documented: ordering follows the database (binary on SQLite/MongoDB),
  not the memory adapter's `localeCompare`.

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

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71) Thanks [@jellologic](https://github.com/jellologic)! - Web-layer fixes (issue [#87](https://github.com/jellologic/payload-auth-link/issues/87)).

  - `safeRedirectPath` resolves dot segments (including percent-encoded ones) before the API-prefix and sign-in checks and returns the normalised path, so `/x/../api/...` and `/./sign-in` fall back.
  - `AuthLinkProvider` sequences session reads: only the newest read writes state, and `signOut` aborts in-flight reads so a late response can no longer restore a signed-out session. `fetchSession` accepts an optional `AbortSignal`.
  - Logout (`DELETE /api/auth-link/session`) also expires Better Auth's `dont_remember` and cookie-cache `session_data` cookies, the `__Secure-`/plain counterpart of each name, and the configured `legacySessions` names (`getBetterAuthLogoutCookieNames` returns the additional names).
  - A logout presenting no session cookie and no `Authorization`/`x-api-key` header answers without querying any provider (same idempotent response, cookies still expired).
  - The provider admin login view derives its break-glass endpoint (`${routes.api}/${usersCollection}/login`) and post-login destination (`routes.admin`) from the Payload config; new `admin.signInPath` and `admin.authBase` plugin options cover the app sign-in link and the Better Auth mount.
  - Docs: `__Host-` cookie setup for single-host deployments.

  Upgrade impact: no schema change, no push or migration needed on any adapter. Operators with a non-default sign-in page or Better Auth mount set `admin.signInPath` / `admin.authBase`. See `docs/upgrading.md`.

### Patch Changes

- Updated dependencies [[`60deb7d`](https://github.com/jellologic/payload-auth-link/commit/60deb7db81c1a74c9a3b0bc5c60f52e4c61f0c79), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71), [`d210efe`](https://github.com/jellologic/payload-auth-link/commit/d210efe66ed560e2a8394c399e4b64695219dc71)]:
  - @payload-auth-link/core@0.7.0

## 0.7.3

### Patch Changes

- [`840c3cf`](https://github.com/jellologic/payload-auth-link/commit/840c3cfb7220e3940bd7645da938650b482f4360) Thanks [@jellologic](https://github.com/jellologic)! - The session-provenance recording is success-gated: a FAILED sign-in or verification never relabels the session's authentication method.

  Better Auth's endpoint hooks run even when the endpoint returned an error response — its verify-totp RETURNS a 401 for a wrong code instead of unwinding the chain — so the recording hook ran on failures too. A wrong 2FA code from a non-MFA session on an MFA-enabled account could therefore relabel that session `two-factor`, unlocking MFA-gated roles without any valid second factor. The hook now mirrors Better Auth's own `getEndpointResponse` success contract (200 body required; non-2xx responses and APIErrors record nothing), so only successful requests write the method.

  Upgrade impact: none stored — behavior only, and strictly narrower (failed requests record nothing, as they always should have).

## 0.7.2

### Patch Changes

- [#81](https://github.com/jellologic/payload-auth-link/pull/81) [`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94) Thanks [@jellologic](https://github.com/jellologic)! - Better Auth's native sign-in flows record their authentication method, and session ids become opaque handles (issues [#79](https://github.com/jellologic/payload-auth-link/issues/79) and [#80](https://github.com/jellologic/payload-auth-link/issues/80)).

  - **`requireMfaForRoles` works through Better Auth's own 2FA again ([#79](https://github.com/jellologic/payload-auth-link/issues/79)).** 0.10.1's assurance read the per-session `authenticationMethod` column, but only server-side mints wrote it — a user completing BA's native two-factor sign-in got `mfa: 'unknown'` and their MFA-gated role stayed withheld. The provenance plugin now stamps the method on every recognized sign-in flow (`password`, `two-factor` on the verification endpoints, `oauth` callbacks, `magic-link`, `email-otp`, `passkey`); BA's 2FA-pending sign-in expires the session cookie, so a single-factor session is never relabelled — the second factor issues a FRESH session recorded as `two-factor`. Unknown paths still record nothing (fail closed).
  - **Session ids are opaque handles, never bearer tokens ([#80](https://github.com/jellologic/payload-auth-link/issues/80)).** `listSessions` and `createSessionFor().sessionId` return the session row id instead of the raw token — a devices page could otherwise expose one live credential per session into page data, logs, and error reports. `revokeSession` resolves the handle server-side and keeps its verified-deletion semantics; BA's own logout internals (which revoke by token) are unaffected. `createSessionFor().token` and `sessionCookie(token)` are unchanged — the token still rides exactly where setting the cookie needs it.

  Upgrade impact: no stored data changes (the column exists since 0.10.1). Behavior: MFA-gated roles through BA's native 2FA are restored without a custom step-up route; consumers that treated `listSessions` ids as tokens must switch to the opaque handles (revocation accepts both shapes).

- Updated dependencies [[`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94)]:
  - @payload-auth-link/core@0.6.2

## 0.7.1

### Patch Changes

- [`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe) Thanks [@jellologic](https://github.com/jellologic)! - The server session API is hardened: minted sessions carry explicit, recorded assurance; one id type across mint/list/revoke with verified deletion; the requested TTL is honored and the stored expiry audited; `'dev-only'` means development.

  - **Assurance reads a per-session record, not an enrollment flag.** The engine appends an internal Better Auth plugin adding one nullable `authenticationMethod` session field; mints record `server-mint` (no 2FA challenge ran — `mfa: false`), a server-vouched step-up records `server-step-up` (`mfa: true`). The old read leaned on `user.twoFactorEnabled`, so every mint for a 2FA-enrolled user claimed a second factor that never ran. Sign-in sessions without a recorded method report `mfa: 'unknown'`, which the MFA gate treats as absent (fail-closed) — restore gated roles via `createSessionFor(userId, { mfaProof: true })`, only where the server verified the second factor itself. `authLinkServer.sessionCookie`/`createSessionFor().setCookie` unchanged in shape.
  - **`revokeSession` consumes the ids `listSessions` and `createSessionFor` hand out** (the session token — previously they returned row ids while revocation deleted by token, so revokes deleted nothing and reported success), and is verified: an id with no session behind it, or a delete that leaves the row in place, is an error.
  - **Mint TTL honored and audited honestly.** The expiry was landing in Better Auth's `dontRememberMe` slot (every mint got ~24h regardless of the request, with the audit recording the requested value as if stored); it now goes through Better Auth's `override`, and the audit event and returned `expiresAt` carry the STORED expiry (`createSessionFor` result gains nothing breaking; providers report `storedExpiresAt`).
  - **`'dev-only'` (the `allowServerSessions` default) enables minting ONLY on `NODE_ENV === 'development'`** — previously on everything except `'production'`, which silently armed minting in CI, test and staging.

  Upgrade impact: the engine's session table gains one additive, nullable column through Better Auth's own schema machinery — run the usual Payload push/migrations; no data changes. Behaviour: MFA-gated roles are withheld for sessions with no recorded method until a `mfaProof` mint or a method-recording flow; `'dev-only'` now refuses minting outside development (set `allowServerSessions: true` explicitly). CI/test code that relied on the old default must opt in.

- Updated dependencies [[`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe)]:
  - @payload-auth-link/core@0.6.1

## 0.7.0

### Minor Changes

- [#73](https://github.com/jellologic/payload-auth-link/pull/73) [`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c) Thanks [@jellologic](https://github.com/jellologic)! - The server-session API's cookie is actually signed, and the server API is stricter about providers (issues [#68](https://github.com/jellologic/payload-auth-link/issues/68)–[#72](https://github.com/jellologic/payload-auth-link/issues/72) correctness pass, found in the first production rehearsal).

  - **`sessionCookie(token)` now returns `Promise<string>`** on `authLinkServer(payload)` and the provider port, and emits Better Auth's SIGNED form (`token.<HMAC>` — BA reads the session cookie with `getSignedCookie` only, so 0.9.0's raw-token cookie resolved no session). The cookie is built from the engine's own resolved context: secret, cookie name, and the real `Secure`/`SameSite`/`Path`/`Max-Age` attributes. `createSessionFor().setCookie` carries the signed value; await the call.
  - **`revokeAllForUser` and `listSessions` walk every linked provider**, not just the first capable identity — with two linked providers, the second provider's sessions were neither listed nor revoked.
  - **`sessionCookie(token)` refuses ambiguity**: with several cookie-transport providers registered it throws instead of silently signing with the wrong one (`createSessionFor` remains the unambiguous path).
  - **`legacySessions` on the plugin now enforces agreement** with the engine's window at config time (`InvalidConfigError` on missing, disagreeing, or colliding windows; engine-only configuration stays legal — the engine input is what acts).
  - **`admin: { loginView: 'provider' }` renders**: the registration gains its `exportName` and the view signs in through Better Auth's `POST /sign-in/email` (the old `/api/auth/sign-in` link was never a route), with a two-factor-aware response and a path for social-only accounts. Requires a cookie-transport provider (config-time error otherwise), and **apps enabling it must regenerate the Payload import map** (`payload generate:importmap`).

  Upgrade impact: type-level — `await sessionCookie(…)` at call sites; behavior-level — hosts that set only the plugin's `legacySessions` option must move the window to the engine input (the plugin option now asserts it); hosts using `loginView: 'provider'` regenerate the import map. No collection shapes change; no stored data is touched.

### Patch Changes

- Updated dependencies [[`6eb5e57`](https://github.com/jellologic/payload-auth-link/commit/6eb5e57824ac8cbd4ad14b03bda851d103d7a94c)]:
  - @payload-auth-link/core@0.6.0

## 0.6.0

### Minor Changes

- [`a199112`](https://github.com/jellologic/payload-auth-link/commit/a199112f5aff164f2c028a403e816821a7635d27) Thanks [@jellologic](https://github.com/jellologic)! - Coexistence window (issue [#51](https://github.com/jellologic/payload-auth-link/issues/51)): `createBetterAuthEngine({ legacySessions: { until, cookieNames } })`
  honors legacy payload-auth session cookie names READ-ONLY until the
  ISO `until` date — the lookup re-presents them under the current
  names (suffix-preserving, so `.sig` signatures ride along when the
  app keeps the same `BETTER_AUTH_SECRET`), while minting always uses
  the current names. After the window the legacy names are refused with
  a session miss. The engine exposes `legacySessionCookieNames` for
  cookie helpers and Edge middleware; the plugin mirrors the
  declaration (`legacySessions`) for the doctor's expiry check.
  `Upgrade impact:` none — additive, opt-in.

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

### Patch Changes

- Updated dependencies [[`408b579`](https://github.com/jellologic/payload-auth-link/commit/408b5799d2642c8734ea9752a6df73218ccc389c)]:
  - @payload-auth-link/core@0.5.0

## 0.5.0

### Minor Changes

- [#63](https://github.com/jellologic/payload-auth-link/pull/63) [`eab1649`](https://github.com/jellologic/payload-auth-link/commit/eab16491cb4e8630d1d53ad27ea747094959f43d) Thanks [@jellologic](https://github.com/jellologic)! - Adopt existing collections instead of moving rows (issue [#49](https://github.com/jellologic/payload-auth-link/issues/49)), and
  keep stored role values untouched with the role value map (issue [#56](https://github.com/jellologic/payload-auth-link/issues/56)).

  **provider-better-auth**: `createBetterAuthEngine({ schemaMap, idStrategy: 'payload' })`
  serves Better Auth models from EXISTING Payload collections — the
  payload-auth layout boots with zero row moves. The engine creates no
  collection for an adopted model, forces no access, and preserves host
  fields (the adapter writes partial updates only). Per-model field maps
  rename fields both ways (`userId` → `user` or `referenceId`);
  relationship fields read and write as ids, coerced to the Payload id
  type. Every Better Auth field must resolve to a host column — missing
  ones fail fast, naming the model and field, on first adapter use.

  **plugin**: `authLink({ roleValues })` translates canonical roles to
  stored values at the storage edge (field reads, governed writes, the
  injected select's options), so a camelCase role like `frontPlugin`
  stays stored as-is while `requireRoles(['front-plugin'])` works.
  Duplicate stored values and entries for undeclared roles fail at
  config time. `projectRolesAs: 'stored'` (default `'canonical'`)
  projects stored values onto `req.user.roles` for access checks that
  compare the stored literal; the MFA gate and role governance always
  run on canonical roles.

  `Upgrade impact:` no schema changes and no backfill. Adopt-mode boots
  run their own additive step for the plugin-injected users columns (see
  the migrating-from-payload-auth guide); pushing over a payload-auth
  layout is NOT supported (drizzle's push prompts on the layout's enums).
  The fixture proves the whole path: a payload-auth 1.9.4 Postgres dump
  boots on payload-auth-link with zero row moves, old passwords sign in,
  orgs/members/API keys resolve, and host fields survive Better Auth
  writes.

## 0.4.0

### Minor Changes

- [#34](https://github.com/jellologic/payload-auth-link/pull/34) [`b993397`](https://github.com/jellologic/payload-auth-link/commit/b99339781343100ec5ccb8a80c9a9bd61dd36dba) Thanks [@jellologic](https://github.com/jellologic)! - Derive `customFields`/`customModels` from Better Auth's own schema
  (issue [#17](https://github.com/jellologic/payload-auth-link/issues/17)). New `deriveBetterAuthSchema(options)` (built on
  `getAuthTables` from `better-auth/db` — the same source the adapter
  validates against, so a derived declaration cannot disagree with
  what BA asks for), `declarationsFromTables(tables)` for the pure
  step, and `createBetterAuthEngine({ autoDeclare: true })`, which
  derives and merges **under** the builder's explicit declarations —
  a hand-pinned field always wins, the derived remainder fills the
  gaps. Semantics: arrays/unknown BA types map to JSON; enum-valued
  attributes stay text (BA owns value validation); a BA `defaultValue`
  keeps the column nullable; renames (`modelName`/`fieldName`) throw
  with a declare-by-hand pointer. Strict hand-declared mode is
  unchanged. `examples/basic` switches to `autoDeclare: true`; the
  capabilities guide documents the recipe and the snapshot-test drift
  alarm.

  Upgrade impact: none — `autoDeclare` is opt-in and hand declarations
  are unchanged.

### Patch Changes

- [#31](https://github.com/jellologic/payload-auth-link/pull/31) [`e087162`](https://github.com/jellologic/payload-auth-link/commit/e087162c6a1ec8651b0a3f3d104f879b6f0871d0) Thanks [@jellologic](https://github.com/jellologic)! - `@better-auth/api-key` support, verified and probed (issue [#16](https://github.com/jellologic/payload-auth-link/issues/16)): the
  satellite works end to end once the `apikey` model is declared —
  create/list through BA's endpoints, `x-api-key` requests resolve
  through the plugin session, and Payload REST sees the user behind the
  key (invalid keys 401). The committed schema probe now includes the
  satellite (like `@better-auth/passkey`), so BA bumps that change its
  schema fail the probe, not a user's boot; the compat matrix runs it
  via the BA axis. Docs: troubleshooting and compatibility stop calling
  the satellite unsupported; the capabilities guide gains an API-keys
  recipe (declaration, `enableSessionForAPIKeys`, `admitChannels`), the
  security posture — a key session carries its owner's Payload roles,
  so an admin's key is an admin credential — and the MFA note
  (`requireMfaForRoles` stays withheld from key sessions, which report
  `assurance.mfa: false`). `examples/basic` wires the satellite and a
  new e2e spec covers create → session → Payload REST → invalid key.

  Upgrade impact: none for existing databases. Adopting API keys is
  opt-in: declare the model, enable key sessions, admit the channel.

- [#30](https://github.com/jellologic/payload-auth-link/pull/30) [`99942ec`](https://github.com/jellologic/payload-auth-link/commit/99942ec5ac32ab03860fb81acbaac44c9696e76b) Thanks [@jellologic](https://github.com/jellologic)! - Adapter fix: a case-insensitive `eq` (translated to a contains-match
  plus an in-memory exact filter) no longer loses rows to pagination.
  Previously `findMany` fetched a single `skip + limit` window and
  `findOne` a fixed 100-row window, then filtered — decoy rows that
  merely contain the search text could fill the window, so real matches
  past it vanished (empty findMany pages, false-null findOne) and
  offsets counted unfiltered rows.

  Now, when a post-filter is in play, both operations page through the
  source with a stable sort until `skip + limit` **filtered** rows are
  collected (or the source is exhausted), so offsets count filtered
  rows and results are complete. Non-filtered queries are unchanged.
  Pinned by tests planting 150 contains-match decoys ahead of the real
  row (beyond both the page size and the old fixed window).

  Upgrade impact: none for the database; queries return complete,
  correctly-offset results.

- Updated dependencies [[`59ebe9c`](https://github.com/jellologic/payload-auth-link/commit/59ebe9c9ec0a2f21917873a100b8f2f14d4da008)]:
  - @payload-auth-link/core@0.4.0

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

### Patch Changes

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Type-safe upgrade alarms and schema interoperability (upgrade-resilience Phase 3b):

  - Core: `authMethods` exported as the single source for `AuthMethod` and the session wire enum; `sessionChannels` is now a const tuple with `SessionChannel` derived from it; `LinkingPolicy` derives from `linkingPolicySchema`. Union/schema drift now fails typecheck instead of degrading sessions at runtime.
  - Core: `parseSessionUser` accepts `ParseSessionUserOptions.onDegrade` with a typed `SessionUserDegradeReason`, so producer/consumer version skew (e.g. an unknown auth method from a newer server) is observable instead of silent. Default behavior is unchanged.
  - Core: every exported Zod schema is pinned as a Standard Schema v1 (`@standard-schema/spec` added); Zod and Effect Schema compose through `~standard`. Effect interop is covered by a CI test with `effect` as a devDependency only. The `zod: ^4.0.0` floor and a consumer TypeScript floor of 5.5 are now probe-proven and documented.
  - Plugin: stored-row mapping warnings aggregate once per kind per logger instead of once per corrupt row.
  - Better Auth provider: exhaustive `assertNever` guards on custom-field types and where operators, so new upstream variants fail CI typecheck.
  - Repo gates: public-API `.d.ts` snapshots (`bun run api:check`) and a `skipLibCheck: false` consumer fixture (`bun run consumer:check`) now run in `bun run check`.

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

### Patch Changes

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

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085) Thanks [@jellologic](https://github.com/jellologic)! - TanStack Start as a first-class citizen alongside Next.js.

  New packages:

  - `@payload-auth-link/web`: the framework-free web surface
    (`createRouteHandlers`, `createSessionVerifier`, `requireRoles` /
    `requireSessionUser`, `safeRedirectPath`), moved verbatim from
    `next`. No behavior change; `next` re-exports it so existing
    imports keep working.
  - `@payload-auth-link/tanstack-start` (Payload v4):
    `createServerRouteHandlers` for `server.handlers`,
    `createAuthRequestMiddleware` (over the shared `decideAuthRedirect`)
    for `src/start.ts`, `getSessionUserFromRequest` /
    `createSessionLoader` for server functions and hydration,
    `useAuthLinkRefreshStart` for post-auth refresh, and a
    `beforeLoad` guard recipe over shared `requireRoles`. Re-exports
    `web` for the same one-import DX as `next`.

  - Better Auth engine passes `options.plugins` through verbatim:
    builders declare the framework cookie plugin themselves
    (`nextCookies()` on Next.js, `tanstackStartCookies()` on
    TanStack Start) exactly as Better Auth documents. The engine
    never appends framework plugins and owns no cookie flags.

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
