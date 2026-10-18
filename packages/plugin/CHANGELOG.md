# @payload-auth-link/plugin

## 0.14.0

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

## 0.13.0

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

## 0.12.0

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

## 0.11.1

### Patch Changes

- [#97](https://github.com/jellologic/payload-auth-link/pull/97) [`38cc616`](https://github.com/jellologic/payload-auth-link/commit/38cc616cc2420fe265ba71d84ad0aeb10b0b4bd7) Thanks [@jellologic](https://github.com/jellologic)! - The users collection's admin-access wrapper (the impersonation deny) now forwards every argument Payload passes to a host-declared `access.admin`, not just `req`, so host functions that read the other arguments (Payload v4) keep working.

- [#97](https://github.com/jellologic/payload-auth-link/pull/97) [`743e561`](https://github.com/jellologic/payload-auth-link/commit/743e56116b803bf9eb4674267c7405926a762226) Thanks [@jellologic](https://github.com/jellologic)! - An email collision during just-in-time provisioning is recognised structurally, not with `instanceof`, so it is still handled when the host app and the plugin load different copies of `payload` (e.g. a Payload v4 app). Before, the collision surfaced as a raw storage error there and the lost-create-race retry never ran: when two first requests after sign-up raced, one came back signed out.

- [#97](https://github.com/jellologic/payload-auth-link/pull/97) [`a605a5b`](https://github.com/jellologic/payload-auth-link/commit/a605a5b3fa599b4398566d5b060d5fc258453390) Thanks [@jellologic](https://github.com/jellologic)! - `req.user.id` for provider sessions now carries the database's id type (a number on SQLite/Postgres) instead of always a string. Payload v4 fills `createdBy`/`updatedBy` relationships from `req.user`, so on number-id adapters every create by a provider-signed-in user, the organization endpoint included, failed validation (400). The session endpoint's JSON is unchanged.

  The MFA role gate reads and writes `req.user.roles` through a record, so the plugin type-checks against Payload v4's `AuthenticatedUser` as well as v3.

- [#99](https://github.com/jellologic/payload-auth-link/pull/99) [`fb14b12`](https://github.com/jellologic/payload-auth-link/commit/fb14b1284bed261bf473b84f0ad9073d421febd4) Thanks [@jellologic](https://github.com/jellologic)! - `GET /api/users/me` answers for auth-link sessions presented on the bearer channel (`admitChannels: ['cookie', 'bearer']`). Payload's `me` operation decoded the provider's opaque bearer token as a Payload JWT (a 500) and would echo it back as `token`; the plugin's `me` hook now answers for auth-link users with the verified session's `exp` and never returns the provider token. The `admitChannels` TSDoc now states which channels each adapter reports and the bearer CSRF relaxation.

  Upgrade impact: no schema change (no column added, removed or retyped; push and migrations have nothing to do on SQLite, Postgres or MongoDB). The users collection gains a `me` hook, which runs ahead of any host `me` hooks for auth-link sessions only.

## 0.11.0

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

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`a0323fd`](https://github.com/jellologic/payload-auth-link/commit/a0323fd102e8b383fde88a9ec4242cbbdb95a3c9) Thanks [@jellologic](https://github.com/jellologic)! - JIT email linking no longer treats Payload's `_verified` flag as proof of email ownership, and proof never survives an unproven email change.

  - `findByEmail` admits a pre-existing document only when it carries the plugin's `linkable` proof bound to its current address (`linkableEmail`), as docs/security-model.md row 8 documents. Payload keeps `_verified` across email changes (and its default field access lets any signed-in user write it), so a verified, unlinked document whose owner changed its email to someone else's address could previously be linked to that person's provider identity.
  - An email change made neither by the plugin's provider-email resync nor by a role manager clears `linkable` and `linkableEmail` — and `_verified` on `auth.verify` hosts — in the same write.
  - Linking an identity clears Payload's local `sessions` array for the document (`auth.useSessions`, Payload's default), so a local JWT issued before the link is refused afterwards; on hosts without `useSessions`, the account-control gate refuses `local-jwt` requests on provider-linked documents (401) unless `allowLocalCredentialsForLinkedDocs` is set.
  - Provisioning that collides with an existing, unproven document holding the same email is a logged, typed refusal (401, `provisioning refused: …` through the logger) instead of a storage error; Payload's "already registered" auth-collection check now maps to `UserExistsError` like the unique-index violation.

  Upgrade impact: no schema change — no column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Operator step: hosts that relied on `_verified` alone to JIT-link pre-existing accounts must grant `linkable` + `linkableEmail` to the accounts they trust (snippet and audit guidance in docs/upgrading.md); the migration importer already does this for verified imports. Users who change their own email on an `auth.verify` host must re-verify before local sign-in.

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`a0323fd`](https://github.com/jellologic/payload-auth-link/commit/a0323fd102e8b383fde88a9ec4242cbbdb95a3c9) Thanks [@jellologic](https://github.com/jellologic)! - Organization membership governance is enforced on every write path.

  - A membership's `organization` and `user` are immutable after create: field access drops REST/GraphQL/admin writes, and a `beforeChange` guard throws for any other writer, trusted Local-API calls with `overrideAccess` included. The only sanctioned `user` write is the plugin's own invite acceptance binding the verified user to their pending invitation. Previously a manager of one organization could move their own membership into another organization (as owner) or re-point a membership at any user.
  - Membership create/update/delete and invites require a manager of the row's organization and never grant a role above the caller's own (`orgRoles` order is the rank): an `admin` can no longer promote anyone (themselves included) to owner, nor edit or remove an owner's membership.
  - An organization always keeps an active owner: demoting or removing the last one answers a typed `409`.
  - `DELETE /api/organizations/:id` cascades the organization's memberships and pending invitations in the same request instead of failing with a 500.
  - While an operator impersonates a user, organization updates/deletes, every membership write, and the invite / accept / create endpoints are refused (`403`); endpoint attempts are audited through the logger and `onAudit` with `denied: true` and the endpoint path (collection operations keep their existing per-operation audit).

  Upgrade impact: no schema change — no column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Behavioural: Local-API scripts that re-pointed memberships must delete and re-create the row; a sole owner must promote a second owner before stepping down. See docs/upgrading.md.

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`b9c8a18`](https://github.com/jellologic/payload-auth-link/commit/b9c8a189ed8aa8e810626c81174caad9a7cfe190) Thanks [@jellologic](https://github.com/jellologic)! - Organization writes are scoped more tightly, and the last-owner guard holds under concurrency.

  - Bulk `PATCH`/`DELETE /api/organizations?where=…` (no document id) is scoped to the organizations the caller manages (owns, for delete). Before this change, organization update access read the organization id from the request body when no id was present, so a manager of one organization could rewrite other organizations through a bulk update.
  - Deleting an organization is owner-only. It removes every membership, the owners' included, which an `admin` must not be able to do.
  - `verifiedDomains` can be written only by Payload role managers (`roleManagerRoles`), and never while impersonating. A listed domain admits SSO sign-ins (CAP-15) for every address on it, for every registered SSO provider, so organization owners can no longer list one themselves.
  - Two owners removing or demoting each other at the same moment can no longer leave an organization without an owner. Each removal writes (locks) the organization row before counting owners, and re-counts after its write. If no owner is left, it restores the row and answers `409`.
  - Accepting an invitation after joining the organization another way answers `409` (`user is already a member`) instead of a storage validation error.

  Upgrade impact: no schema change. No column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Behavioural: org admins get `403` on organization delete; `verifiedDomains` writes from non-role-managers are ignored, so review existing entries once after upgrading; owner removals bump the organization's `updatedAt`. See docs/upgrading.md.

  Organization creation now seeds the creator's owner membership inside the organization's own transaction. On Postgres (and other transactional adapters) it used to fail the membership's foreign key, so `POST /api/auth-link/organizations` answered 400.

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

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`661455c`](https://github.com/jellologic/payload-auth-link/commit/661455c057a02325f24241188305386ae624d8e9) Thanks [@jellologic](https://github.com/jellologic)! - `reset-password` (REST, GraphQL `resetPasswordUser`, Local API) for a
  SUSPENDED account is now refused (401) in `beforeOperation`, before
  Payload writes anything. Payload's reset operation stores the new
  password and clears the account's sessions before it runs
  `beforeLogin`, so on adapters where that write is not rolled back the
  previous `beforeLogin` refusal came too late: the "refused" reset had
  already rotated the credential, which then worked as soon as the
  suspension lapsed. The check applies whatever
  `allowLocalCredentialsForLinkedDocs` says, and the guard's lookup now
  runs inside the operation's transaction (`req`).

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`77552bb`](https://github.com/jellologic/payload-auth-link/commit/77552bb11b19a243c89cd8816877f6a956897503) Thanks [@jellologic](https://github.com/jellologic)! - Restrict the users collection's `unlock` operation to role managers by default (never while impersonating). Payload's own default let any signed-in user unlock any account, which undid the brute-force lockout. A host that sets `access.unlock` itself keeps its own function.

  Upgrade impact: no schema change. Self-service "unlock my account" flows run by plain users now get 403; route them through a role manager or set `access.unlock` on your users collection.

- [#89](https://github.com/jellologic/payload-auth-link/pull/89) [`0adba41`](https://github.com/jellologic/payload-auth-link/commit/0adba4178662fb899760cf3708b548ba7874fb36) Thanks [@jellologic](https://github.com/jellologic)! - Close open write defaults on the users collection: with no host-declared access, `update` is now self-or-role-manager and `delete` is role-manager only (never while impersonating), instead of Payload's "any signed-in user". The injected email field lets a non-manager change only their own address, even under a broader host `update`. `migrate export --out` and import manifests are written owner-only (0600) before content lands; sealed manifest values are bound to their entry and rollback restores only the fields the kit writes. `validateSessionEndpoint` rejects whitespace and control characters.

  Upgrade impact: no schema change. Hosts that relied on any signed-in user updating or deleting other users must declare that access explicitly; see docs/upgrading.md.

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

## 0.10.2

### Patch Changes

- [#81](https://github.com/jellologic/payload-auth-link/pull/81) [`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94) Thanks [@jellologic](https://github.com/jellologic)! - Better Auth's native sign-in flows record their authentication method, and session ids become opaque handles (issues [#79](https://github.com/jellologic/payload-auth-link/issues/79) and [#80](https://github.com/jellologic/payload-auth-link/issues/80)).

  - **`requireMfaForRoles` works through Better Auth's own 2FA again ([#79](https://github.com/jellologic/payload-auth-link/issues/79)).** 0.10.1's assurance read the per-session `authenticationMethod` column, but only server-side mints wrote it — a user completing BA's native two-factor sign-in got `mfa: 'unknown'` and their MFA-gated role stayed withheld. The provenance plugin now stamps the method on every recognized sign-in flow (`password`, `two-factor` on the verification endpoints, `oauth` callbacks, `magic-link`, `email-otp`, `passkey`); BA's 2FA-pending sign-in expires the session cookie, so a single-factor session is never relabelled — the second factor issues a FRESH session recorded as `two-factor`. Unknown paths still record nothing (fail closed).
  - **Session ids are opaque handles, never bearer tokens ([#80](https://github.com/jellologic/payload-auth-link/issues/80)).** `listSessions` and `createSessionFor().sessionId` return the session row id instead of the raw token — a devices page could otherwise expose one live credential per session into page data, logs, and error reports. `revokeSession` resolves the handle server-side and keeps its verified-deletion semantics; BA's own logout internals (which revoke by token) are unaffected. `createSessionFor().token` and `sessionCookie(token)` are unchanged — the token still rides exactly where setting the cookie needs it.

  Upgrade impact: no stored data changes (the column exists since 0.10.1). Behavior: MFA-gated roles through BA's native 2FA are restored without a custom step-up route; consumers that treated `listSessions` ids as tokens must switch to the opaque handles (revocation accepts both shapes).

- Updated dependencies [[`d20684e`](https://github.com/jellologic/payload-auth-link/commit/d20684e5e8a1602e3b8e6de37ce494112c250c94)]:
  - @payload-auth-link/core@0.6.2

## 0.10.1

### Patch Changes

- [`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe) Thanks [@jellologic](https://github.com/jellologic)! - The server session API is hardened: minted sessions carry explicit, recorded assurance; one id type across mint/list/revoke with verified deletion; the requested TTL is honored and the stored expiry audited; `'dev-only'` means development.

  - **Assurance reads a per-session record, not an enrollment flag.** The engine appends an internal Better Auth plugin adding one nullable `authenticationMethod` session field; mints record `server-mint` (no 2FA challenge ran — `mfa: false`), a server-vouched step-up records `server-step-up` (`mfa: true`). The old read leaned on `user.twoFactorEnabled`, so every mint for a 2FA-enrolled user claimed a second factor that never ran. Sign-in sessions without a recorded method report `mfa: 'unknown'`, which the MFA gate treats as absent (fail-closed) — restore gated roles via `createSessionFor(userId, { mfaProof: true })`, only where the server verified the second factor itself. `authLinkServer.sessionCookie`/`createSessionFor().setCookie` unchanged in shape.
  - **`revokeSession` consumes the ids `listSessions` and `createSessionFor` hand out** (the session token — previously they returned row ids while revocation deleted by token, so revokes deleted nothing and reported success), and is verified: an id with no session behind it, or a delete that leaves the row in place, is an error.
  - **Mint TTL honored and audited honestly.** The expiry was landing in Better Auth's `dontRememberMe` slot (every mint got ~24h regardless of the request, with the audit recording the requested value as if stored); it now goes through Better Auth's `override`, and the audit event and returned `expiresAt` carry the STORED expiry (`createSessionFor` result gains nothing breaking; providers report `storedExpiresAt`).
  - **`'dev-only'` (the `allowServerSessions` default) enables minting ONLY on `NODE_ENV === 'development'`** — previously on everything except `'production'`, which silently armed minting in CI, test and staging.

  Upgrade impact: the engine's session table gains one additive, nullable column through Better Auth's own schema machinery — run the usual Payload push/migrations; no data changes. Behaviour: MFA-gated roles are withheld for sessions with no recorded method until a `mfaProof` mint or a method-recording flow; `'dev-only'` now refuses minting outside development (set `allowServerSessions: true` explicitly). CI/test code that relied on the old default must opt in.

- Updated dependencies [[`5c76018`](https://github.com/jellologic/payload-auth-link/commit/5c76018ad084e58ec2fc483a811a66b803f21bbe)]:
  - @payload-auth-link/core@0.6.1

## 0.10.0

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

## 0.9.0

### Minor Changes

- [`e8117a0`](https://github.com/jellologic/payload-auth-link/commit/e8117a0d15e94c30beaf6468fe6ad8af2367f72c) Thanks [@jellologic](https://github.com/jellologic)! - Provider-backed admin login view (issue [#55](https://github.com/jellologic/payload-auth-link/issues/55)):
  `authLink({ admin: { loginView: 'provider' } })` swaps Payload's local
  login view for one that runs admin sign-in through the configured
  provider (email+password, magic link, social — whatever the provider
  exposes) plus the break-glass local fallback form for UNLINKED
  operator accounts (0.7.0 refuses provider-linked documents on the
  local login path by design). The view is a Payload custom view;
  the import map must include
  `@payload-auth-link/plugin/admin#ProviderLoginView` (the doctor
  counts it). `Upgrade impact:` none — opt-in; the default stays
  Payload's local login.

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

## 0.8.0

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

- [#63](https://github.com/jellologic/payload-auth-link/pull/63) [`ff5e0fd`](https://github.com/jellologic/payload-auth-link/commit/ff5e0fd69a9c0655ed32bbade8f3a6d706cf7dd1) Thanks [@jellologic](https://github.com/jellologic)! - Opt-in full user document on `req.user` (issue [#57](https://github.com/jellologic/payload-auth-link/issues/57)):
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

## 0.7.0

### Minor Changes

- [`5286408`](https://github.com/jellologic/payload-auth-link/commit/528640858e94619d859b82f63827e662ca1f133f) Thanks [@jellologic](https://github.com/jellologic)! - Security hardening: the plugin's account controls now apply to EVERY
  strategy (GHSA-f4hj — suspension and the MFA policy were enforced only
  on the `auth-link` strategy, and Payload's forgot/reset-password flow
  ran past the 0.6.0 password-write strip, so a suspended user could
  keep access through a self-minted local password).

  - **Suspension is enforced on every strategy, at request time.**
    `beforeLogin` refuses the local sign-in for a suspended account
    (401), and a request-time gate on every collection and global
    refuses any request carrying a suspended account's local JWT or API
    key (401) — including `refresh-token` and GraphQL — with a fresh
    read of `suspendedUntil`, so the control lands the moment an
    operator sets it.
  - **`policies.requireMfaForRoles` applies to local credentials.**
    Local sessions have no MFA proof, so the listed roles are withheld
    from local-strategy sessions (JWT, API key) before any access check
    reads them. Local login is not blocked; the session loses the role.
  - **Provider-linked documents are provider-owned** (new
    `allowLocalCredentialsForLinkedDocs` option, default `false`):
    local sign-in is refused (403) and the forgot/reset-password flow
    is refused (403, no token issued) for documents holding linked
    identities — a local password there would bypass the provider's
    MFA, bans, rate limits, and revocation. Documents without linked
    identities (operator accounts, imports not yet linked) keep local
    credentials and password recovery.
  - **New committed credential-path matrix** (`docs/security-model.md`)
    plus a table-driven test walking every path for a suspended user, a
    non-manager attempting role/email/password writes, and an
    unproven-email link.

  Upgrade impact: no schema changes and no backfill. Default-behaviour
  changes only — see `docs/upgrading.md` (0.6.x → 0.7.0): suspended
  accounts now lose local credentials too; provider-linked documents no
  longer accept local sign-in or self-service password reset unless
  `allowLocalCredentialsForLinkedDocs: true` is set (migration-window
  escape hatch; remove it when the window closes).

## 0.6.0

### Minor Changes

- [`e631ada`](https://github.com/jellologic/payload-auth-link/commit/e631ada0abae1b0cc467c14d4181ee250b22054a) Thanks [@jellologic](https://github.com/jellologic)! - Security hardening: the JIT-linking proof is now bound to the email
  it was granted for (GHSA-8524 — the 0.5.0 `linkable` marker survived
  a self-service email change, so a pre-created document re-proven for
  an attacker-chosen password could be moved to a victim's email and
  JIT-linked to them).

  - **New `linkableEmail` field**: the email the proof was granted for.
    The proof holds only while the document email equals it; any email
    change that is not the plugin's own provider-email resync
    invalidates linking automatically.
  - **Email changes over REST on documents with linked identities are
    role-manager-only** (stripped for non-managers). Payload's own
    `auth.verify` can re-prove an address if the host enables it.
  - **Self-service local passwords on plugin-managed documents are
    stripped** for non-managers: a provider-provisioned user can no
    longer mint a Payload local credential that bypasses Better Auth's
    MFA, bans, rate limits, and verification. Role managers keep
    password writes; hosts who declare their own password field access
    keep it.
  - **The link-time local-password warning now actually fires** (the
    hidden-field lookup was silently failing).
  - The provider-email resync keeps the proof bound: repository
    `setEmail` moves the email and the proof together with
    `overrideAccess`.

  Upgrade impact + backfill: existing `linkable: true` documents
  (created by 0.5.0/0.5.1 without `linkableEmail`) are treated as
  unproven. Backfill `linkableEmail = email` ONLY where the email still
  matches the linked identity's email; treat anything else as unproven.
  Role managers can set it per user over REST; the migration runbook's
  script marks both fields for imported users. Negative e2e specs cover
  the full advisory chain on all six adapter/example combos.

## 0.5.1

### Patch Changes

- [#44](https://github.com/jellologic/payload-auth-link/pull/44) [`31aa536`](https://github.com/jellologic/payload-auth-link/commit/31aa536734771829d8aeda8256d7b5c91569069b) Thanks [@jellologic](https://github.com/jellologic)! - One session resolution per request (issue [#42](https://github.com/jellologic/payload-auth-link/issues/42)): the auth strategy and
  the endpoint handler verify the same `req.headers` reference for a
  single request, so each refused request walked the providers (and
  logged its warnings) three times. Verification results are now
  memoized on the headers identity — one provider walk, one set of
  logs, one resolution per request; a new request brings new headers
  and a fresh verification. The guest read is unchanged.

  Upgrade impact: none — refused requests now log each warning once
  instead of three times, and refused requests stop paying repeated
  provider round-trips.

## 0.5.0

### Minor Changes

- [`a0e374c`](https://github.com/jellologic/payload-auth-link/commit/a0e374c52cbe226378c460014a73acbb557c611d) Thanks [@jellologic](https://github.com/jellologic)! - Security hardening: JIT email linking now requires proof of email
  ownership, and the users collection's `create`/`read` defaults fail
  closed (GHSA-98hq-hh6v-2p2r — pre-account hijack: any authenticated
  user could pre-create a Payload user with a victim's email and their
  own password; when the victim later signed up through the provider,
  JIT linking attached the verified identity to that attacker-created
  document, and the attacker logged in with the password they chose).

  - **New `linkable` field** on the users collection: the JIT-linking
    proof. Set automatically on plugin-managed creates (verified
    provider identity) and role-manager creates; role managers can
    toggle it. Documents created outside the plugin start unproven and
    are never JIT-linked until marked. Payload's own verified flag
    (`auth.verify`) also proves ownership.
  - **Collection-level `create` on the users collection defaults to
    role-manager-only** (plus the impersonation deny), and **`read`
    defaults to self + role managers** (removing user enumeration) —
    both only where the host hasn't declared that access function.
  - Linking to a document that also holds a local password logs a
    warning (one document, two credential owners).
  - `findByEmail` (email-based resolution) returns unproven documents
    as absent, with a logged reason, so a verified identity is refused
    (401) rather than attached.

  Upgrade impact: default-behaviour change. Non-managers can no longer
  create users over REST or list other users; pre-existing documents
  from before this release are unproven and need `linkable: true` (a
  role-manager write, or the migration runbook's step 3) before their
  owner's first provider sign-in links. Hosts whose end users
  self-register through Payload REST must declare
  `access: { create: ... }` on the users collection. Negative e2e
  specs + integration tests pin the refusal, the proven/imported path,
  the create block, and self-only listing on all six
  adapter/example combos.

## 0.4.0

### Minor Changes

- [#33](https://github.com/jellologic/payload-auth-link/pull/33) [`97feee9`](https://github.com/jellologic/payload-auth-link/commit/97feee90d5ff3a06dfc6c77f7ff85d176272b13f) Thanks [@jellologic](https://github.com/jellologic)! - Adopt an existing roles field instead of throwing (issue [#20](https://github.com/jellologic/payload-auth-link/issues/20)) — the
  migration path from `payload-auth`-style schemas where the Payload
  users table already carries a role column. A compatible field at the
  configured `rolesField` (Payload `select`, `hasMany: true`, options
  covering every configured role) is taken over: the plugin imposes
  required-ness, the default, and its governed write access, while the
  host's options, labels, and extra roles survive. Incompatible shapes
  fail at config time naming the exact remediation; `rolesField:
'role'` remapping against an existing `role` column now works.

  Alongside: **docs/migrating-from-payload-auth.md** — the runbook for
  moving data from `payload-auth` (users → `ba-users` with `baId` =
  old id, `user_accounts` → `ba-accounts` with password hashes and
  OAuth tokens verbatim, identity pre-linking, plugin-model foreign-key
  rewrites, session/verification drop policy, `advanced.cookiePrefix`
  continuity) with a script sketch, plus the prominent
  `req.user`-is-the-session-projection note.

  Upgrade impact: config-time behavior — setups that previously failed
  with a roles-field collision now boot and adopt the field, which
  gains the role-manager write restriction; no database change.

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

- [#32](https://github.com/jellologic/payload-auth-link/pull/32) [`b8d3a19`](https://github.com/jellologic/payload-auth-link/commit/b8d3a1923e128af9611725a891937203f0181409) Thanks [@jellologic](https://github.com/jellologic)! - Docs-drift sweep (issue [#19](https://github.com/jellologic/payload-auth-link/issues/19)) plus one developer-experience widening:

  - `requireOrgRole` accepts **plain role slugs and plain wiring**:
    roles are parsed fail-closed (`InvalidRoleError` on a bad entry,
    like `requireRoles`), and the wiring parameter is a structural
    subset (`organizationsCollection` + `membershipsCollection`, extra
    fields accepted) — the capabilities guide's snippet now
    type-checks as written, and the validated wiring from
    `authLink({ organizations })` still satisfies it.
  - README peer ranges are generated from the manifests and
    `check-docs` now fails when a README states a peer range the
    manifest does not (the drift that started this issue).
  - getting-started says `better-auth` is a peer (since 0.3.0), not a
    bundled dependency; MISSION.md no longer promises admin session
    views or webhook sync (none exist, by design); SECURITY.md and
    PLAN.md drop webhook wording; PLAN.md marks sessions views/admin
    revoke as deferred so PLAN and MISSION agree.

  Upgrade impact: none — the `requireOrgRole` signature is widened, so
  existing call sites (including branded-role callers) compile
  unchanged.

- [#29](https://github.com/jellologic/payload-auth-link/pull/29) [`179e561`](https://github.com/jellologic/payload-auth-link/commit/179e56120a07cde1878d368099fe496296bc8e9f) Thanks [@jellologic](https://github.com/jellologic)! - Verified fixes from the code-read sweep (issue [#21](https://github.com/jellologic/payload-auth-link/issues/21)):

  - **Organization membership uniqueness.** The memberships collection
    gains a compound **unique index on `(user, organization)`**: two
    concurrent invite-accepts (or owner-bootstrap hooks) could
    previously both pass the check-then-insert and land duplicate rows.
    Existing databases with duplicates must dedupe before the index
    builds (see docs/upgrading.md).
  - **`setEmail` keeps identity rows in step.** Changing a user's email
    now rewrites linked-identity rows that carried the old address, so
    the admin users view no longer shows a stale identity email.
  - **Role-config audit is bounded and its truncation note is
    reachable.** The startup audit no longer passes `pagination: false`
    (which ignored the 500-doc limit and made the truncation message
    unreachable); the note now fires when more users exist than were
    scanned.
  - **Impersonation in custom endpoints: proven, not assumed.** The
    "is `req.user` populated here?" doubt is settled by a test — the
    organization-create endpoint's impersonation deny fires on a real
    impersonated session.
  - **`checkAuthCookies(request, options)`** (next): composable form of
    the optimistic middleware — returns the 303 sign-in redirect or
    `null` — for apps that run their own `proxy.ts` (Next 16) /
    `middleware.ts` pipeline.

  Upgrade impact: new unique index on the memberships collection
  (dedupe existing duplicates first — per-adapter notes in
  docs/upgrading.md); `setEmail` now also writes the `identities` array
  when address-bearing rows change; the startup role audit's query
  shape changes (bounded, paginated).

### Patch Changes

- [`78bc505`](https://github.com/jellologic/payload-auth-link/commit/78bc5056399e265d6e0743feefee65c1e02b7662) Thanks [@jellologic](https://github.com/jellologic)! - Security hardening: the injected users-collection fields now fail
  closed by default. Payload's own collection defaults give every
  authenticated user write access to every field, which is the wrong
  default for fields that decide privileges. The new defaults:

  - **`roleManagerRoles`** (new option) names the roles that govern
    the auth system. Defaults to `['admin']` when an `admin` role is
    configured; **required at config time when it is not** (the plugin
    refuses to guess who manages roles).
  - `roles`, `phone`, `suspendedUntil` and `suspendReason` field
    writes: role-manager roles only, with the existing
    deny-while-impersonating rule on top. Local-API
    (`overrideAccess`) writes — the plugin's own engine paths and
    your own scripts — are never restricted.
  - Field reads: `suspendReason` and `suspendedUntil` are
    role-manager only (matching the documented "never exposed");
    `identities` too (engine-managed rows carry provider ids and
    emails); every user still reads their own `roles` (and phone).
  - `identities` writes are denied for every REST/admin caller —
    linking happens through the plugin only.
  - The default admin-panel grant is the role-manager roles, not "any
    signed-in user". A builder `access.admin` on the users collection
    still wins (wrapped with the impersonation deny, as before).

  Upgrade impact: default-behaviour change — REST/admin writers other
  than the manager roles lose write access to the injected fields, and
  non-managers no longer read `identities`/`suspension` fields. Hosts
  whose editors use a non-admin role must pass
  `roleManagerRoles: [...]`. Docs updated (getting-started, concepts,
  capabilities guide); negative e2e specs added on every adapter.
  Schema snapshots unchanged (access functions are not DB shape).

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

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Role-config safety (B11): removing a role from `authLink({ roles })`
  now stops granting it at the next session instead of the next time a
  user doc happens to be rewritten. Reads drop stored roles outside
  the configured set (one `LoggerPort` warning per removed role,
  naming it); a user whose only role was removed is denied a record
  entirely — never silently upgraded to the default role. The first
  boot after the change logs one aggregate startup audit warning
  (`N user doc(s) carry roles outside the configured set: 'editor'
(2)`), so drift is visible without touching the data. Runbook for
  removals and renames (drain first, then remove, then read the
  audit) in docs/upgrading.md.

  Upgrade impact: none for the database. Behavior change for anyone
  relying on stored-but-unconfigured roles still granting: they stop
  granting on upgrade. Re-add the role to the config to restore the
  old behavior while you drain assignments.

### Patch Changes

- [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd) Thanks [@jellologic](https://github.com/jellologic)! - Type-safe upgrade alarms and schema interoperability (upgrade-resilience Phase 3b):

  - Core: `authMethods` exported as the single source for `AuthMethod` and the session wire enum; `sessionChannels` is now a const tuple with `SessionChannel` derived from it; `LinkingPolicy` derives from `linkingPolicySchema`. Union/schema drift now fails typecheck instead of degrading sessions at runtime.
  - Core: `parseSessionUser` accepts `ParseSessionUserOptions.onDegrade` with a typed `SessionUserDegradeReason`, so producer/consumer version skew (e.g. an unknown auth method from a newer server) is observable instead of silent. Default behavior is unchanged.
  - Core: every exported Zod schema is pinned as a Standard Schema v1 (`@standard-schema/spec` added); Zod and Effect Schema compose through `~standard`. Effect interop is covered by a CI test with `effect` as a devDependency only. The `zod: ^4.0.0` floor and a consumer TypeScript floor of 5.5 are now probe-proven and documented.
  - Plugin: stored-row mapping warnings aggregate once per kind per logger instead of once per corrupt row.
  - Better Auth provider: exhaustive `assertNever` guards on custom-field types and where operators, so new upstream variants fail CI typecheck.
  - Repo gates: public-API `.d.ts` snapshots (`bun run api:check`) and a `skipLibCheck: false` consumer fixture (`bun run consumer:check`) now run in `bun run check`.

- Updated dependencies [[`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd), [`8ef5975`](https://github.com/jellologic/payload-auth-link/commit/8ef59750f5cc42de7488587b2f3d47abe59202bd)]:
  - @payload-auth-link/core@0.3.0

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

### Patch Changes

- [#1](https://github.com/jellologic/payload-auth-link/pull/1) [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085) Thanks [@jellologic](https://github.com/jellologic)! - Logout revokes every provider session the request presents, not only
  the verified one. Verification stops at the first registered provider
  with a live session (registry order is precedence, now documented), so
  a browser signed in through two providers previously kept the second
  session alive server-side after `DELETE /api/auth-link/session`. The
  sweep is best-effort — failures are logged, never fatal — and also runs
  on the idempotent 401 path, where a provider session can be live behind
  a failed verification.
- Updated dependencies [[`70e87c3`](https://github.com/jellologic/payload-auth-link/commit/70e87c3c3bfdda54f9ebdca5b074ac2635f7aed8), [`b010bea`](https://github.com/jellologic/payload-auth-link/commit/b010bea61a807e9400ebe944e9424463d7f55085)]:
  - @payload-auth-link/core@0.1.0
