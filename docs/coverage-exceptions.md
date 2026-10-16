# Coverage floors and exceptions

`vitest.config.ts` sets a per-file coverage floor for every
auth-critical file (issue #86). The target is 95% on every metric.
Where a file is below that, its floor is the measured value rounded
down, and this page says which branches are still uncovered and why.

Raise a floor whenever coverage improves. Never lower one without
updating this page: a lower floor means a security-relevant branch
lost its test.

## Floors

Each cell is lines / functions / branches / statements.

| File                                             | Floor             | Notes                  |
| ------------------------------------------------ | ----------------- | ---------------------- |
| `core/src/cookies.ts`                            | 95 / 95 / 95 / 95 | at target              |
| `plugin/src/access.ts`                           | 95 / 95 / 95 / 95 | at target              |
| `plugin/src/audit.ts`                            | 95 / 91 / 88 / 95 | see below              |
| `plugin/src/collections.ts`                      | 95 / 95 / 86 / 95 | see below              |
| `plugin/src/compat-shim.ts`                      | 95 / 95 / 95 / 95 | at target              |
| `plugin/src/endpoints.ts`                        | 95 / 95 / 91 / 95 | see below              |
| `plugin/src/organizations.ts`                    | 70 / 69 / 60 / 70 | provisional, see below |
| `plugin/src/repository.ts`                       | 95 / 95 / 95 / 95 | at target              |
| `plugin/src/server.ts`                           | 95 / 95 / 94 / 95 | see below              |
| `plugin/src/session.ts`                          | 95 / 95 / 94 / 95 | see below              |
| `plugin/src/strategy.ts`                         | 95 / 95 / 86 / 95 | see below              |
| `provider-authjs/src/port.ts`                    | 95 / 95 / 95 / 95 | at target              |
| `provider-better-auth/src/adapter.ts`            | 80 / 91 / 73 / 81 | see below              |
| `provider-better-auth/src/cookies.ts`            | 95 / 95 / 89 / 95 | see below              |
| `provider-better-auth/src/port.ts`               | 86 / 86 / 77 / 86 | see below              |
| `provider-better-auth/src/session-provenance.ts` | 95 / 95 / 95 / 95 | at target              |
| `provider-better-auth/src/where.ts`              | 95 / 95 / 95 / 95 | at target              |
| `web/src/authz.ts`                               | 95 / 95 / 95 / 95 | at target              |
| `web/src/verify.ts`                              | 95 / 95 / 95 / 95 | at target              |

## Recurring kinds of uncovered branch

Most of the remaining gaps fall into four kinds. They are listed once
here and referred to by name below.

- **Registry miss** — `wired.registry.require(id)` for an `id` that
  came from `wired.registry.ids()`. The registry is immutable after
  wiring, so the `isErr()` arm cannot run. It stays in the code
  because the `Result` type requires a check, and `continue` (rather
  than `throw`) is the safe answer if the registry ever becomes
  mutable.
- **`?? fallback` on an error cause** — `error.cause ?? error` in log
  calls. Each error class always sets `cause` on the path that reaches
  the log line, so the fallback arm is defensive.
- **Untyped-input narrowing** — `typeof x === 'string' ? x : …` and
  `isRecord(x) ? … : …` on values the plugin itself wrote, such as
  Payload documents with the plugin's own field types. The "wrong
  type" arm needs a document that bypassed Payload validation.
- **Environment switches at module load** — for example
  `process.env.PROVENANCE_HOOKS_OFF` in `session-provenance.ts`, read
  once when the module is imported. Covering the other arm would mean
  re-importing the module inside the test.

## Per file

### `plugin/src/audit.ts` (branches 88.88%)

- Lines 57, 59 and 64: `targetUserId`/`actorUserId` arms for a
  request user with no id, or a non-`payload-user` actor (untyped-input
  narrowing; the strategy always projects an id).
- Line 96: `fields ?? {}` in `composeAuditLogger`. Every audit call
  site passes fields.

### `plugin/src/collections.ts` (branches 86%)

- Lines 45 and 85: role narrowing on a user without a `roles` array,
  and a host-supplied access function in a slot the belt wraps
  (untyped-input narrowing).
- Lines 297, 800, 804 and 808: `suspensionActive`/`suspendRevokeHook`
  arms for a non-record document (untyped-input narrowing).
- Line 447: the re-entrant account-status read. It runs only when the
  status read re-enters the gate on the same request. No current test
  in this run reaches it.
- Lines 744 and 748: the phone field's `validate`. This is the CAP-9
  phone path, which has its own suite in the provider packages.
- Lines 826 and 1016–1021: registry miss in the suspend-revoke hook,
  and the field-collision message for the identities field. The
  generic collision is tested; the identities-specific wording is not.
- The remaining `cond-expr#1` arms (271, 330, 369, 407, 470, 529, 550,
  551, 688, 690, 942–971 and 1042) are `?? default` and
  `isRecord(...) ? ... : undefined` narrowing on documents Payload has
  already validated.

### `plugin/src/endpoints.ts` (branches 89.83%)

- Lines 32, 79 and 115: registry miss.
- Line 46: `presentedLogoutCookieNames` with no request headers. The
  logout endpoint always has headers.
- Line 162: a provider with no `guest` hook, on the anonymous path.
- Line 181: `?? fallback` on an error cause.

Another change is editing this file at the same time (cookie expiry).
Re-measure after it lands.

### `plugin/src/organizations.ts` (provisional: 70 / 69 / 60 / 70)

This floor is the value measured on this branch. Organization
membership-access tests are being added in a separate change, and the
floor should go up to the measured value once those tests land.

### `plugin/src/server.ts` (branches 94.64%)

- Lines 186, 201 and 352: registry miss (`firstProviderWith`,
  `allProvidersWith`, `revokeSession`).
- Line 230: `wired.roleValues[role] ?? role` on a role that has no
  stored value under `projectRolesAs: 'stored'`. Roles are canonical
  and every configured role has a value.
- Line 440: `sessionCookie` re-checking `capable[0]` after the length
  check. This is unreachable; the check is there for
  `noUncheckedIndexedAccess`.

Every fail-loud branch (revoke, revoke-all, verifyApiKey, mint and
list refusals) is covered by `server-failures.test.ts`.

### `plugin/src/session.ts` (branches 94.94%)

- Lines 105 and 132: registry miss.
- Line 205: the per-request verify memo on a request whose `context`
  is not a record. Payload always supplies a context object.
- Lines 348 and 405: `emailClaim?.value ?? null` and
  `suspendedUntil ?? clock.now()`. These are narrowing arms that the
  guarding conditions already exclude.

### `plugin/src/strategy.ts` (branches 86.11%)

- Line 46: `?? fallback` on an error cause.
- Line 68: `roleValues[role] ?? role` (same as `server.ts` line 230).
- Line 119: `organizationId` projection when a strategy session
  reports an active organization. This is reachable and is a good
  candidate for the next test.
- Two `if#1` arms in the `reqUser: 'document'` memo: a request without
  `context`.

### `provider-better-auth/src/adapter.ts` (73% branches)

- Lines 607–685, the host-collection validation for adopted models
  (`schemaMap`, issue #49): auth-collection detection, tabs and ui
  walking, and missing-collection errors. The happy path is covered by
  `integration-adopt.test.ts`. The error arms need host configs that
  Payload itself would reject at `buildConfig`.
- Lines 123–305, the `narrow*` helpers for Local API results: the
  arms for "Payload returned a non-record / non-array". These are
  untyped-input narrowing.
- Lines 385–472, id-coercion arms for adopted models with numeric
  Payload ids (`idStrategy: 'payload'`). The SQLite suite uses string
  ids on the BA collections. Postgres and MongoDB run these arms in
  the e2e matrix, which does not report coverage.
- Lines 787–1131, `count`/`findMany` pagination fallbacks for
  post-filtered reads when Payload returns an unpaginated result, and
  `rethrowAsOperation` for non-Error causes.
- The failure contract is pinned by `adapter-failures.test.ts`: bulk
  partial failure, malformed bulk results, empty-where refusal, and
  the post-filter with no exact match. Query semantics are pinned by
  `adapter-differential.test.ts`.

### `provider-better-auth/src/cookies.ts` (branches 89.13%)

- Line 105: the admin-session cookie name override from
  `advanced.cookies.admin_session.name`.
- Lines 162–175: the `?? defaults ?? secureDefault` attribute chain
  for cookies with no per-cookie or default attributes, and a config
  with no session-token entry.

All of these are configuration permutations of Better Auth's
`advanced` options rather than security branches. The secure-prefix
and clearing behaviour is covered by `cookies.test.ts`.

### `provider-better-auth/src/port.ts` (77% branches)

- Lines 829–861, `narrowApiKeyVerification`. Another change in
  progress adds a real-engine `verifyApiKey` test (with
  `@better-auth/api-key`) that covers this. Raise the floor once it
  lands.
- Lines 561–689: legacy-cookie coexistence and multi-session
  enumeration arms for malformed `$context` shapes, which are
  untyped-input narrowing on Better Auth internals.
- Lines 1022–1167: `createBetterAuthProviderFromUnknown` arms for
  instances missing optional internal-adapter methods.
  `port-failures.test.ts` covers the revoke and verify arms; the rest
  are capability-probe fallbacks.
