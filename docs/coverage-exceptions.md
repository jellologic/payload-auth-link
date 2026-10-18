# Coverage floors and exceptions

`vitest.config.ts` sets a per-file coverage floor for every
auth-critical file (issue #86). The target is 95% on every metric.
Where a file is below that, its floor is the measured value rounded
down, and this page says which branches are still uncovered and why.

Raise a floor whenever coverage improves. Never lower one without
updating this page: a lower floor means a security-relevant branch
lost its test.

Coverage is measured on the workspace **sources**. `vitest.config.ts`
aliases every `@payload-auth-link/*` import to `packages/<name>/src`
(`vitest.shared.ts`), so a real-engine suite that boots the plugin by
package name runs, and is credited to, `plugin/src`. Before issue #110
those imports resolved to `dist`, and files reached only that way
(`lifecycle.ts`, `verified-email.ts`) read as 5% and 0%.

## Floors

Each cell is lines / functions / branches / statements.

| File                                                  | Floor             | Notes     |
| ----------------------------------------------------- | ----------------- | --------- |
| `core/src/cookies.ts`                                 | 95 / 95 / 95 / 95 | at target |
| `core/src/use-cases/ensure-linked-user.ts`            | 95 / 95 / 95 / 95 | at target |
| `plugin/src/access.ts`                                | 95 / 95 / 95 / 95 | at target |
| `plugin/src/audit.ts`                                 | 95 / 95 / 95 / 95 | at target |
| `plugin/src/collections.ts`                           | 95 / 95 / 91 / 95 | see below |
| `plugin/src/compat-shim.ts`                           | 95 / 95 / 95 / 95 | at target |
| `plugin/src/credential-gate.ts`                       | 95 / 95 / 95 / 95 | at target |
| `plugin/src/endpoints.ts`                             | 95 / 95 / 95 / 95 | see below |
| `plugin/src/hooks.ts`                                 | 95 / 95 / 95 / 95 | at target |
| `plugin/src/lifecycle.ts`                             | 95 / 95 / 95 / 95 | at target |
| `plugin/src/mapping.ts`                               | 91 / 95 / 92 / 91 | see below |
| `plugin/src/options.ts`                               | 92 / 95 / 90 / 92 | see below |
| `plugin/src/organizations.ts`                         | 95 / 95 / 95 / 95 | see below |
| `plugin/src/repository.ts`                            | 95 / 95 / 95 / 95 | at target |
| `plugin/src/server.ts`                                | 95 / 95 / 95 / 95 | see below |
| `plugin/src/services.ts`                              | 78 / 80 / 83 / 78 | see below |
| `plugin/src/session.ts`                               | 95 / 95 / 95 / 95 | see below |
| `plugin/src/strategy.ts`                              | 95 / 95 / 95 / 95 | see below |
| `plugin/src/verified-email.ts`                        | 95 / 95 / 95 / 95 | at target |
| `provider-authjs/src/adapter.ts`                      | 95 / 95 / 95 / 95 | see below |
| `provider-authjs/src/callbacks.ts`                    | 95 / 95 / 95 / 95 | at target |
| `provider-authjs/src/credentials.ts`                  | 95 / 95 / 93 / 95 | see below |
| `provider-authjs/src/engine.ts`                       | 95 / 95 / 95 / 95 | at target |
| `provider-authjs/src/port.ts`                         | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/adapter.ts`                 | 95 / 95 / 95 / 95 | see below |
| `provider-better-auth/src/cookies.ts`                 | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/engine.ts`                  | 95 / 95 / 95 / 95 | see below |
| `provider-better-auth/src/events.ts`                  | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/port.ts`                    | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/session-provenance.ts`      | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/session-token-redaction.ts` | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/step-up.ts`                 | 95 / 95 / 95 / 95 | at target |
| `provider-better-auth/src/where.ts`                   | 95 / 95 / 95 / 95 | at target |
| `web/src/authz.ts`                                    | 95 / 95 / 95 / 95 | at target |
| `web/src/verify.ts`                                   | 95 / 95 / 95 / 95 | at target |

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

### `plugin/src/collections.ts` (branches 91.68%)

Unit tests now pin the field-collision messages (identities-specific
and generic), the adopted roles select's own `defaultValue`, the phone
field's E.164 `validate`, host-declared `delete`/`readVersions` access
behind the belt, the fail-closed defaults for a user without a `roles`
array, and the suspend-revoke hook skipping a provider without
`revokeUserSessions` or a non-record document.

- Line 236: `linkableMarkerHook` for an operation that is neither
  `create` nor `update`. Payload runs `beforeChange` for those two only.
- Line 800: `assertNever` on the account decision (exhaustive switch).
- Lines 887 and 896–897: the belt's fallback for an unfilled
  `update`/`delete`/`unlock` slot. Both call sites pass the access
  through `withDefaultUserAccess` first, which fills every slot, so
  the fallback cannot run. It stays as a fail-safe if a future caller
  skips the defaults.
- The re-entrant account-status read is pinned by a unit test
  (`collections-fail-closed.test.ts`); the engine never reaches it,
  because the status read runs on its own request.
- Since GHSA-mjvh, a dead account's Payload local JWT / API key
  resolves no user at authentication (`credential-gate.ts`), so the
  operation-layer provider-owned refusals are reached by the unit
  tests and Local API calls handed such a user, not by REST walks.
- Lines 728–780: `reqUser: 'document'` arms for a local session
  without a `context` record, without `findByID`, or whose user lacks
  `email`/`roles` (Payload always supplies them).
- The remaining arms (84, 247, 351, 425, 449, 534, 571, 641, 927, 929,
  1047, 1060, 1085, 1185, 1188, 1226 and 1297) are `?? default` and
  `isRecord(...) ? ... : undefined` narrowing on documents and config
  Payload has already validated, or a `roleValues` lookup on a
  configured role (every configured role has a value).

### `plugin/src/endpoints.ts` (branches 98.68%)

Measured 100 / 100 / 98.68 / 100. The registry-miss arms (a provider
id the registry lists but no longer resolves) and a cookie name two
providers share are pinned by `endpoints.test.ts`. The one uncovered
arm:

- Line 254: `?? fallback` on a user-reload error with no `cause`. The
  repository always wraps the storage failure as the cause.

### `plugin/src/mapping.ts` (branches 92.23%)

Measured 91.37 / 100 / 92.23 / 91.37 (lines / functions / branches /
statements). Maps provider documents onto the plugin's fields. The
uncovered arms are untyped-input narrowing on rows the plugin itself
wrote, plus one exhaustive-switch default:

- Lines 93–112 (`toIdentityRow`): a row that is not a record, a blank
  `providerUserId`, an unparsable email, and a falsy `linkedAt`. The
  engine's own tables always hold well-formed rows, so each arm needs
  a document that bypassed Payload validation; the dropping arms fail
  safe (the row is skipped with a warning).
- Line 202: the `identities` field not being an array — same
  narrowing kind.
- Line 296: the `phone` spread for `input.phone === undefined`; the
  callers that reach mapping always project a phone for sessions
  carrying one, and `undefined` means the input type had none.
- Line 336: `assertNever(actor)` on the actor union — exhaustive by
  construction.

### `plugin/src/options.ts` (branches 90.2%)

Measured 92.5 / 100 / 90.2 / 92.15. Config validation; the uncovered
arms are all fail-fast `InvalidConfigError`/narrowing paths whose
sibling errors are tested, each needing a config shape no test builds:

- Line 374 and 417: a stored-role value or timestamp that fails its
  `parse`/date check — the tested configs only carry valid ones.
- Line 421: `roleManagerRoles` resolving to an empty list (the default
  derivation always yields at least one role).
- Line 453: an `engine` slot left undefined where both adapters
  declare one.
- Lines 502–512: `roleValues` sanity arms (an unknown canonical role,
  an empty stored value, an owner-role alias) on maps the tested
  configs declare correctly.
- Line 610: `assertNever` on the resolved-provider union.
- Lines 679–683: `roleManagerRoles` empty or listing a role outside
  `roles`.
- Line 714: `organizations.ssoProviders` naming an unregistered
  provider id.
- Line 777: `emailVerifiedField` colliding with a plugin-managed
  users-collection field.

### `plugin/src/organizations.ts` (branches 98.77%)

Measured 100 / 100 / 98.77 / 100 (lines / functions / branches /
statements). The floor is capped at 95. The four uncovered arms are:

- Line 178: `roleRank` returning `Infinity` for a role that is not in
  `orgRoles`. Its only caller, `mayAssignRole`, checks that both roles
  are configured before ranking them, so the unknown-role arm cannot
  run. The arm stays so that an unknown role can never outrank a
  configured one if a future caller skips that check.
- Line 907: `refuseWhileImpersonating` throwing on a `presentedActor`
  that is absent. Every endpoint resolves the presented session just
  before this call, so the arm needs a session that disappears between
  the two reads; the `req.user` actor check still refuses the request
  in that case.
- Line 933: the list-read audit when the session re-verify fails. The
  verify passing (and the audit landing) is the tested path; the
  failure arm refuses the read before any audit is due.
- Line 1066: `orgRoles.at(-1) ?? null` in the invite endpoint. Wiring
  falls back to `owner`/`admin`/`member` when `orgRoles` is empty, so
  the list is never empty at runtime.

### `plugin/src/server.ts` (branches 98.46%)

Measured 99.4 / 100 / 98.46 / 99.4. Registry misses on every provider
walk (`firstProviderWith`, `allProvidersWith`, `revokeSession`) are
pinned by `server-failures.test.ts`. The one uncovered arm:

- Line 527: `sessionCookie` re-checking `capable[0]` after the length
  check. This is unreachable; the check is there for
  `noUncheckedIndexedAccess`.

(The former second arm — `wired.roleValues[role] ?? role` on a role
with no stored value — is covered since the round-4 audit tests.)

### `plugin/src/services.ts` (branches 83.33%)

Measured 78.57 / 80 / 83.33 / 78.57. Builds the port's repositories
plus the SSO-domain gate. The gate is WIRED only when the app
configures organizations with verified domains AND SSO providers
(otherwise the property is spread away), so suites without that
configuration never execute it; the organizations integration suites
exercise the governed path through REST. Uncovered arms:

- Line 64: a provider id that is not one of the configured
  `ssoProviders` — early allow without a database read.
- Line 67: `email === null` — an email-less session can never match a
  verified domain, so the gate refuses it. Every session the suites
  present to the gate carries an email claim.

The rest of the file is thin plumbing around the repositories, whose
fail-loud behavior is pinned in the repository suites it delegates to.

Every fail-loud branch (revoke, revoke-all, verifyApiKey, mint and
list refusals) and the `verifyApiKey` owner gate (GHSA-j68x: no linked
user, suspended, store error) are covered by `server-failures.test.ts`.

### `plugin/src/session.ts` (branches 98.34%)

The SSO domain gate for an email-less session (the claim reaches the
guard as `null`, never as the deprecated `email` alias) is tested in
`session.test.ts`, as is the per-request verify memo's cache hit
(`requestVerifiedSession`).

- Line 156: registry miss in the stale-cookie warning walk. (The
  former second arm — the `email` log field on the provisioning-refused
  path — is covered since the round-4 audit tests.)

### `plugin/src/strategy.ts` (branches 95.23%)

The `organizationId` projection under `reqUser: 'document'` is tested
in `integration-req-user-document.test.ts`; the stored-role projection
drops (and logs) a role with no stored value instead of passing it
through raw (`strategy.test.ts`).

- `?? fallback` on an error cause (repository errors always carry one).
- `payloadUser.assurance !== undefined`: the strategy always projects
  from a verified session, which always carries assurance.

### `provider-authjs/src/adapter.ts` (branches 97.56%)

`adapter-failures.test.ts` pins the fail-loud contract: every
unmappable document is an `AdapterMappingError`, every Local API
failure an `AdapterOperationError`, never a `null` read as "not
found". The remaining arms are `?? {}` spreads for optional fields
that Auth.js never sends as `undefined` (lines 159, 397, 497) and
`getUserByAccount` with an account whose user row is gone (line 339).

### `provider-authjs/src/callbacks.ts` (branches 97.36%)

At target. The D6 stamp guards (the adapter returning no `Date`, a
missing, blank or mismatched email on either side), the CAP-14 event
narrowing, and the builder-session credential scrub (nested
`sessionToken` keys, token-bearing strings, shared values, cycles) are
tested in `callbacks-guards.test.ts`; the scrub also runs against the
real engine in `session-shape-engine.test.ts`. The remaining arms are
`input.user ?? {}` and `image === undefined` in the allowlisted
session (Auth.js always passes a user, with `image`), and a sign-in
`user` without an `id` in the jwt callback (lines 159, 163, 304).

### `provider-authjs/src/credentials.ts` (branches 93.44%)

Measured 95.83 / 100 / 93.44 / 95.83. The Auth.js credentials
provider (local sign-in through the provider, issue #54). Uncovered
arms are the mapping guards for documents that bypassed Payload
validation, and one repository error wrap:

- Line 168: the matched user document is not a record.
- Line 180: the matched document carries no `email`.
- Line 245: `credentials register` returning a document without an
  `auId` — the repository errors instead of returning such a row.
- Line 252: the `?? cause` fallback on a repository error with no
  cause (repository errors always carry one).

### `provider-better-auth/src/engine.ts` (branches 96.62%)

The `trustedProviders` check for `email-password` (safe only while
`emailAndPassword.requireEmailVerification` stays on) and for social
providers without an explicit `true` requirement is tested in
`engine.test.ts`.

- `fields ?? []` on builder custom fields (a `Partial` record value
  the builder declared as `undefined`).
- Two `if#1` arms in the plugin-id and derived-model loops
  (untyped-input narrowing).

### `provider-better-auth/src/adapter.ts` (branches 96.04%)

`adapter-unit.test.ts` drives the raw adapter without Better Auth's
adapter factory (issue #113): schema validation, malformed Local API
results, the empty-where `update` guard (the factory answers that case
itself, so no engine suite can reach the adapter's own guard), joins,
and adopted-model host validation. Still uncovered:

- `planFor`'s unknown-slug throw: `resolveModel` refuses unknown
  models first.
- `asModelRow`'s throw: rows are always built by `toBaRow`.
- Host validation: the per-slug cache hit (two adopted models on one
  slug), a non-array `fields`, a non-string field `type`, and a model
  with no validated field set (untyped-input narrowing).
- `findOne`'s post-filter paging past a full 100-row page.

Fixed (issue #113): host validation used to run only for the models
planned by the adapter's FIRST operation, so when another model's
`findOne` ran first the adopted collections were never validated and
their relationship fields stayed unclassified. It now validates every
adopted model on the first operation (`adapter-unit.test.ts`). A
missing REQUIRED Better Auth field fails fast; a missing OPTIONAL one
(Better Auth 1.7's `jwks.expiresAt` on a payload-auth layout, the
engine's `session.authenticationMethod`) is tolerated: writes to it are
dropped and reads see it unset. Without `authenticationMethod` no MFA
provenance is recorded, which fails closed. The password
injection for local-strategy auth collections is decided on each
create (`integration-adopt-local-strategy.test.ts`).
