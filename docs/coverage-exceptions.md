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
| `plugin/src/collections.ts`                           | 95 / 95 / 88 / 95 | see below |
| `plugin/src/compat-shim.ts`                           | 95 / 95 / 95 / 95 | at target |
| `plugin/src/credential-gate.ts`                       | 95 / 95 / 95 / 95 | at target |
| `plugin/src/endpoints.ts`                             | 95 / 95 / 91 / 95 | see below |
| `plugin/src/hooks.ts`                                 | 95 / 95 / 95 / 95 | at target |
| `plugin/src/lifecycle.ts`                             | 95 / 95 / 94 / 95 | see below |
| `plugin/src/organizations.ts`                         | 95 / 95 / 95 / 95 | see below |
| `plugin/src/repository.ts`                            | 95 / 95 / 95 / 95 | at target |
| `plugin/src/server.ts`                                | 95 / 95 / 94 / 95 | see below |
| `plugin/src/session.ts`                               | 95 / 95 / 95 / 95 | see below |
| `plugin/src/strategy.ts`                              | 95 / 95 / 95 / 95 | see below |
| `plugin/src/verified-email.ts`                        | 95 / 95 / 95 / 95 | at target |
| `provider-authjs/src/adapter.ts`                      | 95 / 95 / 95 / 95 | see below |
| `provider-authjs/src/callbacks.ts`                    | 95 / 95 / 95 / 95 | at target |
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

### `plugin/src/collections.ts` (branches 88.91%)

- Lines 45 and 85: role narrowing on a user without a `roles` array,
  and a host-supplied access function in a slot the belt wraps
  (untyped-input narrowing).
- Lines 297, 800, 804 and 808: `suspensionActive`/`suspendRevokeHook`
  arms for a non-record document (untyped-input narrowing).
- The re-entrant account-status read is pinned by a unit test
  (`collections-fail-closed.test.ts`); the engine never reaches it,
  because the status read runs on its own request.
- Since GHSA-mjvh, a dead account's Payload local JWT / API key
  resolves no user at authentication (`credential-gate.ts`), so the
  operation-layer provider-owned refusals are reached by the unit
  tests and Local API calls handed such a user, not by REST walks.
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

### `plugin/src/lifecycle.ts` (branches 94.73%)

`integration-lifecycle.test.ts` drives the `onInit` subscription on
real Payload: the verified-email sync, application failure, a failed
linked-user lookup, and a throwing handler (Error and non-Error
causes), each logged and never thrown into the provider.

- Line 65: registry miss.

### `plugin/src/organizations.ts` (branches 99.05%)

Measured 100 / 100 / 99.05 / 100 (lines / functions / branches /
statements). The floor is capped at 95. The
three uncovered arms are:

- Line 178: `roleRank` returning `Infinity` for a role that is not in
  `orgRoles`. Its only caller, `mayAssignRole`, checks that both roles
  are configured before ranking them, so the unknown-role arm cannot
  run. The arm stays so that an unknown role can never outrank a
  configured one if a future caller skips that check.
- Line 885: `refuseWhileImpersonating` when the second
  `sessions.verify` fails. Every endpoint verifies the same session
  just before this call, so it can fail only if the session is revoked
  between the two reads. If that happens, the check falls back to the
  `req.user` actor alone (`isImpersonating(req)`), which still refuses
  an impersonated request.
- Line 1032: `orgRoles.at(-1) ?? null` in the invite endpoint. Wiring
  falls back to `owner`/`admin`/`member` when `orgRoles` is empty, so
  the list is never empty at runtime.

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

### `plugin/src/session.ts` (branches 96.69%)

The SSO domain gate for an email-less session (the claim reaches the
guard as `null`, never as the deprecated `email` alias) is tested in
`session.test.ts`.

- Lines 105 and 132: registry miss.
- Line 205: the per-request verify memo on a request whose `context`
  is not a record. Payload always supplies a context object.
- Line 396: the `email` log field on the provisioning-refused path for
  a session with no email claim. That path needs a `UserExistsError`
  from `create`, and only an email-carrying session creates.

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

### `provider-better-auth/src/engine.ts` (branches 96.5%)

The `trustedProviders` check for `email-password` (safe only while
`emailAndPassword.requireEmailVerification` stays on) and for social
providers without an explicit `true` requirement is tested in
`engine.test.ts`.

- `fields ?? []` on builder custom fields (a `Partial` record value
  the builder declared as `undefined`).
- Two `if#1` arms in the plugin-id and derived-model loops
  (untyped-input narrowing).

### `provider-better-auth/src/adapter.ts` (branches 96.2%)

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
