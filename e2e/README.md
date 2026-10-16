# End-to-end suite

One Playwright suite, run against both reference integrations:
`examples/basic` (Next, Payload v3) and `examples/tanstack-start`
(TanStack Start, Payload v4 beta), on SQLite (all engines), Postgres,
and Mongo (Chromium). Specs assert shared markers and HTTP behavior,
never framework-default text. See the configs in this folder for
ports and the root `README.md` for the commands.

House rules for specs:

- Admin calls go through `adminContext(browser, baseURL)`
  (`admin-session.ts`): one seeded-admin login per run. Concurrent
  admin logins race on Payload's per-user sessions array and 403 each
  other.
- Navigate with `gotoOwn` / `gotoSettled` (`helpers.ts`) after sign-in:
  they wait for hydration and absorb WebKit/Gecko navigation races.
- Calls whose responses swap or expire cookies (sign-out, Better Auth
  impersonation) run as in-page `fetch` (`pageFetch`): WebKit's
  `page.request` may keep a cookie the response expires.
- Users promoted to `admin` are demoted again before the spec ends;
  later specs share the server and database.

## Capability coverage (issue #84)

| Capability                         | Spec                      | Example wiring                                                                  |
| ---------------------------------- | ------------------------- | ------------------------------------------------------------------------------- |
| Organizations (CAP-11)             | `organizations.spec.ts`   | `authLink({ organizations: { enabled: true } })`                                |
| Impersonation (CAP-8)              | `impersonation.spec.ts`   | Better Auth `admin()` + its declared fields; dev-only `/api/dev-provider-admin` |
| Legacy payload-auth sessions (#51) | `legacy-sessions.spec.ts` | `legacySessions` on the engine and `authLink` (same window object)              |
| MFA step-up (route level)          | `security.spec.ts`        | Better Auth `twoFactor()`, `requireRoles({ requireMfa: true })`                 |
| MFA role policy (CAP-6)            | `mfa-policy.e2e.ts`       | `E2E_MFA_POLICY=1` variant: `policies.requireMfaForRoles: ['auditor']`          |

`policies.requireMfaForRoles` gets its own config,
`playwright.mfa.config.ts` (`bun run e2e:mfa`, :3104, its own
`payload-mfa.db`). Wiring requires every registered provider to
declare the `mfa` capability, and both examples also register
Auth.js, which cannot (decision D4) — the plugin throws
`UnsupportedCapabilityError` at config time. With `E2E_MFA_POLICY=1`
`examples/basic` registers Better Auth alone and gates a dedicated
`auditor` role (never `admin`: the seeded admin is a local-credential
session with no MFA proof, and it grants the role). The spec is named
`*.e2e.ts` so the matrix configs (`*.spec.ts`) never pick it up. Better
Auth's `twoFactor()` caps `/two-factor/*` at 3 requests per 10s per IP,
so the spec waits out 429s rather than asserting through them.

Known gap: on Payload v4 with a numeric-id adapter, a create by a
provider-session user fails `createdBy` validation (the plugin
strategy projects `req.user.id` as a string). The plugin-endpoint
organization-create test is `fixme` on v4 and the lifecycle test seeds
its organizations as the seeded admin there; see the header of
`organizations.spec.ts`.

## Not covered here, and why

- **`roleValues` / `projectRolesAs`.** A non-identity mapping changes
  the stored role values of the shared example database (and its
  Postgres enum), which every other spec and every local dev database
  would then have to carry; the translation is only observable at the
  storage edge, which integration tests pin directly
  (`integration-role-values.test.ts`).
- **`reqUser: 'document'`.** Changes only what builder access
  functions see on `req.user`; the examples have none that read
  non-projected fields. Pinned by `integration-req-user-document.test.ts`.
- **SSO domain enforcement, social OAuth, Google One Tap, phone
  sign-in.** Each needs an external identity provider or SMS gateway
  (a real IdP, Google's One Tap JWKS, an SMS sender). They are pinned
  without hosted services instead: OAuth against local mock IdPs
  (`oauth.test.ts` in each provider adapter), SSO domain enforcement
  in the plugin (`integration-sso.test.ts`), One Tap token
  verification (`provider-authjs` `recipes.test.ts`), and phone
  linking (`phone.test.ts`).
- **Multi-session (Better Auth `multiSession`).** Not wired in the
  examples; device-session listing and logout are pinned by
  `provider-better-auth`'s `multi-session.test.ts`.
