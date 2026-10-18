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
  `gotoSettled` first waits until the current page has no request in
  flight: leaving a page mid-load cancels its module graph or loader
  fetches, which WebKit reports as page errors ("Importing a module
  script failed", "Load failed") in the dev-server log.
- Calls whose responses swap or expire cookies (sign-out, Better Auth
  impersonation) run as in-page `fetch` (`pageFetch`): WebKit's
  `page.request` may keep a cookie the response expires.
- Users promoted to `admin` are demoted again before the spec ends;
  later specs share the server and database.

## Capability coverage (issue #84)

| Capability                          | Spec                       | Example wiring                                                                  |
| ----------------------------------- | -------------------------- | ------------------------------------------------------------------------------- |
| Organizations (CAP-11)              | `organizations.spec.ts`    | `authLink({ organizations: { enabled: true } })`                                |
| Impersonation (CAP-8)               | `impersonation.spec.ts`    | Better Auth `admin()` + its declared fields; dev-only `/api/dev-provider-admin` |
| Legacy payload-auth sessions (#51)  | `legacy-sessions.spec.ts`  | `legacySessions` on the engine and `authLink` (same window object)              |
| MFA step-up (route level)           | `security.spec.ts`         | Better Auth `twoFactor()`, `requireRoles({ requireMfa: true })`                 |
| MFA role policy (CAP-6)             | `mfa-policy.e2e.ts`        | `E2E_MFA_POLICY=1` variant: `policies.requireMfaForRoles: ['auditor']`          |
| Social OAuth (CAP-3)                | `idp-oauth.e2e.ts`         | `E2E_MOCK_IDP` variant: Better Auth `genericOAuth` → mock OIDC provider         |
| Google One Tap (CAP-4)              | `idp-oauth.e2e.ts`         | `E2E_MOCK_IDP` variant: Better Auth `oneTap()`; Auth.js One Tap recipe          |
| Phone sign-in (CAP-9)               | `idp-phone.e2e.ts`         | `E2E_MOCK_IDP` variant: Better Auth `phoneNumber()`; dev-only `/api/dev-sms`    |
| SSO domain enforcement (CAP-15)     | `idp-sso.e2e.ts`           | `E2E_MOCK_IDP` variant: Auth.js OIDC + `organizations.ssoProviders: ['authjs']` |
| Multi-session (CAP-13b)             | `idp-multi-session.e2e.ts` | `E2E_MOCK_IDP` variant: Better Auth `multiSession()`                            |
| `roleValues` (#56), `reqUser` (#57) | `idp-roles.e2e.ts`         | `E2E_MOCK_IDP` variant: `editor` stored as `contentEditor`; `memos` access      |

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

## External-IdP variant (`idp-*.e2e.ts`)

`playwright.idp.config.ts` (`bun run e2e:idp`, :3105,
`payload-idp.db`) and `playwright.tanstack-idp.config.ts`
(`bun run e2e:tanstack-idp`, :3205, `src/payload-idp.db`) run the same
specs against each example with `E2E_MOCK_IDP=http://localhost:3190`.
Their first `webServer` is `mock-idp.ts`: a local OpenID Connect
provider (discovery, JWKS, an HTML consent form the specs fill, token
with an RS256 `id_token`, userinfo) that also mints Google-shaped One
Tap ID tokens. It imports node builtins only. The flag wires, in each
example's `lib/e2e-idp.ts`:

- Better Auth `genericOAuth` (provider `mock-idp`), `oneTap`,
  `phoneNumber` (codes captured in a dev SMS outbox read through
  `/api/dev-sms`, 404 in production), and `multiSession`;
- Auth.js: an OIDC provider (`mock-sso`, trusted for
  `email_verified`) and the One Tap recipe
  (`createGoogleOneTapAuthorize` with `jwksUrl` on the mock);
- `authLink`: `organizations.ssoProviders: ['authjs']`,
  `roleValues: { editor: 'contentEditor' }`, `reqUser: 'document'`,
  plus a host `department` field and a `memos` collection whose
  access reads it.

The variant needs its own database and run: it changes stored data
shapes (role values, the extra field and collection), and making
Auth.js the SSO provider refuses every Auth.js session on an
unverified domain, which the default suite's Auth.js specs rely on.
Without the flag nothing here is wired. CI runs Chromium and WebKit
(`e2e-idp`, `e2e-tanstack-idp`).

## Not covered end to end, and why

- **Better Auth One Tap success path.** Better Auth's `oneTap`
  verifies the ID token against Google's JWKS, and that URL is
  hardcoded (`@better-auth/core` `verifyGoogleIdToken`). No option
  points it elsewhere, and patching `fetch` would be a monkey-patch.
  The spec covers what can be observed: a token not signed by Google
  is refused (400, no session). The full One Tap sign-in runs on the
  Auth.js recipe, which takes a `jwksUrl`. Google's browser widget
  itself is Google's script and runs in neither.
- **Phone-only linking (`linkingPolicy: 'verified-email-or-phone'`).**
  The policy needs every registered provider to declare `phone`. Both
  examples also register Auth.js, which cannot. The phone spec covers
  phone sign-in into an existing, email-verified user, which links
  through that user's verified email. It also checks the verified
  phone claim syncing onto the Payload user. The phone-only branch
  stays pinned by `ensure-linked-user.test.ts` (core).
