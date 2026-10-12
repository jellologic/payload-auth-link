# Sprint: adversarial review follow-through

Source key: prior result 3 = security review, prior result 1 = architecture review, prior result 5 = types and error-taxonomy review, prior result 2 = test-coverage review, prior result 6 = framework-parity review, prior result 4 = docs and DX review. Zero reviewers failed; all 72 findings plus 3 below-cap observations were readable (one handoff needed a single retry, then read cleanly).

## Goal

Close every high-severity adversarial finding before release by fixing two auth-bypass class defects (host-header session forgery via the verifier fallback and JIT provisioning from unverified emails), one total-auth outage (Auth.js database-strategy session callback crash), one startup outage (Payload v4 plugin-options shape), and the logout cookie-survival defect, while landing the missing enforcement tests that prove each fix, the lint and coverage gates that prevent recurrence, and the getting-started corrections that currently break copy-paste adopters; medium-severity hardening follows in the same sprint only while the validation gates stay green, and low-severity polish waits in the backlog.

## Backlog

| ID      | Severity | Area             | Effort | Title                                                                                                                          | Acceptance criteria                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------- | -------- | ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-1   | High     | Security         | M      | Harden session-origin resolution and require valid baseUrl (r3 verify.ts:54; r1 engine.ts:95; r5 engine.ts:163)                | Single shared origin resolver used by packages/web/src/verify.ts and packages/provider-authjs/src/engine.ts; production verifier construction without baseUrl throws instead of falling back to forwarded host headers; malformed baseURL throws InvalidConfigError at wiring, never a per-request TypeError; proven by new unit tests in the web verifier suite and packages/provider-authjs/src/**tests**/engine.test.ts covering unset-baseUrl-in-production, invalid-baseURL fail-fast, and forwarded-header fallback behavior |
| SEC-2   | High     | Security         | M      | Gate JIT provisioning on verified email (r3 ensure-linked-user.ts:84)                                                          | First-touch user creation with an unverified provider email returns UnverifiedEmailError (or quarantines without roles) exactly like the link path in packages/core/src/use-cases/ensure-linked-user.ts; proven by a unit test asserting unverified create-path yields UnverifiedEmailError and verified create-path still provisions                                                                                                                                                                                              |
| SEC-3   | Medium   | Security         | M      | Apply case-insensitive post-filter to mutating adapter ops (r3 adapter.ts:590)                                                 | update, updateMany, delete, deleteMany in packages/provider-better-auth/src/adapter.ts exact-match insensitive clauses (read-then-match-by-id) or reject them; proven by adapter unit tests showing an insensitive update rewrites only the exact row and bulk ops no longer over-match                                                                                                                                                                                                                                            |
| SEC-4   | Medium   | Security         | S      | Guard empty where in deleteMany and updateMany (r3 adapter.ts:653)                                                             | Empty where in deleteMany and updateMany throws or no-ops like delete and update do in packages/provider-better-auth/src/adapter.ts; proven by unit tests asserting no full-collection write on empty where                                                                                                                                                                                                                                                                                                                        |
| SEC-5   | Medium   | Security         | S      | Default trustHost to false in Auth.js engine (r3 engine.ts:156)                                                                | packages/provider-authjs/src/engine.ts defaults trustHost to false with explicit opt-in documented for trusted proxies; proven by an engine unit test asserting the default and an opt-in test                                                                                                                                                                                                                                                                                                                                     |
| SEC-6   | Medium   | Security         | M      | Narrow and document the JWT post-logout replay window (r3 engine.ts:200)                                                       | Credentials deployments default to a short session maxAge, the stateless-JWT revocation limit is documented at the engine boundary, and a denylist hook is offered or explicitly deferred to Accepted risks; proven by an engine unit test on the maxAge default plus a docs assertion                                                                                                                                                                                                                                             |
| SEC-7   | Medium   | Security         | S      | Gate example admin seeding and dev secrets behind explicit dev-only flags (r3 payload.config.ts:94; r3 dev-secret observation) | examples/basic/payload.config.ts no longer seeds a known-password admin on every fresh database without an explicit dev-only env flag and env-provided password, and example PAYLOAD_SECRET fallbacks in examples/basic/lib/auth.ts and sibling modules are labeled local-dev-only or removed; proven by a fresh-database boot test showing no seeded admin without the flag                                                                                                                                                       |
| SEC-8   | Medium   | Security         | S      | Emit no-store on session GET and client reader (r3 endpoints.ts:80)                                                            | packages/plugin/src/endpoints.ts session responses carry Cache-Control no-store and packages/react/src/session.ts fetchSessionUser passes cache no-store; proven by an endpoint header assertion test and a fetch-option unit test                                                                                                                                                                                                                                                                                                 |
| SEC-9   | Low      | Security         | S      | Remove signup email-enumeration oracle (r3 authjs-signup/route.ts:35)                                                          | examples/basic/app/api/authjs-signup/route.ts returns a uniform success-shaped response for existing and new emails (out-of-band notice for duplicates); proven by a route test asserting identical status and shape for both cases                                                                                                                                                                                                                                                                                                |
| SEC-10  | Low      | Security         | S      | Validate cookie Domain and Path values (r3 cookies.ts:19)                                                                      | packages/core/src/cookies.ts rejects Domain and Path containing semicolons, commas, whitespace, or controls by throwing like assertCookieName; proven by unit tests for injection and CRLF inputs                                                                                                                                                                                                                                                                                                                                  |
| SEC-11  | Low      | Security         | S      | Normalize email before authorize lookup (r3 credentials.ts:124)                                                                | packages/provider-authjs/src/credentials.ts authorize normalizes via parseEmail before querying, failing closed to null on invalid input while keeping the dummy-hash timing path; proven by a unit test where User@X.com signs in with the right password                                                                                                                                                                                                                                                                         |
| SEC-12  | Low      | Security         | S      | Funnel SignOutButton redirectTo through safeRedirectPath (r3 components.tsx:62)                                                | packages/react/src/components.tsx wraps redirectTo in safeRedirectPath before navigation; proven by a component test asserting an absolute-URL prop does not navigate off-origin                                                                                                                                                                                                                                                                                                                                                   |
| SEC-13  | Medium   | Security         | M      | Add rate limiting to example auth routes and document builder ownership (r3 below-cap observation)                             | Example signup, sign-in, and authorize paths carry a throttle (429 on abuse) and docs state library-level limiting is builder-owned; proven by a route test asserting 429 after the threshold plus the documented guidance                                                                                                                                                                                                                                                                                                         |
| ARCH-1  | High     | Architecture     | M      | Move cookie-plugin selection out of the Better Auth engine (r1 engine.ts:7)                                                    | packages/provider-better-auth/src/engine.ts takes composed plugins with no framework default while @payload-auth-link/next and @payload-auth-link/tanstack-start supply their own; proven by engine unit tests showing zero framework imports by default and adapter tests for each framework plugin                                                                                                                                                                                                                               |
| ARCH-2  | High     | Architecture     | S      | Close dependency-rule gaps in the lint config (r1 eslint config)                                                               | Root eslint.config.mjs gains a web core-only block, a tanstack-start block mirroring the next block, and react, next, tanstack bans in the provider block (finding cited packages/eslint.config.mjs; the real file is the root config); proven by bun run lint passing plus a fixture test showing a web-to-react import now fails lint                                                                                                                                                                                            |
| ARCH-3  | Medium   | Architecture     | M      | Hoist one decideAuthRedirect into web (r1 middleware.ts:29)                                                                    | A single framework-free decideAuthRedirect in @payload-auth-link/web backs both packages/next/src/middleware.ts and packages/tanstack-start/src/middleware.ts as thin adapters; proven by web unit tests for bounce matrix plus both adapter suites green                                                                                                                                                                                                                                                                          |
| ARCH-4  | Medium   | Architecture     | M      | Share the secure-cookie prefix and derive names from SDK getters (r1 cookies.ts:7)                                             | Both providers import one prefix instead of copying the __Secure- const and derive session cookie names from the SDKs' own getters; proven by kept drift tests in both providers' cookie suites                                                                                                                                                                                                                                                                                                                                    |
| ARCH-5  | Medium   | Architecture     | S      | Decide the credentials-store question and record it (r1 credentials.ts:32)                                                     | Either packages/provider-authjs/src/credentials.ts authenticates against Payload native password auth or a rationale for the separate scrypt store is recorded with a tracked follow-up; proven by the credentials e2e suite green on the chosen path plus the recorded decision                                                                                                                                                                                                                                                   |
| ARCH-6  | Medium   | Architecture     | M      | Route provider registration through the UserRepository port with Result returns (r1 credentials.ts:164; r5 credentials.ts:164) | Provider register flows through packages/core/src/use-cases/register-user.ts and returns ResultAsync with InvalidEmailError, WeakPasswordError, UserExistsError, AdapterOperationError instead of throwing; proven by unit tests asserting err values for each expected failure                                                                                                                                                                                                                                                    |
| ARCH-7  | Medium   | Architecture     | S      | Add one createServices factory for strategy and endpoints (r1 strategy.ts:23)                                                  | packages/plugin/src/strategy.ts and packages/plugin/src/endpoints.ts share one createServices wiring factory; proven by plugin strategy and endpoint suites green with a single wiring change point                                                                                                                                                                                                                                                                                                                                |
| ARCH-8  | Medium   | Architecture     | S      | Single-read session verify owned by ensureLinkedUser (r1 session.ts:108)                                                       | packages/plugin/src/session.ts resolveUser no longer double-reads the user before packages/core/src/use-cases/ensure-linked-user.ts; proven by a session-service test asserting one repository read per verification                                                                                                                                                                                                                                                                                                               |
| ARCH-9  | Medium   | Architecture     | S      | Share one parseSessionResponse helper (r1 session.ts:16)                                                                       | packages/react/src/session.ts and packages/web/src/verify.ts parse envelopes through one shared helper; proven by both suites green plus a helper unit test for malformed envelopes failing closed                                                                                                                                                                                                                                                                                                                                 |
| ARCH-10 | Low      | Architecture     | S      | Unify the web re-export barrels (r1 index.ts:18)                                                                               | packages/next/src/index.ts and packages/tanstack-start/src/index.ts share one re-export statement so new web exports cannot diverge adapters; proven by barrel tests asserting identical export sets                                                                                                                                                                                                                                                                                                                               |
| ARCH-11 | Low      | Architecture     | S      | Consume or drop the required plugin secret (r1 options.ts:26; r3 secret observation)                                           | The 32-char secret in packages/plugin/src/options.ts is either consumed for a real purpose or the requirement is dropped in favor of Payload secret; proven by validation tests matching the chosen contract                                                                                                                                                                                                                                                                                                                       |
| TYP-1   | High     | Types and errors | M      | Fix session callback crash for database strategy (r5 callbacks.ts:66)                                                          | packages/provider-authjs/src/callbacks.ts branches on shape (user fields when token absent, token claim when present) so database-strategy sessions no longer throw on params.token.sub; proven by a new database-shape unit test plus the existing jwt-shape tests                                                                                                                                                                                                                                                                |
| TYP-2   | Medium   | Types and errors | S      | Stop upgrading emptied roles to defaultRole (r5 mapping.ts:76)                                                                 | packages/plugin/src/mapping.ts maps an empty persisted roles array to deny (empty or null-record) with defaultRole reserved for undefined legacy docs, and packages/plugin/src/collections.ts marks the roles field required with minRows 1; proven by mapping unit tests for empty versus undefined arrays                                                                                                                                                                                                                        |
| TYP-3   | Medium   | Types and errors | S      | Allowlist AdapterAccount type from storage (r5 adapter.ts:85)                                                                  | packages/provider-authjs/src/adapter.ts validates the stored type against oauth, oidc, email, webauthn and throws AdapterMappingError on mismatch; proven by a unit test with a corrupt type value                                                                                                                                                                                                                                                                                                                                 |
| TYP-4   | Medium   | Types and errors | S      | Log loudly on verify failures (r5 strategy.ts:39)                                                                              | packages/plugin/src/strategy.ts and packages/plugin/src/endpoints.ts log warn for invalid or expired sessions and error with cause for RepositoryError before returning null or 401; proven by strategy and endpoint tests asserting the log calls                                                                                                                                                                                                                                                                                 |
| TYP-5   | Low      | Types and errors | S      | Validate emailVerified dates at authorize (r5 credentials.ts:159)                                                              | packages/provider-authjs/src/credentials.ts narrows stored emailVerified with a NaN check and throws AdapterMappingError on invalid values instead of leaking RangeError; proven by a unit test with a corrupt date string                                                                                                                                                                                                                                                                                                         |
| TYP-6   | Low      | Types and errors | S      | Return SessionInvalidError instead of throwing in verify (r5 session.ts:98)                                                    | packages/plugin/src/session.ts validates empty provider sessionIds into err SessionInvalidError so contract violations yield 401, not 500; proven by a session-service test asserting err on empty sessionId                                                                                                                                                                                                                                                                                                                       |
| TYP-7   | Low      | Types and errors | S      | Narrow the verifier JSON body with isRecord (r5 verify.ts:104)                                                                 | packages/web/src/verify.ts uses isRecord before accessing body.user instead of casting; proven by a verifier unit test passing an array body that fails closed                                                                                                                                                                                                                                                                                                                                                                     |
| TYP-8   | Low      | Types and errors | S      | Validate provider cookie names at wiring (r5 ports.ts:187)                                                                     | Provider sessionCookieNames are validated against the token regex at registry or engine wiring with InvalidConfigError on illegal names; proven by a wiring test asserting fail-fast on a bad name                                                                                                                                                                                                                                                                                                                                 |
| TYP-9   | Low      | Types and errors | S      | Assert row shape in toBaRow and asModelRow (r5 adapter.ts:344)                                                                 | packages/provider-better-auth/src/adapter.ts asserts id presence (and date-typed fields) and throws AdapterOperationError on drift; proven by a unit test with a baId-less row                                                                                                                                                                                                                                                                                                                                                     |
| TYP-10  | Low      | Types and errors | S      | Validate required roles at the boundary (r5 authz.ts:56)                                                                       | packages/web/src/authz.ts validates each required role once per call and throws InvalidRoleError or InvalidConfigError on invalid entries; proven by an authz unit test with a typo-cased role                                                                                                                                                                                                                                                                                                                                     |
| TST-1   | High     | Tests            | M      | Test multi-provider failover and all-fail paths (r2 session.ts:45)                                                             | A session-service test with failingProvider plus workingProvider asserts verify succeeds with a logged warn, and an all-fail case asserts 401; proven by the new tests in the plugin session suite                                                                                                                                                                                                                                                                                                                                 |
| TST-2   | High     | Tests            | S      | Test the JIT create-race retry branch (r2 session.ts:119)                                                                      | A stub UserRepository whose create returns UserExistsError proves winner-readable reread yields ok and still-missing yields SessionInvalidError; proven by the new tests in the plugin session suite                                                                                                                                                                                                                                                                                                                               |
| TST-3   | High     | Tests            | M      | Exercise verification enforcement end to end (r2 auth.ts:29)                                                                   | An integration or e2e case with requireEmailVerification on proves unverified better-auth sign-in yields plugin-session 401; proven by the new case in the better-auth integration or e2e suite                                                                                                                                                                                                                                                                                                                                    |
| TST-4   | Medium   | Tests            | S      | Test multi-provider logout cookie clearing on 200 and 401 (r2 endpoints.ts:23)                                                 | A logout test with two providers (plain plus __Secure- and Domain variants) asserts every Set-Cookie clear on both the 200 and idempotent-401 paths; proven by the new tests in the plugin endpoints suite                                                                                                                                                                                                                                                                                                                         |
| TST-5   | Medium   | Tests            | S      | Add per-file coverage floors for auth-core files (r2 vitest.config.ts:10)                                                      | vitest.config.ts gains per-file or per-package thresholds covering packages/plugin/src/session.ts, strategy.ts, repository.ts (after a fresh bun run coverage run, since cited percentages came from the checked-in report); proven by the coverage gate failing when a floor is artificially raised                                                                                                                                                                                                                               |
| TST-6   | Medium   | Tests            | S      | Replace CI-retry reliance with explicit waits (r2 users-admin.spec.ts:27)                                                      | e2e/users-admin.spec.ts uses an explicit longer timeout or readiness probe for the data-row expect instead of relying on retries:2; proven by the spec passing with retries disabled locally                                                                                                                                                                                                                                                                                                                                       |
| TST-7   | Medium   | Tests            | M      | Add e2e specs for expiry, corrupt rows, provider-down, OAuth, rate limits (r2 auth.spec.ts:88)                                 | New e2e specs cover expired or stale cookie bounces, an OAuth-link smoke path, and a rate-limit throttle assertion beyond the credentials happy path; proven by the new specs in e2e/auth.spec.ts or sibling spec files                                                                                                                                                                                                                                                                                                            |
| TST-8   | Medium   | Tests            | M      | Add Firefox and WebKit to the sqlite e2e matrix (r2 playwright.config.ts:17)                                                   | e2e/playwright.config.ts gains firefox and webkit projects at least for the sqlite matrix; proven by bun run e2e executing all three projects in CI                                                                                                                                                                                                                                                                                                                                                                                |
| TST-9   | Low      | Tests            | S      | Snapshot the a11y exclusion set (r2 a11y.spec.ts:45)                                                                           | e2e/a11y.spec.ts fails on any violation outside the currently excluded set so new chrome regressions are caught; proven by the updated gate passing on the snapshot and failing on an injected violation                                                                                                                                                                                                                                                                                                                           |
| TST-10  | Low      | Tests            | S      | Replace the 10ms sleep with deterministic settling (r2 components.test.tsx:102)                                                | packages/react/src/**tests**/components.test.tsx awaits DELETE-call settling plus microtask drain instead of sleeping; proven by the negative test passing reliably under load                                                                                                                                                                                                                                                                                                                                                     |
| TST-11  | Low      | Tests            | S      | Scope shared mocks per test (r2 server-provider.test.tsx:6)                                                                    | packages/next/src/**tests**/server-provider.test.tsx and sibling client tests use beforeEach with vi.clearAllMocks and fresh arrays; proven by the suites green with an added second test inheriting no state                                                                                                                                                                                                                                                                                                                      |
| TST-12  | Low      | Tests            | S      | Trim tautological entrypoint tests (r2 index.test.ts:5)                                                                        | React, next, tanstack-start, plugin, core, and provider-better-auth keep at most one re-export smoke per package asserting the real callable contract; proven by the trimmed suites with no typeof-only assertions                                                                                                                                                                                                                                                                                                                 |
| PAR-1   | High     | Parity           | M      | Ship a version-agnostic plugin entry plus an honest v4 peer range (r6 index.ts:18; r4 plugin package.json:36)                  | packages/plugin/src/index.ts no longer depends on definePlugin argument shape (plain version-agnostic export or raw.options normalization) and peer ranges admit the payload 4.0.0-beta line used by examples/tanstack-start; proven by a boot test feeding v4-shaped raw keys plus a v4 install resolving without ERESOLVE                                                                                                                                                                                                        |
| PAR-2   | High     | Parity           | S      | Expire cookies on the failed-logout 500 path (r6 endpoints.ts:103)                                                             | packages/plugin/src/endpoints.ts best-effort clears known session cookies before returning 500 on revoke failure or unknown provider, with re-registration documented; proven by a logout test with a failing provider asserting 500 plus Set-Cookie clears                                                                                                                                                                                                                                                                        |
| PAR-3   | Medium   | Parity           | S      | Bounce with explicit 303 on both adapters (r6 middleware.ts:75)                                                                | packages/next/src/middleware.ts and packages/tanstack-start/src/middleware.ts pass explicit 303 so bounces always become GETs to sign-in; proven by status assertions in both middleware suites                                                                                                                                                                                                                                                                                                                                    |
| PAR-4   | Medium   | Parity           | S      | Fix TanStack query-bearing post-login redirects (r6 -sign-in.form.tsx:42)                                                      | examples/tanstack-start/src/app/_frontend/-sign-in.form.tsx splits destinations into navigate to plus search (or href navigation) so redirect=/private?tab=1 lands correctly; proven by a new e2e case for a query-bearing redirect                                                                                                                                                                                                                                                                                                |
| PAR-5   | Medium   | Parity           | S      | Hard-exempt server functions from the Start middleware bounce (r6 middleware.ts:71)                                            | packages/tanstack-start/src/middleware.ts exempts /_serverFn/ by default while staying overridable; proven by a middleware unit test plus docs kept as explanation                                                                                                                                                                                                                                                                                                                                                                 |
| PAR-6   | Medium   | Parity           | S      | Align secure-cookie defaults between providers (r6 cookies.ts:52)                                                              | Better Auth and Auth.js cookie-name derivation share one production-secure rule with a canonical-https baseURL required and documented; proven by cookie unit tests in both providers asserting identical __Secure- behavior under the same env                                                                                                                                                                                                                                                                                    |
| PAR-7   | Medium   | Parity           | M      | Document precedence and revoke every provider on logout (r6 session.ts:45)                                                     | First-registry-match precedence is documented and logout best-effort revokes every provider presenting a session instead of only the verified one; proven by a multi-session logout test asserting all providers revoked                                                                                                                                                                                                                                                                                                           |
| PAR-8   | Low      | Parity           | S      | Reject non-contiguous Auth.js chunk sets (r6 port.ts:58)                                                                       | packages/provider-authjs/src/port.ts treats missing middle chunk slots as malformed with a loud log instead of joining a garbage revoke id; proven by a port unit test with a gapped chunk set                                                                                                                                                                                                                                                                                                                                     |
| PAR-9   | Low      | Parity           | S      | Add verify clock-skew leeway or document the requirement (r6 session.ts:83)                                                    | packages/plugin/src/session.ts expiry check gains a small documented leeway or synchronized clocks become a stated hard requirement; proven by a boundary session test or the documented requirement                                                                                                                                                                                                                                                                                                                               |
| PAR-10  | Low      | Parity           | S      | Sync initialUser prop updates into context (r6 provider.tsx:63)                                                                | packages/react/src/provider.tsx picks up later initialUser values via an effect while keeping refresh explicit; proven by a provider test re-rendering with a new user                                                                                                                                                                                                                                                                                                                                                             |
| PAR-11  | Low      | Parity           | S      | Reject sign-in and API destinations in safeRedirectPath (r6 redirect.ts:16)                                                    | packages/web/src/redirect.ts falls back when the destination equals the sign-in path or targets /api; proven by redirect unit tests for both inputs                                                                                                                                                                                                                                                                                                                                                                                |
| PAR-12  | Low      | Parity           | S      | Scope Auth.js error detection to the error page (r6 form.tsx:81)                                                               | examples/basic/app/(frontend)/sign-in-authjs/form.tsx checks the final URL path instead of a URL substring for error detection; proven by a form test with a destination containing error= that still reports success                                                                                                                                                                                                                                                                                                              |
| DX-1    | High     | Docs and DX      | M      | Fix the getting-started snippet defects (r4 getting-started.md: six findings)                                                  | docs/getting-started.md gains requireEmailVerification:false with the local-only comment, the shared exampleBaseURL module instead of APP_URL, redirect-preserving sign-in with real imports, the ReactNode import, the dual-provider publicPaths and cookie-names delta, and the baseURL-versus-baseUrl casing callout; proven by copy-pasting each snippet into the example shape and by greps for the six tokens                                                                                                                |
| DX-2    | High     | Docs and DX      | S      | Rewrite the UnsupportedStrategy troubleshooting entry (r4 troubleshooting.md:23)                                               | docs/troubleshooting.md states factories are inspected per packages/provider-authjs/src/engine.ts with 500s meaning genuinely missing session.strategy jwt or a throwing factory; proven by the entry matching packages/provider-authjs/src/**tests**/engine.test.ts factory behavior                                                                                                                                                                                                                                              |
| DX-3    | High     | Docs and DX      | S      | Add the Auth.js guide install section (r4 guide-authjs.md:11)                                                                  | docs/guide-authjs.md shows installing the provider package plus a direct @auth/core dependency mirroring getting-started; proven by a fresh-install walkthrough following the guide                                                                                                                                                                                                                                                                                                                                                |
| DX-4    | Medium   | Docs and DX      | S      | Fix TanStack guide imports and install line (r4 guide-tanstack-start.md: two findings)                                         | docs/guide-tanstack-start.md shows both react and tanstack-start import lines in the hydration snippet (AuthLinkProvider comes from react) and drops web from the install command; proven by compiling the snippet imports against the real barrels                                                                                                                                                                                                                                                                                |
| DX-5    | Medium   | Docs and DX      | S      | Add changeset and generated-docs freshness gates to CI (r4 ci.yml:12)                                                          | .github/workflows/ci.yml gains a PR changeset-status job and a docs:llms idempotence check covering llms-full.txt, docs/api, and docs/media; proven by a PR without a changeset failing and a drifted generated artifact failing                                                                                                                                                                                                                                                                                                   |

### Dedup map

Overlapping findings were merged into one item citing every source: SEC-1 (host-header fallback, origin-resolution duplication, baseURL fail-fast), SEC-7 (weak admin seed plus dev-secret fallback), ARCH-6 (register through port plus Result contract), ARCH-11 (dead plugin secret), PAR-1 (v4 definePlugin shape plus v4 peer range), DX-1 (six getting-started snippet defects), DX-4 (two TanStack guide defects), SEC-13 (promoted from a below-cap observation on rate limiting). One finding path was corrected: the lint config lives at root eslint.config.mjs, not packages/eslint.config.mjs (ARCH-2).

## Sprint plan

### Batch 1 (P0: all High severity, must-fix before release)

Order: TYP-1, PAR-1, SEC-1, SEC-2, PAR-2, TST-1, TST-2, TST-3, ARCH-1, ARCH-2, DX-1, DX-2, DX-3.

Rationale: outage and account-takeover defects first (the database-strategy crash and v4 boot failure break entire deployments; the host-header fallback and unverified-JIT flaws bypass authentication), then the logout cookie-survival fix, then the enforcement tests that prove the security and session behavior (failover, race retry, verification), then the structural guards that stop recurrence (framework decoupling, lint blocks), and finally the high-severity docs fixes, which break adopters at copy-paste time but change no runtime behavior.

### Batch 2 (Medium severity, same sprint only while gates stay green)

Order: SEC-3, SEC-4, SEC-8, SEC-5, SEC-7, SEC-6, SEC-13, TYP-2, TYP-3, TYP-4, ARCH-6, ARCH-3, ARCH-7, ARCH-8, ARCH-9, ARCH-4, ARCH-5, PAR-3, PAR-5, PAR-4, PAR-6, PAR-7, TST-4, TST-5, TST-6, TST-7, TST-8, DX-4, DX-5.

Rationale: data-integrity and session-hygiene security fixes before probabilistic hardening; fail-open roles and silent-verify logging before refactors that touch the same files; register-path and session-verify refactors before the wider adapter and cookie cleanups that build on them; parity behavior fixes before the tests that lock them in; docs and CI gates last since they observe rather than change behavior.

### Backlog (Low severity, later)

SEC-9, SEC-10, SEC-11, SEC-12, ARCH-10, ARCH-11, TYP-5, TYP-6, TYP-7, TYP-8, TYP-9, TYP-10, TST-9, TST-10, TST-11, TST-12, PAR-8, PAR-9, PAR-10, PAR-11, PAR-12, in severity-then-effort order. These are real defects with failing-closed behavior or narrow blast radius; they ship after Batch 2 is green.

## Validation gates

Run these exact commands from the repo root; every batch must leave all of them green:

- Full gate: `bun run check` (runs format:check, lint, build, typecheck, coverage, and size)
- Unit tests: `bun run test`, with thresholds via `bun run coverage`
- Release gate: `bun run release:check`
- E2E matrix: `bun run e2e`, `bun run e2e:postgres`, `bun run e2e:mongo`, `bun run e2e:tanstack`, `bun run e2e:tanstack-postgres`, `bun run e2e:tanstack-mongo`
- Docs regen after any user-facing change: `bun run docs:llms`, `bun run docs:api`, `bun run docs:media`

## Accepted risks

- Full migration of the credentials store to Payload-native password auth is deferred (ARCH-5 is actioned as record-the-rationale): the custom scrypt store is contained, timing-safe, and reviewed, while migration is a breaking product decision needing its own design pass. Interim risk is maintaining two credential pipelines.
- Server-side JWT revocation (a denylist) is not built (SEC-6 is phased): stateless JWTs cannot be revoked without new shared infrastructure, so the accepted mitigation is a documented window plus a short default maxAge. Residual risk is a short replay window after logout for JWT deployments.
- Library-level rate limiting stays out of scope (SEC-13 covers examples and docs only): core has no storage primitive for counters, so throttling is builder-owned. Residual risk is brute-force and enumeration pressure on builders that skip the guidance.
- Cross-browser e2e beyond Chromium is conditional on CI budget (TST-8): Chromium remains the release gate and Firefox plus WebKit join the sqlite matrix only. Residual risk is engine-specific cookie or redirect regressions shipping outside Chromium.
- Evidence caveat from prior result 2: per-file coverage percentages came from the checked-in coverage report rather than a fresh run, and the review suite was not executed; TST-5 therefore starts with a fresh `bun run coverage` before any floor is set.

## Sprint notes (deviations with evidence)

- **TST-3 runs with `requireEmailVerification` OFF, not on.** Probed
  2026-10-11: with verification on, Better Auth withholds sessions
  from unverified users entirely (signup returns `token: null`,
  sign-in 403s `EMAIL_NOT_VERIFIED`), so no unverified provider
  session can reach the plugin and an "on" test would prove
  Better Auth's gate instead of ours. The spec
  (`e2e/verification.spec.ts`) signs up through the raw API
  (bypassing the form's dev stamp, modeling unverified OAuth) and
  asserts plugin-session 401 → stamp → 200 on all six suites.
  Counts updated to 17 specs in living docs; phase-evidence lines
  stay historical.
- **ARCH-1 lands as builder-declared plugins, not adapter-supplied
  ones.** The acceptance text has the framework adapters supply the
  cookie plugin; the shipped design instead passes
  `options.plugins` through the engine verbatim and the _builder_
  declares `nextCookies()` / `tanstackStartCookies()` exactly as
  Better Auth documents. Rationale: an adapter-supplied plugin
  would be a second engine-owned cookie API with the same
  misconfiguration surface (and adapters would need to reach into
  engine construction); builder declaration has zero new API.
  Proven by the engine unit tests (verbatim passthrough, no
  framework imports) plus both examples booting with their own
  plugin through the full 17-spec e2e suites — and by the
  integration-test 401s the rebuild exposed, which now pin the
  SEC-2 gate through the real engine (verified stamp helper +
  deliberate refusal test).
- **ARCH-2 also completes the sibling-ban lists the new package
  exposed.** The tanstack-start mirror block is joined by
  `@payload-auth-link/tanstack-start` in the react block
  ("react sits below framework adapters") and the plugin block
  ("plugin sits below UI adapters" — Start ships `client.tsx`),
  whose messages already demanded those bans. The provider block
  additionally bans `better-auth/next-js` and
  `better-auth/tanstack-start`, locking ARCH-1 in at the lint
  layer. Proof beyond the committed web-to-react fixture test:
  injected `react` (provider) and plugin (tanstack-start) imports
  were verified to fail with the new messages, then reverted.
- **SEC-5 lands as origin anchoring, not `trustHost: false`.** The
  acceptance default was attempted first and bricked every Auth.js
  request: raw `@auth/core`'s `assertConfig` returns `UntrustedHost`
  whenever `trustHost` is falsy, unconditionally — `Auth()` never
  runs `setEnvDefaults`, so no `AUTH_URL` rescue exists at this
  layer (verified in `@auth/core@0.41.3` source; all 4 authjs e2e
  specs failed with `UntrustedHost` on direct localhost). The
  reviewer assumed framework-adapter semantics. The shipped fix
  keeps the mandatory `trustHost: true` default and hardens the
  actual host authority instead: `handleRequest` rewrites the
  request origin to the configured `baseURL` (path/query/method/
  headers/body preserved; matching origins pass through untouched),
  so forwarded host headers cannot steer Auth.js redirects or
  callback validation. Proven by anchor unit tests plus the authjs
  e2e specs returning green.
- **SEC-7 covers both examples, not just basic.** The acceptance
  names `examples/basic`; the TanStack example seeded the identical
  known-password admin, so it got the identical gate (plus v4's
  `overrideAccess`). The seed proof is a dedicated
  `e2e:seed-gate` config (fresh DBs, no flag, both frameworks)
  rather than a unit test, since only a real boot exercises
  `onInit`; the six matrix configs set the flag via the shared
  `e2e/dev-admin.ts` module. All `PAYLOAD_SECRET` fallbacks were
  already `local-dev-only`-labeled — verified, no change needed.
- **TYP-2 ships `required: true`, not `minRows: 1`.** Payload's
  `SelectField` type has no `minRows` (it belongs to array/group
  fields — passing it would be a type error); Payload's own select
  validation already rejects `[]` for `required` + `hasMany`
  (`value?.length === 0` → `validation:required`, verified in
  `payload@3.90.2` source). So `required: true` alone is the full
  write-side enforcement the acceptance asks for. Read-side, the
  null-record branch of the "(empty or null-record)" alternative was
  chosen over empty-roles: a session with zero roles would still
  authenticate to non-role-gated paths, while `null` denies the
  session entirely.
- **ARCH-6 routes through `register-user.ts`, not the
  `UserRepository` port.** The title names the port, but the
  Auth.js users store (`auId`, `passwordHash`) is not
  `NewUser`/`UserRecord` and cannot flow through the plugin-users
  repository without corrupting both abstractions (routing it there
  would also provision plugin users at signup, bypassing SEC-2's
  verification gate). The file-level requirement wins: the provider
  implements the new `RegistrationStore` interface — the
  registration-relevant subset of `UserRepository`, which the
  plugin repository satisfies structurally — and `registerWithStore`
  carries the duplicate-check flow with `Result` returns. The
  existing plugin `registerUser` is untouched.
- **SEC-13 follow-up: example `customRules` for sign-up/sign-in.**
  Enabling Better Auth's limiter with a generous global `max` broke
  full parallel e2e runs (2 specs timing out on both frameworks):
  Better Auth ships default special rules (3 sign-ups/sign-ins per
  10s per IP) that override the global ceiling, and shared-IP dev
  traffic (no trusted client IP) trips them immediately. Both
  examples now raise those two paths to 100/min via `customRules`
  with a comment; the guides document the special rules. Suites
  back to 18/18.

- **ARCH-4 lands as mirror-plus-drift-test, not runtime
  derivation.** Both providers now import the one `secureCookiePrefix`
  from core (local copies deleted). Names stay a pure mirror rather
  than calling the SDK getters at runtime: `better-auth/cookies`
  drags a heavy graph (crypto, db schema, jose) into the Edge-safe
  `cookies` subpath, and `@auth/core` exposes no public cookie
  getter at all (`defaultCookies` is internal; the exports map has
  no cookies entry — verified in `@auth/core@0.41.3`). Proof is the
  BA drift test (7 option-matrix cases plus an ambient-fallback
  tripwire against the real `getCookies`) and the Auth.js e2e specs
  running real Auth.js cookies through the mirror. The drift test
  cannot re-freeze BA's load-time `isProduction` in-process
  (`vi.resetModules` reuses the externalized module — probed), so
  the production branch is pinned by shared-rule unit tests plus
  source-verified parity instead.
- **PAR-6 lands as one shared core rule plus documented
  requirement, with no wiring throw.** `resolveSecureCookies` in
  core is the single implementation both providers call (explicit
  flag → dynamic protocol → https origin → `NODE_ENV`), and the
  only divergent cell (production without an origin) now agrees —
  which also improves Auth.js fidelity on real https deployments.
  The canonical-https-baseURL production requirement is documented
  in both provider guides and the engine/cookie TSDoc rather than
  enforced by a throw: both SDKs permit http, and a throw would
  brick local prod-mode testing. Violation fails closed (Auth.js
  session detection misses on http production). Core stays
  global-free: it takes the environment by injection while the
  adapters read the live `NODE_ENV` (core has no Node types by
  design — `process` there is a compile error, not a fallback).

- **PAR-4 finishes on the Better Auth form too.** The Auth.js form
  already pushed the raw href; the Better Auth form still called
  `navigate({ to })`, where `to` is path-only. Both TanStack forms now
  `router.history.push(safeRedirectPath(redirect))`, so the
  intercepted destination survives byte for byte. Proven by the
  query-bearing e2e case on both frameworks.
- **PAR-7 sweeps on every logout path.** After the verified
  provider's revoke, `revokePresentedSessions` (in `endpoints.ts`)
  asks every other registered provider for a live session and revokes
  it best-effort (logged, never fatal). It runs on the idempotent 401
  path too, because a provider session can be live behind a failed
  verify. Registry-order precedence is documented in `session.ts` and
  `docs/concepts.md`. Proven by the multi-provider logout unit tests.
- **TST-5 also floors `endpoints.ts`, and lifts `repository.ts`
  first.** A fresh run measured `repository.ts` at 69% lines and 46%
  branches, which is too low to floor usefully. The new
  `repository.test.ts` takes it to 100%, then floors were set just
  under the measured values for `session.ts`, `strategy.ts`,
  `repository.ts` and `endpoints.ts`. Proof: raising the
  `session.ts` lines floor to 99 failed the gate (`Coverage for lines
(92.1%) does not meet … threshold (99%)`), and it was then reverted.
- **TST-7's OAuth smoke drives the link path, not a live IdP.** The
  examples configure no external OAuth provider, so the suites stay
  offline. `e2e/session-lifecycle.spec.ts` covers four cases:
  - a corrupted cookie and a revoked cookie replayed after logout
    are both rejected by Node validation (`/admin-only` bounces,
    `/account` renders signed out, the session endpoint 401s);
  - a second provider identity for the same verified email links
    onto the same Payload user (the same `ensureLinkedUser` path an
    OAuth sign-in takes);
  - unconfigured social entry points of both SDKs fail closed.

  Rate limiting was already covered by `e2e/rate-limit.spec.ts`. The
  suite is now 23 specs, and the living docs are updated.

- **TST-8 runs the engines in sequence; Firefox runs in Linux.**
  Running the engines concurrently against one server raced two admin
  logins on Payload's per-user sessions array: one write dropped the
  other's session, giving a spurious 403. That reproduced twice, and
  Chromium alone was green. So `firefox` depends on `chromium` and
  `webkit` depends on `firefox`. Chaining the engines on one database
  also exposed two admin-list locator bugs:
  - a bare `admin` cell matched users promoted by earlier engines.
    `seededAdminCell` now targets the only admin row with
    `0 Identities`.
  - the seeded admin fell off page one. The list is now sorted or
    sized (`?sort=createdAt`, `?limit=500`).

  WebKit-only navigation races are handled by `gotoSettled`, which
  `gotoOwn` and the raw Payload-admin navigations now use. It
  retries a `goto` that collides with the app's own navigation
  (`Frame load interrupted` after the sign-out redirect, or `is
interrupted by another navigation` when a page bounces to sign-in
  after `clearCookies()`), up to twice, and never other failures.
  Playwright's macOS Firefox build cannot launch on the dev host
  ("Could not find profile folder"). So the acceptance command was
  proven against CI's Linux browsers instead, through a
  `mcr.microsoft.com/playwright:v1.64.0-noble` `run-server`
  container (`PW_TEST_CONNECT_WS_ENDPOINT`, loopback exposed to the
  host dev servers). Both `bun run e2e` and `bun run e2e:tanstack`
  passed 69/69: 23 specs each in Chromium, Firefox and WebKit. CI's
  `e2e` and `e2e-tanstack` jobs now install all three engines.

- **`docs:media` was stale since SEC-7; fixed and rerun.**
  `scripts/capture-media.mjs` never set the dev-only seed flag and
  logged in with an old hardcoded password, so the admin screenshot
  could not be captured. It now takes `DEV_ADMIN_SEED_ENV` and the
  credentials from `e2e/dev-admin.ts`, the same module the e2e
  harness uses. `bun run docs:media` was regenerated and the
  screenshots were reviewed.
- **DX-5 gates `docs/api` with a strict build, not a diff.**
  `docs/api/` is gitignored, so there is nothing to diff. Its
  freshness gate is `typedoc --treatWarningsAsErrors`. The new
  `bun run docs:check` (`scripts/check-docs.mjs`) proves two things:
  that `llms.txt` and `llms-full.txt` regenerate as a no-op, and that
  every `docs/media` file is referenced and every reference
  resolves. CI gains a `docs-fresh` job and a PR-only `changeset` job
  (`changeset status --since=origin/<base>`). Proofs:
  - the check failed on the real `llms-full.txt` drift from this
    sprint's doc edits;
  - it failed on an injected orphan screenshot;
  - in a scratch copy of the repo, a feature branch with no
    changeset exited 1 ("Some packages have been changed but no
    changesets were found").
- **DX-4's proof is a guard test inside the adopter app.**
  `examples/tanstack-start/src/lib/guide.test.ts` extracts every
  `@payload-auth-link/*` import from the guide's snippets and asserts
  each name is a real export of that barrel, resolved the way the
  example resolves it. It also checks that `AuthLinkProvider` comes
  from `react` and that `web` is absent from the install line.
- **Audit follow-ups.** The ARCH-5 rationale is now recorded in
  `docs/guide-authjs.md` as well as under Accepted risks. A
  session-service test pins the unknown-provider revoke error behind
  the PAR-2 500 path.

- **The first real CI run surfaced three issues that only a clean
  checkout or CI concurrency could show.** All three are fixed.
  - `importMap.js` (Payload) and `routeTree.gen.ts` (TanStack
    Router) were gitignored, so example pages and type-aware lint
    broke on a fresh clone. Both files are now tracked.
  - `check` linted before `build`, and `docs:check` ran typedoc
    without one. Type-aware tools resolve sibling packages through
    `dist`, so both scripts now build first. This was proven in a
    fresh `git clone` with `bun install --frozen-lockfile`: `check`
    passed with 457 tests, and both frameworks' e2e passed 23/23.
  - In CI, two retried flakes (an admin escalation 403 and an empty
    admin list) traced to concurrent seeded-admin logins inside one
    project. Payload's login read-modify-writes the user's `sessions`
    array. `e2e/admin-session.ts` is now `globalSetup` for the six
    matrix configs: it logs the admin in once per run and hands specs
    pre-authenticated contexts. Only `users-admin.spec.ts` keeps the
    real UI login, which is safe because nothing else logs in
    concurrently. This closes TST-6's "no reliance on retries" for
    real.

  With `--retries=0`, both three-engine suites passed 69/69 twice
  each in CI's Linux browsers, and all four Postgres and Mongo
  suites passed 23/23.

## Status

Batch 1 (13 items), Batch 2 (29 items) and the Low backlog (21
items) are complete: **0 items remain**. Each has its implementation
plus the proving test or the recorded evidence above. CI is green on
PR #1 for every job, including `e2e` and `e2e-tanstack`, which run
all three engines.

### Backlog close-out notes (deviations with evidence)

- **TYP-7 was already satisfied by ARCH-9.** The shared
  `parseSessionResponse` narrows with `isRecord`, and the web
  verifier suite already feeds an array body (`jsonResponse([user])`)
  and asserts it fails closed. No code change was needed.
- **PAR-9 takes the "stated hard requirement" branch, not a
  leeway.** A leeway would accept sessions the provider already
  considers expired. Synchronized clocks are documented in
  `docs/concepts.md` and `session.ts`, and a boundary test pins
  `expiresAt == now` as expired.
- **PAR-10 syncs during render, not in an effect.** It uses React's
  "adjust state when a prop changes" pattern: no stale frame, and it
  satisfies `react-hooks/set-state-in-effect`. Snapshots are compared
  by value, so a parent re-rendering with an equal fresh object never
  undoes a client sign-out (tested).
- **PAR-11 adds `{ signInPath: null }`.** Landing on sign-in after
  sign-out is legitimate, so `SignOutButton` (SEC-12) disables that
  one rule. `safeRedirectPath` moved to core so `react` can use it
  without a `web` dependency; `web` re-exports it unchanged.
- **PAR-12's proof is a decision-helper test.** The fix is
  `isAuthJsFailureLanding` (path-based), wired into both example
  forms. Its unit tests include a destination carrying `error=` that
  reports success. A full form render would need a live Auth.js
  round-trip, which the e2e suites cover.
- **SEC-9 returns a uniform `{ ok: true }` 200** for new and existing
  emails through `lib/signup-response.ts` in both examples, unit
  tested for identical status and body, with a `notifyExisting`
  out-of-band hook. A duplicate signup with another password now fails
  generically at sign-in and changes nothing; the e2e spec asserts
  both. The rate-limit spec now expects ten uniform 200s → 429.
- **ARCH-10 uses `export * from '@payload-auth-link/web'`** in both
  adapters. The adapter's local `packageName` takes precedence. The
  barrel tests assert every web runtime export is the identical
  binding. This already fixed a real drift: `SafeRedirectOptions` was
  missing from both adapters.
- **ARCH-11 drops the requirement.** `secret` is optional,
  `@deprecated` and ignored; core's strict schema rejects it. The
  examples, getting-started and tests no longer pass it. Migration
  note: `docs/upgrading.md`.
- **TYP-8 throws at registration.** Illegal names throw
  `InvalidConfigError` from `registry.register` (config errors throw
  by convention), checked with the same RFC 6265 token rule as
  serialization (`isCookieName`).
- **TYP-9's date drift is proven with a one-call `find` stub.**
  Drizzle cannot even hold an unparseable date, but document stores
  can. The `baId` drift is proven with a raw `payload.db.updateOne`
  on real SQLite.
- **TYP-10 also rejects an empty role list** (`InvalidConfigError`):
  `requireRoles({ roles: [] })` would otherwise grant every signed-in
  user.
- **TST-9 snapshots the full admin page per Payload major.** The
  snapshot pins axe rule id → maximum node count across engines.
  Per-row upstream chrome (row checkboxes, the v4 `.id-label`) is
  excluded so counts don't scale with rows. Gecko flags 8 v4
  contrast nodes that Chromium and WebKit don't, so the snapshot
  keeps the max. An injected `<img>` without `alt` failed the gate
  on both frameworks; the injection was then reverted. Configs
  declare `metadata.payloadMajor`.
- **TST-10 waits for the work, not the clock.** `settle()` awaits
  every stubbed response, then drains microtasks inside `act`. No
  wall-clock sleep remains.
- **TST-11's proof:** with the new `beforeEach` removed, the added
  second test failed ("starts from clean mocks"); restored, both
  pass.
- **TST-12:** each package keeps at most one entrypoint smoke, and
  it calls a real contract through the barrel. No `typeof`
  assertions remain.

## Verified strengths

- Unverified-email link refusal blocks direct unverified account takeover on the link path, and state-changing endpoints fail closed on CSRF with idempotent logout that always expires provider cookies.
- Credentials crypto uses salted scrypt with timing-safe comparison plus dummy-hash verification for unknown users, so no timing oracle leaks account existence.
- Core is genuinely framework-free behind injected ports with strict zod startup validation and single error-mapping choke points; web, Next, and TanStack share one real parity core instead of forks.
- Verify-time fault isolation is sound (one provider down never breaks the others), cookie clearing mirrors live attributes with prefix fallbacks, and JSON edges fail closed with no unchecked casts in src.
- Documentation is substantially accurate: the 385-unit-test and 18-spec counts match the suites, the Auth.js credentials-callback protocol matches the example form line for line, and compatibility pins match bun.lock and CI.
