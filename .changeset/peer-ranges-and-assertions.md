---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
'@payload-auth-link/next': minor
'@payload-auth-link/tanstack-start': minor
---

Version-range honesty (upgrade-resilience Phase 1): declared ranges
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
