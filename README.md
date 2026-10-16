# payload-auth-link

Enterprise-grade auth plugin for Payload CMS (v3 and v4): hexagonal
ports/adapters, strict and typesafe. Identity providers (Better Auth,
Auth.js/NextAuth) are swappable adapters, users stay first-class
Payload documents, and Next.js and TanStack Start are both first-class
framework adapters over one framework-free web core.

Status: published on npm as `@payload-auth-link/*`. 751 unit and
integration tests and 33 Playwright specs pass on SQLite, Postgres,
and Mongo for both frameworks; the SQLite suites run in Chromium,
Firefox, and WebKit.

## Packages

| Package                                                                              | Purpose                                                           |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| [`@payload-auth-link/plugin`](packages/plugin/README.md)                             | The Payload plugin: users, roles, identities, strategy, endpoints |
| [`@payload-auth-link/provider-better-auth`](packages/provider-better-auth/README.md) | Better Auth provider adapter                                      |
| [`@payload-auth-link/provider-authjs`](packages/provider-authjs/README.md)           | Auth.js provider adapter                                          |
| [`@payload-auth-link/next`](packages/next/README.md)                                 | Next.js adapter (re-exports `web`)                                |
| [`@payload-auth-link/tanstack-start`](packages/tanstack-start/README.md)             | TanStack Start adapter (re-exports `web`)                         |
| [`@payload-auth-link/react`](packages/react/README.md)                               | Provider-agnostic React UI                                        |
| [`@payload-auth-link/web`](packages/web/README.md)                                   | Framework-free web layer                                          |
| [`@payload-auth-link/core`](packages/core/README.md)                                 | Framework-free domain and ports                                   |

## Compatibility

Validated set (see [Compatibility](docs/compatibility.md) for the
full matrix — databases, browsers, capability-by-provider):

|                          | Validated                                     |
| ------------------------ | --------------------------------------------- |
| Payload                  | 3.91.0 (Next) · 4.0.0-beta.0 (TanStack Start) |
| Next.js / TanStack Start | 16.4.0 / 1.168.61                             |
| Better Auth / Auth.js    | 1.7.7 / `@auth/core` 0.41.3                   |
| Databases                | SQLite · Postgres · MongoDB                   |
| Browsers (e2e)           | Chromium · Firefox · WebKit                   |

Sign-in capabilities are declared per provider and fail fast at
wiring when unsupported — highlights (full matrix in the
[capabilities guide](docs/guide-capabilities.md)):

| Capability              | Better Auth                      | Auth.js            |
| ----------------------- | -------------------------------- | ------------------ |
| Magic link / email OTP  | ✅                               | ✅ (OTP recipe)    |
| OAuth / OIDC            | ✅                               | ✅ (D6 allow-list) |
| Passkeys                | ✅                               | — experimental     |
| Two-factor / MFA policy | ✅                               | —                  |
| Impersonation           | ✅ (audit log + `onAudit`)       | —                  |
| Phone · anonymous guest | ✅                               | —                  |
| Organizations · SSO     | ✅ Payload-owned, both providers |

## Docs

Start with [Getting started](docs/getting-started.md) (four edits to
signed-in users), then the [Tour](docs/tour.md) and
[Concepts](docs/concepts.md). Provider specifics live in the
[Better Auth guide](docs/guide-better-auth.md),
[Auth.js guide](docs/guide-authjs.md), and
[TanStack Start guide](docs/guide-tanstack-start.md); sign-in
methods beyond passwords in the
[Capabilities guide](docs/guide-capabilities.md); also
[Migrating from payload-auth](docs/migrating-from-payload-auth.md); also
[Compatibility](docs/compatibility.md),
[Troubleshooting](docs/troubleshooting.md), and
[Upgrading](docs/upgrading.md).

Operations: [Audit trail for production](docs/audit.md),
[Rate limiting](docs/rate-limiting.md), and the
[Stability and upgrade policy](docs/stability.md) (takes effect at 1.0).

Project docs: [Mission](docs/MISSION.md),
[DNA](docs/DNA.md) (binding), [Plan](docs/PLAN.md). Agent
consumers: [llms.txt](llms.txt), [llms-full.txt](llms-full.txt),
[AGENTS.md](AGENTS.md).

## Develop

```bash
bun install
bun run check        # full quality gate
bun run dev:example  # example site on :3100
bun run e2e          # Playwright: SQLite on :3101
bun run e2e:postgres # Playwright: Postgres on :3102
bun run e2e:mongo    # Playwright: mongo memory replset on :3103
bun run e2e:mfa      # Playwright: MFA-policy variant (SQLite) on :3104
bun run e2e:idp      # Playwright: external-IdP variant (mock OIDC) on :3105
bun run docs:api     # typedoc HTML to docs/api/
bun run docs:llms    # regenerate llms.txt + llms-full.txt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## License

[MIT](LICENSE) © jellologic
