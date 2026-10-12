# payload-auth-link

Enterprise-grade auth plugin for Payload CMS (v3 and v4): hexagonal
ports/adapters, strict and typesafe. Identity providers (Better Auth,
Auth.js/NextAuth) are swappable adapters, users stay first-class
Payload documents, and Next.js and TanStack Start are both first-class
framework adapters over one framework-free web core.

Status: published on npm as `@payload-auth-link/*`. 498 unit and
integration tests and 24 Playwright specs pass on SQLite, Postgres,
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

## Docs

Start with [Getting started](docs/getting-started.md) (four edits to
signed-in users), then the [Tour](docs/tour.md) and
[Concepts](docs/concepts.md). Provider specifics live in the
[Better Auth guide](docs/guide-better-auth.md),
[Auth.js guide](docs/guide-authjs.md), and
[TanStack Start guide](docs/guide-tanstack-start.md); also
[Compatibility](docs/compatibility.md),
[Troubleshooting](docs/troubleshooting.md), and
[Upgrading](docs/upgrading.md).

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
bun run docs:api     # typedoc HTML to docs/api/
bun run docs:llms    # regenerate llms.txt + llms-full.txt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).
