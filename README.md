# payload-auth-link

Enterprise-grade auth plugin for Payload CMS 3: hexagonal
ports/adapters, strict typesafe, with identity providers
(Better Auth, Auth.js/NextAuth) as swappable adapters and users as
first-class Payload documents.

Status: both providers shippable (Better Auth + Auth.js), 268 unit
tests and 13 Playwright specs green on SQLite, Postgres, and Mongo —
see [docs/PLAN.md](docs/PLAN.md) for phase evidence.

## Docs

Start with [Getting started](docs/getting-started.md) (four edits to
signed-in users), then the [Tour](docs/tour.md) and
[Concepts](docs/concepts.md). Provider specifics live in the
[Better Auth guide](docs/guide-better-auth.md) and
[Auth.js guide](docs/guide-authjs.md); also
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
