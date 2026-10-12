# Contributing

## Setup

```bash
bun install
bun run check   # format, lint, typecheck, coverage, build, size
bun run dev:example  # example site on :3100
```

Read [docs/MISSION.md](docs/MISSION.md), [docs/DNA.md](docs/DNA.md),
[docs/PLAN.md](docs/PLAN.md), and [AGENTS.md](AGENTS.md) before changing
anything — DNA invariants are binding.

## Pull Requests

- `bun run check` must be green; `bun run e2e` for auth-flow changes.
- Behavior change → test. Security change → an integration test that
  fails without the fix.
- User-facing changes need a changeset (`bunx changeset`).
- Public API needs TSDoc plus a `docs/` guide update.
- Never commit secrets, never log credentials, never ship debug output.

## Release

Releases ride changesets on `main` (`.github/workflows/release.yml`):

1. Land PRs with changesets; the release workflow opens a
   "Version Packages" PR.
2. Merging it publishes to npm with provenance attestations via
   trusted publishing — configure the npm org as a trusted
   publisher before the first release; no long-lived token.
3. Before approving a Version Packages PR, run the packaging gate
   locally: `bun run release:check` (`publint` + `attw` over every
   package; all packages are ESM-only by decision).

First-publish checklist: npm trusted publisher for the
`@payload-auth-link` org, `NPM_CONFIG_PROVENANCE` unset (per-package
`provenance: true` already set).
