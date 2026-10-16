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

Releases ride changesets on `main` (`.github/workflows/release.yml`).
The release workflow is gated on CI: it runs only when the `ci`
workflow completes **successfully** for a push to `main`, and only
while that tested commit is still `main`'s head (if `main` moved, the
newer commit's CI run releases instead). Publishing runs in the
`npm-publish` GitHub environment.

1. Land PRs with changesets. Once CI is green on `main`, the release
   workflow opens (or updates) a "Version Packages" PR.
2. **Run CI on the Version Packages PR before merging.** GitHub does
   not trigger workflows for PRs opened by the workflow's own
   `GITHUB_TOKEN`, so the PR arrives with no checks. Close and
   reopen it (`gh pr close <n> && gh pr reopen <n>`) to start CI, and
   merge only when every check is green.
3. Merging it (once CI passes on `main`) publishes every unpublished
   version through `scripts/publish.mjs`. Tarballs are packed by Bun (real dependency
   versions, never `workspace:`) and published by npm through trusted
   publishing with provenance, so no npm token exists anywhere. All 8
   packages trust `jellologic/payload-auth-link` → `release.yml`.
4. Prove the release from the outside:
   `bun run verify:published <version> --expect-provenance`. It checks
   the registry manifests, provenance, `npm audit signatures`, every
   entry point importing in a clean consumer, and a consumer
   type-check.

Empty changesets (`bunx changeset --empty`) are for internal-only PRs.
If **only** empty changesets are pending, `changesets/action` neither
opens a Version PR nor publishes ("All changesets are empty; not
creating PR"), and the release stalls until they're deleted. Don't
use an empty changeset to ride metadata into an unpublished version:
delete it once nothing else is pending.

`bun run release:check` gates every PR on the packed tarballs: `publint`
and `attw`, no undeclared imports, no `.d.ts` imports of untyped
dependencies, no shipped test files, no `workspace:` ranges, a README
per package, and a `LICENSE` in every tarball (each package commits a
copy of the root `LICENSE`; update all of them together).

### Publishing never happens locally

`scripts/publish.mjs` refuses a real publish outside GitHub Actions
(`GITHUB_ACTIONS=true`); locally only `bun run release -- --dry-run`
works. A local publish ships **without provenance**, so it is an
emergency-only path (e.g. GitHub Actions is down and a security fix
must ship):

```sh
PAL_ALLOW_LOCAL_PUBLISH=i-understand-no-provenance bun run release
```

Record why in the release notes, and publish the next version from CI
so the line regains provenance. Never set that variable in CI or a
shell profile.

### Workflow hygiene

`bun run ci:lint` (part of `bun run check`) parses every workflow and
`.github/dependabot.yml` strictly, requires top-level `permissions`,
and requires every action pinned by full commit SHA with a version
comment (`uses: actions/checkout@<sha> # v4.4.0`). Dependabot's
`github-actions` updates keep the pins current.
