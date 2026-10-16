# Releasing

The release checklist. Everything here is gated by CI except the
judgment calls; when a step feels optional, re-read
[PLAN-UPGRADE-RESILIENCE](PLAN-UPGRADE-RESILIENCE.md)'s success
criteria — releases must never break a user's database or install.

## Before cutting a version PR

1. **`bun run check` green.** This runs format, lint, typecheck,
   the full unit/integration/component suite (including the
   golden-DB SQLite upgrade tests), size budgets, the API-type
   snapshot gate, the **schema-snapshot gate** (`schema:check`),
   and the consumer fixture.
2. **Golden-DB suites on all adapters.** SQLite runs in step 1;
   Postgres and Mongo are env-gated locally and always run in the
   `compat` workflow's `golden` job — confirm it is green on the
   release commit (run it with `workflow_dispatch` if the last run
   predates your change).
3. **Schema snapshot reviewed.** If `snapshots/schema/` changed in
   this release, the diff is intentional, the PR carries the
   `Upgrade impact:` changeset section (per-adapter push and
   migrations behavior), and `docs/upgrading.md` has the version
   heading with operator steps. The schema gate enforces the pair;
   the review is yours.
4. **`docs/upgrading.md` current.** Every user-facing change with a
   migration or install consequence has an entry under the upcoming
   version heading. Peer-range moves, new version assertions, and
   anything touching stored data always do.
5. **Compat matrix matches the manifests.** If this release widens
   or narrows a band (`supported*Band` constants + manifest peer
   ranges + the `compat` workflow matrix cell), all three moved
   together, and [compatibility.md](compatibility.md) states the new
   band with its bisect evidence. Regenerate the matrix claim from
   the workflow's latest run, never from memory.
6. **Changesets complete.** Every user-facing change has one;
   internal-only PRs an empty one. Upgrade notes live in the
   changeset text so they surface verbatim in the CHANGELOGs.
   Never leave ONLY empty changesets pending — the release action
   then neither versions nor publishes.

## Cutting the release

7. Merge the Version Packages PR. Note: **GITHUB_TOKEN-opened PRs
   trigger no CI** — close and reopen the Version PR once so the
   full gates run on its head before merging.
8. The release workflow publishes with OIDC trusted publishing +
   provenance, then tags. It is gated on CI: it starts only when the
   `ci` workflow succeeds for the merge commit on `main` (and that
   commit is still `main`'s head), and the publish job runs in the
   `npm-publish` environment — approve it there if the environment
   requires reviewers. Staged publishing makes new versions 404 for a
   few minutes after upload.

   **Never publish locally.** `scripts/publish.mjs` refuses outside
   GitHub Actions. The emergency-only override (Actions down, a
   security fix must ship) publishes WITHOUT provenance:
   `PAL_ALLOW_LOCAL_PUBLISH=i-understand-no-provenance bun run release`.
   Record why in the release notes and ship the next version from CI.

9. **Verify the release:**

   ```sh
   bun run verify:published <version> --expect-provenance
   ```

10. **Consumer-install smoke** when the release touches packaging
    (exports, peer ranges, new entries): pack tarballs and install
    into throwaway npm and pnpm consumers
    (`scripts/consumer-fixture/` typechecks the built types; the
    `release:check` job covers packing + attw + publint). pnpm's
    strict linker requires consumers that import
    `@payload-auth-link/core` directly to install it explicitly —
    documented in the READMEs; keep it that way.

## After the release

11. Confirm the band claims still hold: the weekly `compat` run on
    the release tag is the compatibility.md source of truth.
12. If any upstream shipped a minor during the window: the compat
    patch widening the band is the next release (commitment window
    in [compatibility.md](compatibility.md)).
