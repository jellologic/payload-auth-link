/**
 * changesets/action's publish contract: the action sets
 * `$CHANGESETS_OUTPUT` to a file, reads it back as JSON lines, and for
 * every `{ type: 'git-tag', tag, packageName }` event pushes the (local)
 * tag and creates the GitHub release. See `readChangesetsOutput` in
 * changesets/action `src/run.ts`.
 */

/** One output line announcing a release tag for a published package. */
export function gitTagEvent(packageName, version) {
  return `${JSON.stringify({ type: 'git-tag', tag: `${packageName}@${version}`, packageName })}\n`
}
