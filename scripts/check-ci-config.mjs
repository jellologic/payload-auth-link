/**
 * CI-config gate (issue #85). GitHub silently tolerates — or silently
 * ignores — malformed config: a duplicate `ignore:` key in
 * dependabot.yml dropped half the ignore rules without any error.
 * This parses every workflow and `.github/dependabot.yml` strictly
 * (duplicate keys are errors) and enforces the supply-chain rules:
 *
 *  - every workflow declares top-level `permissions` (least privilege;
 *    jobs widen it explicitly);
 *  - every third-party action is pinned by full commit SHA with a
 *    version comment (`uses: owner/repo@<40-hex> # vX.Y.Z`), so a moved
 *    or compromised tag cannot change what runs.
 *
 * Run: `bun run ci:lint` (part of `bun run check`).
 */
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseDocument } from 'yaml'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const workflowsDir = join(root, '.github', 'workflows')
const workflows = readdirSync(workflowsDir)
  .filter((file) => file.endsWith('.yml') || file.endsWith('.yaml'))
  .map((file) => join('.github', 'workflows', file))
const files = [...workflows, join('.github', 'dependabot.yml')]

const problems = []

function parseStrict(file) {
  const text = readFileSync(join(root, file), 'utf8')
  const doc = parseDocument(text, { uniqueKeys: true, prettyErrors: true })
  for (const error of [...doc.errors, ...doc.warnings]) {
    problems.push(`${file}: ${error.message}`)
  }
  return { text, value: doc.errors.length === 0 ? doc.toJS() : null }
}

for (const file of files) {
  const { text, value } = parseStrict(file)
  if (value === null || typeof value !== 'object') {
    if (value !== null) {
      problems.push(`${file}: expected a mapping at the top level`)
    }
    continue
  }
  if (file.endsWith('dependabot.yml')) {
    if (value.version !== 2 || !Array.isArray(value.updates)) {
      problems.push(`${file}: expected version: 2 and an updates list`)
    }
    continue
  }
  if (!('permissions' in value)) {
    problems.push(`${file}: missing top-level permissions (use {} or contents: read)`)
  }
  if (typeof value.jobs !== 'object' || value.jobs === null) {
    problems.push(`${file}: no jobs`)
  }
  // Check the raw lines so the version comment is enforced too.
  text.split('\n').forEach((line, index) => {
    const match = /^\s*(?:-\s+)?uses:\s*(\S+)(.*)$/.exec(line)
    if (match === null) {
      return
    }
    const ref = match[1] ?? ''
    const rest = match[2] ?? ''
    if (ref.startsWith('./') || ref.startsWith('docker://')) {
      return
    }
    if (!/^[^@\s]+@[0-9a-f]{40}$/.test(ref) || !/^\s+#\s*v\d/.test(rest)) {
      problems.push(
        `${file}:${index + 1}: pin '${ref}' by full commit SHA with a version comment (owner/repo@<sha> # vX.Y.Z)`
      )
    }
  })
}

if (problems.length > 0) {
  for (const problem of problems) {
    process.stderr.write(`ci:lint: ${problem}\n`)
  }
  process.exit(1)
}
process.stdout.write(`ci:lint passed (${files.length} files)\n`)
