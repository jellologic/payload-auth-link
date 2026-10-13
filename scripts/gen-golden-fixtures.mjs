/**
 * Regenerate the golden 0.1.1 collection fixtures used by the
 * upgrade tests (PLAN-UPGRADE-RESILIENCE Phase 2). The fixtures are
 * the tagged 0.1.1 collection definitions verbatim, so the upgrade
 * tests seed a database with the exact physical schema a real
 * 0.1.1 deployment has — never a hand-copied approximation.
 *
 * Run: bun scripts/gen-golden-fixtures.mjs
 */
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const fixtures = [
  {
    tag: '@payload-auth-link/provider-better-auth@0.1.1',
    source: 'packages/provider-better-auth/src/collections.ts',
    target: 'packages/provider-better-auth/src/__tests__/golden-0.1.1-collections.ts',
  },
  {
    tag: '@payload-auth-link/provider-authjs@0.1.1',
    source: 'packages/provider-authjs/src/collections.ts',
    target: 'packages/provider-authjs/src/__tests__/golden-0.1.1-collections.ts',
  },
]

for (const fixture of fixtures) {
  const body = execFileSync('git', ['show', `${fixture.tag}:${fixture.source}`], {
    cwd: root,
    encoding: 'utf8',
  })
  const header =
    '/**\n' +
    ` * GOLDEN FIXTURE — generated from git tag ${fixture.tag}\n` +
    ` * (${fixture.source} at that tag).\n` +
    ' * Do not edit by hand: regenerate with scripts/gen-golden-fixtures.mjs.\n' +
    ' * Used only by upgrade-golden.test.ts to create a real 0.1.1-shaped database.\n' +
    ' */\n'
  writeFileSync(join(root, fixture.target), header + body)
  console.log(`wrote ${fixture.target} from ${fixture.tag}`)
}
