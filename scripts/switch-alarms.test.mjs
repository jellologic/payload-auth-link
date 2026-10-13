/**
 * Switch-exhaustiveness alarm (PLAN-UPGRADE-RESILIENCE Phase 3b,
 * B17): every shipped source file that switches must also call
 * `assertNever`, so a newly added union variant (ours or an
 * upstream's) fails typecheck in CI instead of falling through at
 * runtime. The typechecker proves each individual switch; this
 * structural test proves no new switch skips the guard.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function shippedSources(dir) {
  const files = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === '__fixtures__' || entry.name === 'dist') {
        continue
      }
      files.push(...shippedSources(path))
    } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
      files.push(path)
    }
  }
  return files
}

describe('switch exhaustiveness alarm', () => {
  it('every shipped file with a switch calls assertNever', () => {
    const offenders = []
    for (const file of shippedSources(join(root, 'packages'))) {
      const text = readFileSync(file, 'utf8')
      if (/\bswitch\s*\(/.test(text) && !/assertNever\s*\(/.test(text)) {
        offenders.push(file.slice(root.length + 1))
      }
    }
    expect(offenders).toEqual([])
  })
})
