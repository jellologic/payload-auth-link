import { describe, expect, it } from 'vitest'
import { gitTagEvent } from './changesets-output.mjs'

/**
 * Verbatim from changesets/action `src/run.ts` (isChangesetsOutputEvent):
 * an event the action skips silently means no tag and no GitHub release,
 * which is exactly how 0.1.1 shipped without either.
 */
function isObject(value) {
  return typeof value === 'object' && value !== null
}
function isChangesetsOutputEvent(value) {
  return (
    isObject(value) &&
    'type' in value &&
    value.type === 'git-tag' &&
    'tag' in value &&
    typeof value.tag === 'string' &&
    'packageName' in value &&
    typeof value.packageName === 'string'
  )
}

describe('changesets/action output contract', () => {
  it('emits one JSON line the action accepts as a git-tag event', () => {
    const line = gitTagEvent('@payload-auth-link/core', '0.1.1')
    expect(line.endsWith('\n')).toBe(true)
    expect(line.trimEnd().includes('\n')).toBe(false)
    const event = JSON.parse(line)
    expect(isChangesetsOutputEvent(event)).toBe(true)
    expect(event).toEqual({
      type: 'git-tag',
      tag: '@payload-auth-link/core@0.1.1',
      packageName: '@payload-auth-link/core',
    })
  })
})
