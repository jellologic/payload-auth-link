import { describe, expect, it } from 'vitest'
import { assertUniqueSlugs, denyAllAccess, resolveSlugs } from '../collections.js'

describe('resolveSlugs', () => {
  const defaults = { user: 'app-users', session: 'app-sessions' }

  it('merges overrides over defaults', () => {
    expect(resolveSlugs(defaults, { user: 'custom' })).toEqual({
      user: 'custom',
      session: 'app-sessions',
    })
    expect(resolveSlugs(defaults)).toEqual(defaults)
  })

  it('rejects empty and non-string slugs at wiring time', () => {
    expect(() => resolveSlugs(defaults, { user: '' })).toThrow(
      'slug for model "user" must be a non-empty string'
    )
    expect(() => resolveSlugs(defaults, { user: undefined as unknown as string })).toThrow(
      'slug for model "user" must be a non-empty string'
    )
  })

  it("rejects unknown model keys (typo'd overrides)", () => {
    expect(() =>
      resolveSlugs(defaults, { usr: 'x' } as unknown as Partial<typeof defaults>)
    ).toThrow('unknown model "usr" in slug overrides')
  })
})

describe('assertUniqueSlugs', () => {
  it('passes unique slugs and names collisions', () => {
    expect(() => assertUniqueSlugs({ a: 'x', b: 'y' }, 'owner')).not.toThrow()
    expect(() => assertUniqueSlugs({ a: 'x', b: 'x' }, 'owner')).toThrow(
      'owner: models "a" and "b" share slug "x"'
    )
  })
})

describe('denyAllAccess', () => {
  it('denies every operation and returns a fresh object per call', () => {
    const access = denyAllAccess()
    expect(access.create()).toBe(false)
    expect(access.read()).toBe(false)
    expect(access.update()).toBe(false)
    expect(access.delete()).toBe(false)
    expect(denyAllAccess()).not.toBe(access)
  })
})
