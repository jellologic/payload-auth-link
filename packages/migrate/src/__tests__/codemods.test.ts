import { describe, expect, test } from 'vitest'
import { applyCodemods, codemodRules } from '../codemods.js'

describe('codemods (issue #53)', () => {
  test('getPayloadAuth -> getPayload', () => {
    const before = [
      "import { getPayloadAuth } from 'payload-auth'",
      'export const p = getPayloadAuth()',
    ].join('\n')
    const result = applyCodemods('a.ts', before)
    expect(result.changed).toBe(true)
    expect(result.applied).toContain('get-payload-auth')
    expect(result.manual).toEqual([])
    expect(result.applied.length).toBeGreaterThan(0)
    // The rewrite output no longer references getPayloadAuth.
    const after = codemodRules.find((rule) => rule.id === 'get-payload-auth')?.apply(before) ?? ''
    expect(after).not.toContain('getPayloadAuth')
    expect(after).toContain('getPayload({ config })')
  })

  test('getSession call site rewrites to the server API', () => {
    const before = 'export const s = () => payload.betterAuth.api.getSession({ headers })'
    const after =
      codemodRules.find((rule) => rule.id === 'better-auth-get-session')?.apply(before) ?? ''
    expect(after).not.toContain('betterAuth.api.getSession')
    expect(after).toContain('getSession(headers)')
  })

  test('unrewritable call sites are reported as manual, never half-rewritten', () => {
    const before = 'const other = payload.betterAuth.api.signOut({ headers })'
    const result = applyCodemods('b.ts', before)
    expect(result.changed).toBe(false)
    expect(result.manual.join(' ')).toContain('payload.betterAuth.api.<method>')
    const internals = applyCodemods('c.ts', 'await payload.betterAuth.$context.internalAdapter.x()')
    expect(internals.manual.join(' ')).toContain('$context internals')
  })
})
