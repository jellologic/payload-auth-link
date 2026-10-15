import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { cliMain } from '../cli.js'
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

  test('applyCodemods returns the rewritten content', () => {
    const before = 'export const s = () => payload.betterAuth.api.getSession({ headers })'
    const result = applyCodemods('d.ts', before)
    expect(result.changed).toBe(true)
    expect(result.after).not.toBe(before)
    expect(result.after).toContain('getSession(headers)')
  })

  test('the CLI --write persists the rewrite to disk (regression: it wrote the original back)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'payload-auth-link-codemod-'))
    const file = join(dir, 'session.ts')
    writeFileSync(file, 'export const s = () => payload.betterAuth.api.getSession({ headers })')
    const out: string[] = []
    const sink = { write: (chunk: string) => void out.push(chunk) }
    const code = await cliMain(['codemod', '--src', dir, '--write'], sink, sink)
    expect(code).toBe(0)
    const onDisk = readFileSync(file, 'utf8')
    expect(onDisk).toContain('getSession(headers)')
    expect(onDisk).not.toContain('betterAuth.api.getSession')
    expect(out.join('')).toContain('rewritten')
  })

  test('the CLI dry run reports the rewrite but leaves the file untouched', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'payload-auth-link-codemod-'))
    const file = join(dir, 'session.ts')
    const before = 'export const s = () => payload.betterAuth.api.getSession({ headers })'
    writeFileSync(file, before)
    const out: string[] = []
    const sink = { write: (chunk: string) => void out.push(chunk) }
    const code = await cliMain(['codemod', '--src', dir], sink, sink)
    expect(code).toBe(0)
    expect(readFileSync(file, 'utf8')).toBe(before)
    expect(out.join('')).toContain('would be rewritten')
  })
})
