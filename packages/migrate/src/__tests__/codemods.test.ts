import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { cliMain } from '../cli.js'
import { applyCodemods, findManualSites } from '../codemods.js'

/** Every payload-auth identifier the codemods account for (#70.4). */
function countAuthIdentifiers(text: string): number {
  return (text.match(/getPayloadAuth|betterAuth|internalAdapter|\$context/g) ?? []).length
}

describe('codemods (issues #53, #70)', () => {
  test('getPayloadAuth(configPromise) -> await getPayload({ config: configPromise })', () => {
    const before = [
      "import { getPayloadAuth } from 'payload-auth/better-auth'",
      'export async function load() {',
      '  return getPayloadAuth(configPromise)',
      '}',
    ].join('\n')
    const result = applyCodemods('a.ts', before)
    expect(result.changed).toBe(true)
    expect(result.applied).toEqual(['get-payload-auth'])
    expect(result.manual).toEqual([])
    expect(result.after).toContain("import { getPayload } from 'payload'")
    expect(result.after).toContain('(await getPayload({ config: configPromise }))')
    // Every reference accounted for: nothing payload-auth-shaped remains.
    expect(countAuthIdentifiers(result.after)).toBe(0)
  })

  test("no-arg getPayloadAuth() rewrites only with an '@payload-config' import", () => {
    const withConfig = [
      "import { getPayloadAuth } from 'payload-auth'",
      "import configPromise from '@payload-config'",
      'export async function load() {',
      '  return getPayloadAuth()',
      '}',
    ].join('\n')
    const rewritten = applyCodemods('a.ts', withConfig)
    expect(rewritten.changed).toBe(true)
    expect(rewritten.after).toContain('(await getPayload({ config }))')
    expect(countAuthIdentifiers(rewritten.after)).toBe(0)
    expect(rewritten.manual).toEqual([])

    // Without '@payload-config' the file cannot name the config: the
    // whole getPayloadAuth state stays untouched and is reported.
    const withoutConfig = [
      "import { getPayloadAuth } from 'payload-auth'",
      'export async function load() {',
      '  return getPayloadAuth()',
      '}',
    ].join('\n')
    const manual = applyCodemods('b.ts', withoutConfig)
    expect(manual.changed).toBe(false)
    expect(manual.after).toBe(withoutConfig)
    expect(manual.applied).toEqual([])
    expect(manual.manual.join(' ')).toContain('@payload-config')
    expect(manual.manual.join(' ')).toContain('import { getPayload }')
  })

  test('getSession call sites rewrite to the server API (shorthand and explicit headers)', () => {
    const shorthand = [
      "import { getPayloadAuth } from 'payload-auth'",
      'export async function currentSession(headers: Headers) {',
      '  const payload = getPayloadAuth()',
      '  return payload.betterAuth.api.getSession({ headers })',
      '}',
    ].join('\n')
    // getPayloadAuth() has no '@payload-config' here, so the payload
    // half stays manual — but the session call still rewrites.
    const result = applyCodemods('a.ts', shorthand)
    expect(result.changed).toBe(true)
    expect(result.applied).toContain('better-auth-get-session')
    expect(result.after).toContain('(await authLinkServer(payload).getSession(headers))')
    expect(result.after).not.toContain('betterAuth.api.getSession')

    const explicit = [
      'const payload = {} as { betterAuth: { api: { getSession: (o: unknown) => unknown } } }',
      'export async function session(request: Request) {',
      '  return payload.betterAuth.api.getSession({ headers: request.headers })',
      '}',
    ].join('\n')
    const rewritten = applyCodemods('b.ts', explicit)
    expect(rewritten.after).toContain('getSession(request.headers)')

    const multiline = [
      'const payload = {} as { betterAuth: { api: { getSession: (o: unknown) => unknown } } }',
      'export async function session() {',
      '  return payload.betterAuth.api.getSession({',
      '    headers: await headers(),',
      '  })',
      '}',
    ].join('\n')
    const unwrapped = applyCodemods('c.ts', multiline)
    expect(unwrapped.after).toContain('getSession(await headers())')
  })

  test('a non-async enclosing function is reported manual, never half-rewritten', () => {
    const before =
      'const payload = {} as { betterAuth: { api: { getSession: (o: unknown) => unknown } } }\n' +
      'export const s = () => payload.betterAuth.api.getSession({ headers })'
    const result = applyCodemods('a.ts', before)
    expect(result.changed).toBe(false)
    expect(result.applied).toEqual([])
    expect(result.manual.join(' ')).toContain('not async')
    // Other methods keep the generic accessor report.
    const other = applyCodemods(
      'b.ts',
      'const payload = {} as { betterAuth: { api: { signOut: (o: unknown) => unknown } } }\nexport async function out() {\n  return payload.betterAuth.api.signOut({ headers: new Headers() })\n}'
    )
    expect(other.manual.join(' ')).toContain('payload.betterAuth.api.<method>')
    expect(countAuthIdentifiers(result.after)).toBe(countAuthIdentifiers(before))
  })

  test('a type-only getPayloadAuth import is reported manual with the payload types suggested', () => {
    const before = [
      "import type { getPayloadAuth } from 'payload-auth'",
      '',
      'type Payload = ReturnType<typeof getPayloadAuth>',
      'export type { Payload }',
    ].join('\n')
    const result = applyCodemods('a.ts', before)
    expect(result.changed).toBe(false)
    const manual = result.manual.join(' ')
    expect(manual).toContain('type reference')
    expect(manual).toContain("import type { Payload } from 'payload'")
    expect(manual).toContain('getPayloadAuth import')
  })

  test('aliased betterAuth bindings are never rewritten — reported manual instead', () => {
    const before = [
      'const payload = {} as { betterAuth: { api: { getSession: (o: unknown) => unknown } } }',
      'export async function session(headers: Headers) {',
      '  const auth = payload.betterAuth',
      '  return auth.api.getSession({ headers })',
      '}',
    ].join('\n')
    const result = applyCodemods('a.ts', before)
    expect(result.changed).toBe(false)
    expect(result.manual.join(' ')).toContain('payload.betterAuth accessor')
    expect(result.after).toContain('const auth = payload.betterAuth')
  })

  test('internals are reported manual, never half-rewritten', () => {
    const before =
      'export const read = async (payload: unknown) => {\n  const ctx = await (\n    payload as { betterAuth: { $context: Promise<unknown> } }\n  ).betterAuth.$context\n  return ctx\n}'
    const internals = applyCodemods('c.ts', before)
    expect(internals.manual.join(' ')).toContain('$context internals')
    const adapter = applyCodemods(
      'd.ts',
      'export const find = async (ctx: { internalAdapter: { findOne: () => unknown } }) => ctx.internalAdapter.findOne()'
    )
    expect(adapter.manual.join(' ')).toContain('internalAdapter')
  })

  test('toNextJsHandler keeps its behavior and matches aliased imports', () => {
    const plain = [
      "import { toNextJsHandler } from 'better-auth/next-js'",
      'export { handler as GET, handler as POST } = toNextJsHandler(payload.betterAuth)',
    ].join('\n')
    const plainResult = applyCodemods('a.ts', plain)
    expect(plainResult.changed).toBe(true)
    expect(plainResult.after).toContain(
      "import { createRouteHandlers } from '@payload-auth-link/next'"
    )
    expect(plainResult.after).toContain('export const GET = createRouteHandlers.GET')
    expect(plainResult.after).toContain('export const POST = createRouteHandlers.POST')
    expect(plainResult.after).not.toContain('toNextJsHandler')

    const aliased = [
      "import { toNextJsHandler as route } from 'better-auth/next-js'",
      'export { handler as GET, handler as POST } = route(payload.betterAuth)',
    ].join('\n')
    const aliasedResult = applyCodemods('b.ts', aliased)
    expect(aliasedResult.changed).toBe(true)
    expect(aliasedResult.after).toContain('export const GET = createRouteHandlers.GET')
    expect(aliasedResult.after).not.toContain('route(payload.betterAuth)')
    expect(aliasedResult.after).not.toContain('toNextJsHandler')
  })

  test('every identifier is either rewritten away or listed in manual (#70.4)', () => {
    const samples: readonly { readonly name: string; readonly content: string }[] = [
      {
        name: 'fixture auth-calls.ts',
        content: [
          "import { getPayloadAuth } from 'payload-auth'",
          '',
          'export async function currentSession(headers: Headers): Promise<unknown> {',
          '  const payload = getPayloadAuth()',
          '  return payload.betterAuth.api.getSession({ headers })',
          '}',
          '',
          'export async function signOut(headers: Headers): Promise<void> {',
          '  const payload = getPayloadAuth()',
          '  await payload.betterAuth.api.signOut({ headers })',
          '}',
        ].join('\n'),
      },
      {
        name: 'fixture api-key-bridge.ts',
        content: [
          "import type { getPayloadAuth } from 'payload-auth'",
          '',
          'type Payload = ReturnType<typeof getPayloadAuth>',
          '',
          'export async function apiKeySession(payload: Payload, key: string): Promise<string | null> {',
          '  const ctx = await payload.betterAuth.$context',
          '  const row = await ctx.adapter.findOne({ model: "apikey", where: [{ field: "key", value: key }] })',
          '  if (row === null || row.userId === null) {',
          '    return null',
          '  }',
          '  const session = await ctx.internalAdapter.createSession(String(row.userId))',
          '  return session.token',
          '}',
        ].join('\n'),
      },
      {
        name: 'fully rewritable',
        content: [
          "import { getPayloadAuth } from 'payload-auth'",
          "import configPromise from '@payload-config'",
          'export async function load() {',
          '  const payload = getPayloadAuth(configPromise)',
          '  return payload.betterAuth.api.getSession({ headers: new Headers() })',
          '}',
        ].join('\n'),
      },
    ]
    for (const sample of samples) {
      const before = sample.content
      const result = applyCodemods('sample.ts', before)
      const beforeCount = countAuthIdentifiers(before)
      const afterCount = countAuthIdentifiers(result.after)
      // Every reference moved either out of the file (rewritten) or into
      // the manual list — nothing silently ignored.
      if (afterCount === 0) {
        expect(result.manual, sample.name).toEqual([])
      } else {
        expect(result.manual.length, sample.name).toBeGreaterThan(0)
        expect(afterCount, sample.name).toBeLessThan(beforeCount + 1)
        // Each surviving line is covered by a manual report.
        const reported = result.manual.join(' ')
        for (const [index, line] of result.after.split('\n').entries()) {
          if (countAuthIdentifiers(line) === 0) {
            continue
          }
          expect(reported, `${sample.name} line ${index + 1}`).toContain(`line ${index + 1}`)
        }
      }
    }
    // findManualSites on its own agrees with applyCodemods' accounting.
    const untouched = samples[1]
    if (untouched !== undefined) {
      expect(findManualSites(untouched.content).length).toBeGreaterThan(0)
    }
  })

  test('the CLI --write persists the rewrite to disk (regression: it wrote the original back)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'payload-auth-link-codemod-'))
    const file = join(dir, 'session.ts')
    writeFileSync(
      file,
      'export const s = async () => payload.betterAuth.api.getSession({ headers })'
    )
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
    const before = 'export const s = async () => payload.betterAuth.api.getSession({ headers })'
    writeFileSync(file, before)
    const out: string[] = []
    const sink = { write: (chunk: string) => void out.push(chunk) }
    const code = await cliMain(['codemod', '--src', dir], sink, sink)
    expect(code).toBe(0)
    expect(readFileSync(file, 'utf8')).toBe(before)
    expect(out.join('')).toContain('would be rewritten')
  })
})
