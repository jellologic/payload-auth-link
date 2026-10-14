import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { classifyPlugins } from '../doctor/plugins.js'
import { scanSource } from '../doctor/source-scan.js'
import { analyzeUsersCollection } from '../doctor/users.js'

describe('doctor units', () => {
  test('plugin classification names removed upstreams, unprobed satellites, and supported ones', () => {
    const findings = classifyPlugins([
      'magic-link',
      'organization',
      'api-key',
      'jwt',
      'next-cookies',
      'oidcProvider',
      'sso',
      '@better-auth/passkey',
      'totally-unknown',
    ])
    const byId = new Map(findings.map((finding) => [finding.id, finding.status]))
    expect(byId.get('magic-link')).toBe('auto-declarable')
    expect(byId.get('organization')).toBe('auto-declarable')
    expect(byId.get('api-key')).toBe('supported')
    expect(byId.get('@better-auth/passkey')).toBe('supported')
    expect(byId.get('jwt')).toBe('auto-declarable')
    expect(byId.get('next-cookies')).toBe('auto-declarable')
    expect(byId.get('oidcProvider')).toBe('removed-upstream')
    expect(byId.get('sso')).toBe('unsupported')
    expect(byId.get('totally-unknown')).toBe('unprobed')
  })

  test('collection slugs and config-source calls derive the live plugin set', async () => {
    const { pluginsFromCollectionSlugs, pluginsFromConfigSource } =
      await import('../doctor/plugins.js')
    expect(pluginsFromCollectionSlugs(['users', 'apiKeys', 'jwks', 'oauthApplications'])).toEqual([
      'api-key',
      'jwt',
      'oidcProvider',
    ])
    expect(pluginsFromConfigSource('magicLink({}), nextCookies(), apiKey({})')).toEqual([
      'api-key',
      'magic-link',
      'next-cookies',
    ])
  })

  test('users analysis: collisions block, single-select roles warn, non-canonical values warn', () => {
    const { finding, issues } = analyzeUsersCollection(
      {
        slug: 'users',
        auth: true,
        fields: [
          { name: 'email', type: 'email' },
          { name: 'role', type: 'select', hasMany: true, options: ['user', 'frontPlugin'] },
          { name: 'linkable', type: 'checkbox' },
        ],
      },
      'roles'
    )
    expect(finding?.collisions).toEqual(['linkable'])
    expect(finding?.roleField?.nonCanonical).toEqual(['frontPlugin'])
    expect(finding?.localStrategy).toBe(true)
    expect(finding?.notes.join(' ')).toContain('local strategy is ON')
    expect(issues.map((issue) => issue.code).sort()).toEqual([
      'injected-field-collision',
      'non-canonical-role-value',
    ])
  })

  test('users analysis: a single-select role field is adoption-incompatible', () => {
    const single = analyzeUsersCollection(
      {
        slug: 'users',
        auth: { disableLocalStrategy: true },
        fields: [{ name: 'roles', type: 'select', options: ['user', 'admin'] }],
      },
      'roles'
    )
    expect(single.issues.map((issue) => issue.code)).toContain('roles-field-single-select')
    const off = analyzeUsersCollection(
      {
        slug: 'users',
        auth: { disableLocalStrategy: true, strategies: [{ name: 'better-auth' }] },
        fields: [{ name: 'roles', type: 'text' }],
      },
      'roles'
    )
    expect(off.finding?.localStrategy).toBe(false)
    expect(off.finding?.notes.join(' ')).toContain('better-auth')
  })

  test('source scan classifies each call-site kind', () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-scan-'))
    try {
      writeFileSync(
        join(dir, 'calls.ts'),
        [
          "import { getPayloadAuth } from 'payload-auth'",
          'export const s = (h: Headers) => getPayloadAuth().betterAuth.api.getSession({ headers: h })',
          'export const ctx = async (p: { betterAuth: { $context: unknown } }) => p.betterAuth.$context',
          'export const read = (req: { user: { name: string } }) => req.user.name',
        ].join('\n')
      )
      writeFileSync(
        join(dir, 'fine.ts'),
        'import { getPayload } from "payload"\nexport const ok = () => getPayload'
      )
      const findings = scanSource(dir)
      const kinds = new Map(findings.map((finding) => [finding.kind, finding]))
      expect(kinds.get('payload-auth-import')?.files).toEqual(['calls.ts'])
      expect(kinds.get('get-payload-auth')?.files).toEqual(['calls.ts'])
      expect(kinds.get('better-auth-accessor')?.files).toEqual(['calls.ts'])
      expect(kinds.get('ba-internals')?.files).toEqual(['calls.ts'])
      expect(kinds.get('req-user-field')?.fields).toEqual(['name'])
      expect(findings.every((finding) => !finding.files.includes('fine.ts'))).toBe(true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
