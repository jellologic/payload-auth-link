import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { readableCredentialFields } from '../doctor/adopted-credentials.js'
import { classifyPlugins, pluginsFromSourceTree } from '../doctor/plugins.js'
import { legacyInvitationRolesWarning, runDoctor } from '../doctor/run-doctor.js'
import { scanSource } from '../doctor/source-scan.js'
import { snakeCaseTableName, sourceMapFromConfig } from '../doctor/source-layout.js'
import type { DoctorReport } from '../doctor/types.js'
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
    expect(
      pluginsFromConfigSource(
        "import { magicLink, nextCookies, apiKey } from 'better-auth/plugins'\nmagicLink({}), nextCookies(), apiKey({})"
      )
    ).toEqual(['api-key', 'magic-link', 'next-cookies'])
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

  test('users analysis: the plugin’s own injected fields on the TARGET config are not collisions (#88)', () => {
    // The target config, after authLink ran: its strategy rides the
    // collection and every injected field is present.
    const { finding, issues } = analyzeUsersCollection(
      {
        slug: 'users',
        auth: { strategies: [{ name: 'auth-link' }] },
        fields: [
          { name: 'email', type: 'email' },
          { name: 'roles', type: 'select', hasMany: true, options: ['user', 'admin'] },
          { name: 'identities', type: 'array' },
          { name: 'phone', type: 'text' },
          { name: 'suspendedUntil', type: 'date' },
          { name: 'suspendReason', type: 'text' },
          { name: 'linkable', type: 'checkbox' },
          { name: 'linkableEmail', type: 'text' },
        ],
      },
      'roles'
    )
    expect(finding?.collisions).toEqual([])
    expect(issues.map((issue) => issue.code)).not.toContain('injected-field-collision')
    expect(finding?.notes.join(' ')).toContain('already installed')
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

  test('users analysis: declared collection hooks warn with the context-marker skip (#123)', () => {
    const hooked = analyzeUsersCollection(
      {
        slug: 'users',
        auth: true,
        fields: [{ name: 'email', type: 'email' }],
        hooks: { beforeChange: [() => {}], afterChange: [] },
      },
      'roles'
    )
    const warning = hooked.issues.find((issue) => issue.code === 'users-collection-hooks')
    expect(warning?.detail).toContain('once per user')
    expect(warning?.detail).toContain('payloadAuthLinkMigration')
    expect(warning?.detail).toContain('MIGRATION_CONTEXT')
    // An empty hooks array (payload-auth's builder emits those)
    // declares nothing, so no warning.
    expect(
      analyzeUsersCollection(
        {
          slug: 'users',
          auth: true,
          fields: [],
          hooks: { beforeChange: [], afterChange: [] },
        },
        'roles'
      ).issues.map((issue) => issue.code)
    ).not.toContain('users-collection-hooks')
  })

  test('users analysis: adopt mode with the local strategy ON is flagged; the note names no source plugin (#110, #113)', () => {
    const collection = { slug: 'users', auth: true, fields: [{ name: 'email', type: 'email' }] }
    const adopt = analyzeUsersCollection(collection, 'roles', { adoptTarget: true })
    const issue = adopt.issues.find((entry) => entry.code === 'adopt-local-strategy-on')
    expect(issue?.detail).toContain('disableLocalStrategy: true')
    expect(issue?.detail).toContain('provider-better-auth 0.11.0 or later')
    expect(issue?.detail).toContain('older engines fail every NEW user')
    // The note no longer claims payload-auth always leaves it on.
    expect(adopt.finding?.notes.join(' ')).not.toContain('payload-auth leaves it active')
    // Not an adopt target (the importer's ba-* layout): no flag.
    expect(
      analyzeUsersCollection(collection, 'roles').issues.map((entry) => entry.code)
    ).not.toContain('adopt-local-strategy-on')
    // Local strategy off: nothing to flag in adopt mode either.
    expect(
      analyzeUsersCollection({ ...collection, auth: { disableLocalStrategy: true } }, 'roles', {
        adoptTarget: true,
      }).issues.map((entry) => entry.code)
    ).not.toContain('adopt-local-strategy-on')
  })

  test('genericOAuth imported from a nested subpath is detected (#110)', async () => {
    const { pluginsFromConfigSource } = await import('../doctor/plugins.js')
    expect(
      pluginsFromConfigSource(
        "import { genericOAuth } from 'better-auth/plugins/generic-oauth'\ngenericOAuth({ config: [] })"
      )
    ).toEqual(['generic-oauth'])
    const dir = mkdtempSync(join(tmpdir(), 'doctor-generic-oauth-'))
    try {
      writeFileSync(
        join(dir, 'auth.ts'),
        [
          "import { genericOAuth } from 'better-auth/plugins/generic-oauth'",
          'export const plugins = [genericOAuth({ config: [] })]',
        ].join('\n')
      )
      expect(pluginsFromSourceTree(dir)).toEqual([{ id: 'generic-oauth', file: 'auth.ts' }])
      const report = await runDoctor({
        configPath: new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
          .pathname,
        srcDir: dir,
      })
      expect(report.warnings.map((entry) => entry.code)).toContain('generic-oauth-providers')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('the users-collection-hooks issue is a warning with the marker as the skip (#123)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-hooks-'))
    try {
      const report = await runDoctor({
        configPath: new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
          .pathname,
        srcDir: dir,
        databaseUrl: '',
        loadModule: () =>
          Promise.resolve({
            custom: { hasBetterAuthPlugin: true },
            collections: [
              {
                slug: 'users',
                auth: true,
                fields: [{ name: 'email', type: 'email' }],
                hooks: { beforeChange: [() => {}] },
              },
            ],
          }),
      })
      const codes = report.warnings.map((issue) => issue.code)
      expect(codes).toContain('users-collection-hooks')
      expect(report.blockers.map((issue) => issue.code)).not.toContain('users-collection-hooks')
      expect(
        report.warnings.find((issue) => issue.code === 'users-collection-hooks')?.detail
      ).toContain('payloadAuthLinkMigration')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
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

describe('doctor: the source layout from the payload-auth config (#113)', () => {
  const stamped = (slug: string, key: string, extra: Record<string, unknown> = {}) => ({
    slug,
    custom: { betterAuthModelKey: key },
    fields: [],
    ...extra,
  })

  test('custom slugs map to their snake_case tables; absent plugins map to null', () => {
    const config = {
      collections: [
        stamped('users', 'user', {
          fields: [{ name: 'role', type: 'select', hasMany: true, options: ['user'] }],
        }),
        stamped('user-accounts', 'account'),
        stamped('userSessions', 'session'),
        stamped('verifications', 'verification'),
        stamped('apiKeys', 'apikey'),
        stamped('jwks', 'jwks', { dbName: 'auth_jwks' }),
        { slug: 'posts', fields: [] },
      ],
    }
    expect(sourceMapFromConfig(config)).toEqual({
      users: 'users',
      accounts: 'user_accounts',
      sessions: 'user_sessions',
      verifications: 'verifications',
      api_keys: 'api_keys',
      jwks: 'auth_jwks',
      organizations: null,
      members: null,
      invitations: null,
      users_role: 'users_role',
    })
    expect(snakeCaseTableName('organizationRoles')).toBe('organization_roles')
  })

  test('a config without payload-auth collections derives nothing', () => {
    expect(sourceMapFromConfig({ collections: [{ slug: 'users', fields: [] }] })).toBeNull()
    expect(sourceMapFromConfig(null)).toBeNull()
    // A single-select role keeps the default child table (not guessed).
    expect(
      sourceMapFromConfig({
        collections: [stamped('members-of-staff', 'user', { fields: [{ name: 'role' }] })],
      })?.users_role
    ).toBeUndefined()
  })

  test('runDoctor reports the derived map, and prints it for --source-map', async () => {
    const report = await runDoctor({
      configPath: new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
        .pathname,
      srcDir: mkdtempSync(join(tmpdir(), 'doctor-layout-')),
      databaseUrl: '',
      loadModule: () =>
        Promise.resolve({
          custom: { hasBetterAuthPlugin: true },
          collections: [stamped('users', 'user'), stamped('user-sessions', 'session')],
        }),
    })
    expect(report.sourceMap?.sessions).toBe('user_sessions')
    expect(report.sourceMap?.accounts).toBeNull()
  })
})

describe('doctor on a TARGET config (issue #116)', () => {
  const authLinkEntry = Object.assign(() => ({}), {
    slug: 'payload-auth-link',
    options: { rolesField: 'role' },
  })
  const fixturePath = new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
    .pathname

  test('no payload-auth-not-detected warning; an adopted session collection without authenticationMethod warns', async () => {
    const srcDir = mkdtempSync(join(tmpdir(), 'doctor-target-'))
    try {
      const report = await runDoctor({
        configPath: fixturePath,
        srcDir,
        databaseUrl: '',
        loadModule: () =>
          Promise.resolve({
            plugins: [authLinkEntry],
            collections: [
              {
                slug: 'users',
                auth: { disableLocalStrategy: true },
                fields: [
                  { name: 'email', type: 'email' },
                  { name: 'role', type: 'select', hasMany: true, options: ['user'] },
                ],
              },
              {
                slug: 'sessions',
                fields: [
                  { name: 'user', type: 'relationship', relationTo: 'users' },
                  { name: 'token', type: 'text' },
                  { name: 'expiresAt', type: 'date' },
                ],
              },
            ],
          }),
      })
      const codes = report.warnings.map((issue) => issue.code)
      expect(codes).not.toContain('payload-auth-not-detected')
      expect(codes).toContain('adopt-session-no-authentication-method')
      expect(
        report.warnings.find((issue) => issue.code === 'adopt-session-no-authentication-method')
          ?.detail
      ).toContain("the adopted session collection 'sessions' declares no 'authenticationMethod'")
    } finally {
      rmSync(srcDir, { recursive: true, force: true })
    }
  })

  test('the key-value adapter no longer gates the doctor (issue #139)', async () => {
    // The kit records into its own collection (issue #139): any
    // payload.config.kv — Redis included — is supported, and the
    // config-level kv-adapter blocker is gone. The record-store check
    // is database-level (migration-records-store-missing).
    const report = async (kv: unknown): Promise<DoctorReport> =>
      runDoctor({
        configPath: fixturePath,
        databaseUrl: '',
        loadModule: () =>
          Promise.resolve({
            kv,
            plugins: [authLinkEntry],
            collections: [],
          }),
      })
    for (const kv of [{ init: () => ({}) }, { kvCollection: { slug: 'payload-kv' } }, undefined]) {
      const codes = (await report(kv)).blockers.map((issue) => issue.code)
      expect(codes).not.toContain('kv-adapter-unsupported')
      expect(codes).not.toContain('migration-records-store-missing')
    }
  })

  test('a session collection that declares the field, or none at all, does not warn', async () => {
    const { sessionCollectionsWithoutAuthMethod } = await import('../doctor/run-doctor.js')
    const session = (extra: readonly Record<string, unknown>[]): Record<string, unknown> => ({
      slug: 'sessions',
      fields: [
        { name: 'userId', type: 'text' },
        { name: 'token', type: 'text' },
        { name: 'expiresAt', type: 'date' },
        ...extra,
      ],
    })
    expect(sessionCollectionsWithoutAuthMethod({ collections: [session([])] })).toEqual([
      'sessions',
    ])
    expect(
      sessionCollectionsWithoutAuthMethod({
        collections: [session([{ name: 'authenticationMethod', type: 'text' }])],
      })
    ).toEqual([])
    // payload-auth's own stamp finds it whatever its fields.
    expect(
      sessionCollectionsWithoutAuthMethod({
        collections: [
          { slug: 'user-sessions', custom: { betterAuthModelKey: 'session' }, fields: [] },
        ],
      })
    ).toEqual(['user-sessions'])
    expect(sessionCollectionsWithoutAuthMethod({ collections: [{ slug: 'posts' }] })).toEqual([])
    expect(sessionCollectionsWithoutAuthMethod(null)).toEqual([])
  })

  test('a config with neither payload-auth nor payload-auth-link still warns it found none', async () => {
    const srcDir = mkdtempSync(join(tmpdir(), 'doctor-neither-'))
    try {
      const report = await runDoctor({
        configPath: fixturePath,
        srcDir,
        databaseUrl: '',
        loadModule: () => Promise.resolve({ collections: [] }),
      })
      expect(report.warnings.map((issue) => issue.code)).toContain('payload-auth-not-detected')
    } finally {
      rmSync(srcDir, { recursive: true, force: true })
    }
  })
})

describe('doctor robustness (issue #71)', () => {
  test('an unloadable config is a blocker, not a crash — the static scans still report', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-unloadable-'))
    try {
      writeFileSync(
        join(dir, 'calls.ts'),
        [
          "import { getPayloadAuth } from 'payload-auth'",
          'export const s = async () => getPayloadAuth().betterAuth.api.getSession({ headers })',
        ].join('\n')
      )
      const report = await runDoctor({
        configPath: '/nonexistent/payload.config.ts',
        srcDir: dir,
        loadModule: () =>
          Promise.reject(
            new Error("oidcProvider is not exported by 'payload-auth' (better-auth 1.7 upgrade)")
          ),
      })
      expect(report.blockers.map((issue) => issue.code)).toContain('config-unloadable')
      expect(report.blockers.find((issue) => issue.code === 'config-unloadable')?.detail).toContain(
        'better-auth 1.7'
      )
      // Config-derived sections are skipped, and the shape stays valid.
      expect(report.users).toBeNull()
      expect(report.warnings.map((issue) => issue.code)).not.toContain('payload-auth-not-detected')
      // The source scan still ran and still reports the call sites.
      const kinds = new Map(report.source.map((finding) => [finding.kind, finding]))
      expect(kinds.get('get-payload-auth')?.files).toEqual(['calls.ts'])
      expect(kinds.get('better-auth-accessor')?.files).toEqual(['calls.ts'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('plugin factory calls in non-config files are reported; removed ones are blocked (#71)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-plugins-'))
    try {
      writeFileSync(
        join(dir, 'auth-plugins.ts'),
        [
          "import { admin, anonymous, magicLink } from 'better-auth/plugins'",
          "import { nextCookies } from 'better-auth/next-js'",
          'export const plugins = [',
          '  admin(),',
          '  anonymous(),',
          '  magicLink({ sendMagicLink: async () => {} }),',
          '  nextCookies(),',
          ']',
          '// legacy pre-1.7 config: oidcProvider({ issuer: "https://example.com" })',
        ].join('\n')
      )
      const report = await runDoctor({
        configPath: new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
          .pathname,
        srcDir: dir,
      })
      const byId = new Map(report.plugins.map((finding) => [finding.id, finding]))
      expect(byId.get('admin')?.status).toBe('auto-declarable')
      expect(byId.get('anonymous')?.files).toEqual(['auth-plugins.ts'])
      expect(byId.get('magic-link')?.files).toEqual(['auth-plugins.ts'])
      expect(byId.get('next-cookies')?.status).toBe('auto-declarable')
      // The removed-in-1.7 plugin is flagged from the static scan alone.
      expect(byId.get('oidcProvider')?.status).toBe('removed-upstream')
      expect(byId.get('oidcProvider')?.detail).toContain('1.7')
      expect(report.blockers.map((issue) => `${issue.code} ${issue.detail}`).join(' ')).toContain(
        'ba-plugin-removed-upstream'
      )
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('the source-tree plugin scan dedupes and names files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-plugins-units-'))
    try {
      writeFileSync(
        join(dir, 'a.ts'),
        [
          "import { admin, bearer, multiSession } from 'better-auth/plugins'",
          'export const x = () => admin({}) && bearer({}) && multiSession({})',
        ].join('\n')
      )
      mkdirSync(join(dir, 'nested'))
      writeFileSync(
        join(dir, 'nested', 'b.ts'),
        ["import { bearer } from 'better-auth/plugins'", 'export const y = () => bearer({})'].join(
          '\n'
        )
      )
      const hits = pluginsFromSourceTree(dir)
      const filesById = new Map<string, string[]>()
      for (const hit of hits) {
        filesById.set(hit.id, [...(filesById.get(hit.id) ?? []), hit.file])
      }
      expect(filesById.get('admin')).toEqual(['a.ts'])
      // Same plugin in two files: one finding, both files named.
      expect(filesById.get('bearer')).toEqual(['a.ts', 'nested/b.ts'])
      expect(filesById.get('multi-session')).toEqual(['a.ts'])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('the scan ignores test files and non-Better-Auth `call(` noise (#75)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'doctor-plugins-noise-'))
    try {
      // A security-tail TEST mentioning removed plugins: app-internal
      // evidence, never the app's Better Auth posture.
      mkdirSync(join(dir, '__tests__'))
      writeFileSync(
        join(dir, '__tests__', 'redirects.security-tail.test.ts'),
        "import { mcp } from 'better-auth/plugins'\nexport const s = () => mcp({})\n"
      )
      // A non-test file whose `admin(` belongs to another package's
      // API — no Better Auth import anywhere in the file.
      writeFileSync(join(dir, 'prose.ts'), 'export const f = () => admin({})\n')
      // The real signal, for contrast.
      writeFileSync(
        join(dir, 'auth.ts'),
        ["import { admin } from 'better-auth/plugins'", 'export const p = [admin()]'].join('\n')
      )
      const hits = pluginsFromSourceTree(dir)
      expect(hits.map((hit) => hit.id)).toEqual(['admin'])
      expect(hits[0]?.file).toBe('auth.ts')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('config-text plugin detection requires a Better Auth import (#75)', async () => {
    const { pluginsFromConfigSource: scan } = await import('../doctor/plugins.js')
    expect(scan('const x = admin({}) && magicLink({})')).toEqual([])
    expect(
      scan(
        "import { admin, magicLink } from 'better-auth/plugins'\nconst x = admin({}) && magicLink({})"
      )
    ).toEqual(['admin', 'magic-link'])
  })
})

describe('doctor report formatting', () => {
  test('an unloadable config still prints a report and exits 1 through the CLI', async () => {
    const { cliMain } = await import('../cli.js')
    const chunks: string[] = []
    const sink = {
      write: (chunk: string): void => {
        chunks.push(chunk)
      },
    }
    const code = await cliMain(['doctor', '--config', '/nonexistent/payload.config.ts'], sink, sink)
    expect(code).toBe(1)
    expect(chunks.join('')).toContain('[config-unloadable]')
    expect(chunks.join('')).toContain('== source scan ==')
    expect(chunks.join('')).toContain('== database ==')
  })

  test('formats blockers, warnings, tables, and behaviour changes as text', async () => {
    // formatReport is not exported; exercise it through cliMain with a
    // config the doctor can load (the CLI prints the text report when
    // --json is absent).
    const { cliMain } = await import('../cli.js')
    const chunks: string[] = []
    const sink = {
      write: (chunk: string): void => {
        chunks.push(chunk)
      },
    }
    const configPath = new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
      .pathname
    const code = await cliMain(['doctor', '--config', configPath], sink, sink)
    expect(code).toBe(2)
    const format = chunks.join('')
    expect(format).toContain('== versions ==')
    expect(format).toContain('== Better Auth plugins ==')
    expect(format).toContain('== users collection ==')
    expect(format).toContain('== source scan ==')
    expect(format).toContain('== database ==')
    expect(format).toContain('not inspected')
    expect(format).toContain('== behaviour changes')
    expect(format).toContain('== blockers ==')
    expect(format).toContain('== warnings ==')
  })
})

describe('doctor: legacy invitation roles (#142)', () => {
  test('a positive count warns with the artifact, the count, and the hand rewrite', () => {
    const warning = legacyInvitationRolesWarning({ legacyInvitationRoles: 3 })
    expect(warning?.code).toBe('legacy-invitation-roles')
    expect(warning?.detail).toContain('3 invitation row(s)')
    expect(warning?.detail).toContain('["member"]')
    expect(warning?.detail).toContain("UPDATE invitations SET role = 'member' WHERE role LIKE '[%'")
    expect(warning?.detail).toContain("'a,b'")
    // adopt-prelink writes the users collection only: the warning must
    // not send the operator to it for this fix.
    expect(warning?.detail).toContain('does not touch the invitations table')
  })

  test('zero, unknown (null), and absent counts emit nothing', () => {
    expect(legacyInvitationRolesWarning({})).toBeNull()
    expect(legacyInvitationRolesWarning({ legacyInvitationRoles: 0 })).toBeNull()
    expect(legacyInvitationRolesWarning({ legacyInvitationRoles: null })).toBeNull()
  })
})

describe('doctor: readable credential fields on adopted collections (#145)', () => {
  const selfRead = { read: ({ req }: { req: { user?: unknown } }) => req.user !== null }

  test('flags each credential field lacking a field-level read, naming collection and field', () => {
    const issues = readableCredentialFields({
      collections: [
        {
          slug: 'accounts',
          custom: { betterAuthModelKey: 'account' },
          access: selfRead,
          fields: [
            { name: 'email', type: 'email' },
            { name: 'password', type: 'text' },
            { name: 'accessToken', type: 'text' },
            { name: 'refresh_token', type: 'text' },
            { name: 'id_token', type: 'text' },
          ],
        },
        {
          slug: 'userSessions',
          custom: { betterAuthModelKey: 'session' },
          fields: [{ name: 'token', type: 'text' }],
        },
        {
          slug: 'apiKeys',
          custom: { betterAuthModelKey: 'apikey' },
          fields: [{ name: 'key', type: 'text' }],
        },
      ],
    })
    // One per field, canonical order within a model: accounts'
    // password, accessToken, refresh_token, id_token (camelCase
    // spellings first), then the session token and the API key.
    expect(issues.map((issue) => issue.code)).toEqual([
      'readable-credential-field',
      'readable-credential-field',
      'readable-credential-field',
      'readable-credential-field',
      'readable-credential-field',
      'readable-credential-field',
    ])
    const details = issues.map((issue) => issue.detail)
    expect(details[0]).toContain("'accounts'")
    expect(details[0]).toContain("'password'")
    expect(details[1]).toContain("'accessToken'")
    expect(details[2]).toContain("'refresh_token'")
    expect(details[3]).toContain("'id_token'")
    expect(details[4]).toContain("'userSessions'")
    expect(details[4]).toContain("'token'")
    expect(details[5]).toContain("'apiKeys'")
    expect(details[5]).toContain("'key'")
    for (const detail of details) {
      expect(detail).toContain('access: { read:')
      expect(detail).toContain('denyAllAccess()')
    }
  })

  test('a field-level access.read, or a literal () => false collection read, stays silent', () => {
    const account = (access: unknown, fieldAccess?: unknown): Record<string, unknown> => ({
      slug: 'accounts',
      custom: { betterAuthModelKey: 'account' },
      ...(access === undefined ? {} : { access }),
      fields: [
        {
          name: 'password',
          type: 'text',
          ...(fieldAccess === undefined ? {} : { access: fieldAccess }),
        },
      ],
    })
    // The host decided at field level: silent whatever the collection read.
    expect(
      readableCredentialFields({ collections: [account(selfRead, { read: () => false })] })
    ).toEqual([])
    // The collection-level read denies everyone — denyAllAccess's exact shape.
    expect(readableCredentialFields({ collections: [account({ read: () => false })] })).toEqual([])
    expect(
      readableCredentialFields({
        collections: [
          account({
            read: () => false,
            create: () => false,
            update: () => false,
            delete: () => false,
          }),
        ],
      })
    ).toEqual([])
    // An OPAQUE collection read proves nothing: it still flags.
    expect(readableCredentialFields({ collections: [account(selfRead)] })).toHaveLength(1)
  })

  test('no collection read at all still flags — Payload defaults to any signed-in user', () => {
    const issues = readableCredentialFields({
      collections: [
        {
          slug: 'verifications',
          custom: { betterAuthModelKey: 'verification' },
          fields: [{ name: 'value', type: 'text' }],
        },
      ],
    })
    expect(issues).toHaveLength(1)
    expect(issues[0]?.detail).toContain("'verifications'")
    expect(issues[0]?.detail).toContain("'value'")
    expect(issues[0]?.detail).toContain('no read access')
  })

  test('collections without payload-auth’s model stamp are never flagged', () => {
    expect(
      readableCredentialFields({
        collections: [
          {
            slug: 'posts',
            fields: [
              { name: 'token', type: 'text' },
              { name: 'key', type: 'text' },
            ],
          },
          { slug: 'accounts', fields: [{ name: 'password', type: 'text' }] },
        ],
      })
    ).toEqual([])
  })

  test('fields nested in tabs are found', () => {
    const issues = readableCredentialFields({
      collections: [
        {
          slug: 'accounts',
          custom: { betterAuthModelKey: 'account' },
          access: selfRead,
          fields: [
            {
              type: 'tabs',
              tabs: [{ label: 'Credentials', fields: [{ name: 'password', type: 'text' }] }],
            },
          ],
        },
      ],
    })
    expect(issues).toHaveLength(1)
    expect(issues[0]?.detail).toContain("'password'")
  })
})

describe('doctor: the credential check rides the adopt-target gate (#145)', () => {
  const authLinkEntry = Object.assign(() => ({}), {
    slug: 'payload-auth-link',
    options: { rolesField: 'role' },
  })
  const fixturePath = new URL('../__fixtures__/doctor-fixture/payload.config.ts', import.meta.url)
    .pathname

  const config = (adoptTarget: boolean): Record<string, unknown> => ({
    ...(adoptTarget ? { plugins: [authLinkEntry] } : { custom: { hasBetterAuthPlugin: true } }),
    collections: [
      {
        slug: 'users',
        auth: { disableLocalStrategy: true },
        fields: [{ name: 'email', type: 'email' }],
      },
      {
        slug: 'accounts',
        custom: { betterAuthModelKey: 'account' },
        access: { read: ({ req }: { req: { user?: unknown } }) => req.user !== null },
        fields: [{ name: 'password', type: 'text' }],
      },
      {
        slug: 'sessions',
        custom: { betterAuthModelKey: 'session' },
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users' },
          { name: 'token', type: 'text' },
          { name: 'expiresAt', type: 'date' },
          { name: 'authenticationMethod', type: 'text' },
        ],
      },
    ],
  })

  test('an adopt target warns once per readable credential field', async () => {
    const srcDir = mkdtempSync(join(tmpdir(), 'doctor-credentials-'))
    try {
      const report = await runDoctor({
        configPath: fixturePath,
        srcDir,
        databaseUrl: '',
        loadModule: () => Promise.resolve(config(true)),
      })
      const issues = report.warnings.filter((issue) => issue.code === 'readable-credential-field')
      expect(issues.map((issue) => issue.detail)).toEqual([
        expect.stringContaining("'accounts'"),
        expect.stringContaining("'sessions'"),
      ])
      expect(issues[0]?.detail).toContain("'password'")
      expect(issues[1]?.detail).toContain("'token'")
      expect(report.blockers.map((issue) => issue.code)).not.toContain('readable-credential-field')
    } finally {
      rmSync(srcDir, { recursive: true, force: true })
    }
  })

  test('the payload-auth SOURCE config is not flagged (nothing is adopted yet)', async () => {
    const srcDir = mkdtempSync(join(tmpdir(), 'doctor-credentials-source-'))
    try {
      const report = await runDoctor({
        configPath: fixturePath,
        srcDir,
        databaseUrl: '',
        loadModule: () => Promise.resolve(config(false)),
      })
      expect(report.warnings.map((issue) => issue.code)).not.toContain('readable-credential-field')
    } finally {
      rmSync(srcDir, { recursive: true, force: true })
    }
  })
})
