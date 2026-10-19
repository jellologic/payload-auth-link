/**
 * Integration test: `reqUser: 'document'` (issue #57). Access
 * functions read the full user document — for cookie AND local
 * sessions — while the security-relevant projected fields stay
 * authoritative (roles after the MFA projection, suspension markers).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { nullLogger, parseEmail, parseRole } from '@payload-auth-link/core'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'req-user-document-secret-32ch'

const dir = mkdtempSync(join(tmpdir(), 'pal-req-user-'))
const stub = createStubProvider()

const baseOptions: AuthLinkPluginOptions = {
  baseUrl: ORIGIN,
  roles: ['user', 'admin'],
  defaultRole: 'user',
  roleManagerRoles: ['admin'],
  reqUser: 'document',
  providers: [{ ...stub.provider, providerUserIdsAreDocumentIds: true }],
  // Issue #126: the guest marker's document-mode copy is exercised by
  // the anonymous test below; harmless for every named session.
  admitAnonymous: true,
  logger: nullLogger(),
}

async function boot(key: string): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    db: sqliteAdapter({
      client: { url: `file:${join(dir, `${key}.db`)}` },
      push: true,
    }),
    admin: { user: 'users' },
    collections: [
      {
        slug: 'users',
        auth: true,
        fields: [
          // Host-added fields the projection never carries — exactly
          // the payload-auth layout's shape (#57's motivation).
          { name: 'activeOrganization', type: 'text' },
          { name: 'department', type: 'text' },
        ],
      },
      {
        slug: 'pages',
        fields: [{ name: 'title', type: 'text' }],
        access: {
          // The access function under test: reads a field that exists
          // only on the full document, never in the projection.
          read: ({ req }) =>
            (req.user as { activeOrganization?: unknown })?.activeOrganization !== undefined,
        },
      },
    ],
    plugins: [authLink(baseOptions)],
  })
  return getPayload({ config, key })
}

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('reqUser: document (issue #57)', () => {
  let payload: Payload
  beforeAll(async () => {
    payload = await boot('doc-shared')
  }, 120_000)

  it('cookie sessions see the full document with projected roles on top', async () => {
    const services = createServices(wireOptions(baseOptions), payload)
    const email = parseEmail('doc@test.dev')
    expect(email.isOk()).toBe(true)
    if (email.isErr()) {
      throw new Error('unreachable')
    }
    const role = parseRole('user')
    if (role.isErr()) {
      throw new Error('unreachable')
    }
    const created = await services.users.create({
      email: email.value,
      roles: [role.value],
    })
    expect(created.isOk()).toBe(true)
    if (!created.isOk()) {
      throw new Error('unreachable')
    }
    // The app writes a host-only field the projection never carries.
    await payload.update({
      collection: 'users',
      id: created.value.id,
      data: { activeOrganization: 'org-7' },
      overrideAccess: true,
    })
    const strategy = payload.config.collections
      .find((collection) => collection.slug === 'users')
      ?.auth?.strategies?.find((candidate) => candidate.name === 'auth-link')
    expect(strategy).toBeDefined()
    const headers = new Headers()
    const cookie = stub.issue({
      sessionId: 'doc-1',
      providerUserId: 'stub-1',
      email: 'doc@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    headers.set('cookie', cookie)
    // Payload's own strategy invocation passes the live request; the
    // document memo only needs a context bag here. A variable, not an
    // inline literal: Payload 3.83's strategy args do not declare `req`.
    const args = {
      headers,
      payload,
      req: { context: {} } as unknown as import('payload').PayloadRequest,
    }
    const result = (await strategy?.authenticate(args)) as {
      user?: Record<string, unknown>
    } | null
    expect(result?.user).not.toBeNull()
    // The document's own field is visible…
    expect(result?.user?.activeOrganization).toBe('org-7')
    // The document carries its (unset) host fields too.
    expect(result?.user?.department).toBeNull()
    // …and the projected fields stay authoritative.
    expect(result?.user?.roles).toEqual(['user'])
    expect(result?.user?.collection).toBe('users')
    expect(result?.user?._strategy).toBe('auth-link')
  })

  it('an anonymous session projects the guest marker onto the document (#126)', async () => {
    const services = createServices(wireOptions(baseOptions), payload)
    const email = parseEmail('guest@test.dev')
    if (email.isErr()) {
      throw new Error('unreachable')
    }
    const role = parseRole('user')
    if (role.isErr()) {
      throw new Error('unreachable')
    }
    const created = await services.users.create({
      email: email.value,
      roles: [role.value],
    })
    if (!created.isOk()) {
      throw new Error(created.error.message)
    }
    // Pre-linked with the document id as the provider user id, exactly
    // what `admitAnonymous` writes on a guest's first resolution.
    const linked = await services.users.linkIdentity(created.value.id, {
      providerId: stub.provider.id,
      providerUserId: String(created.value.id),
    })
    expect(linked.isOk()).toBe(true)
    const strategy = payload.config.collections
      .find((collection) => collection.slug === 'users')
      ?.auth?.strategies?.find((candidate) => candidate.name === 'auth-link')
    const headers = new Headers()
    headers.set(
      'cookie',
      stub.issue({
        sessionId: 'doc-guest',
        providerUserId: String(created.value.id),
        email: 'guest@test.dev',
        anonymous: true,
        expiresAt: new Date(Date.now() + 3_600_000),
      })
    )
    const args = {
      headers,
      payload,
      req: { context: {} } as unknown as import('payload').PayloadRequest,
    }
    const result = (await strategy?.authenticate(args)) as {
      user?: Record<string, unknown>
    } | null
    expect(result?.user).not.toBeNull()
    expect(result?.user?.anonymous).toBe(true)
    // The document's own roles govern — the create hook gave this one
    // the default; access functions distinguish guests by the marker.
    expect(result?.user?.roles).toEqual(['user'])
  })

  it("a session's active organization rides on the document shape (#110)", async () => {
    const strategy = payload.config.collections
      .find((collection) => collection.slug === 'users')
      ?.auth?.strategies?.find((candidate) => candidate.name === 'auth-link')
    const headers = new Headers()
    headers.set(
      'cookie',
      stub.issue({
        sessionId: 'doc-org',
        providerUserId: 'stub-1',
        email: 'doc@test.dev',
        expiresAt: new Date(Date.now() + 3_600_000),
        organizationId: 'org-active',
      })
    )
    const args = {
      headers,
      payload,
      req: { context: {} } as unknown as import('payload').PayloadRequest,
    }
    const result = (await strategy?.authenticate(args)) as {
      user?: Record<string, unknown>
    } | null
    // The provider-reported organization is projected on top of the
    // document; the host's own (stale) field is left as stored.
    expect(result?.user?.organizationId).toBe('org-active')
    expect(result?.user?.activeOrganization).toBe('org-7')
    expect(result?.user?.roles).toEqual(['user'])
  })

  it('local sessions are reshaped to the document through the request gate', async () => {
    const created = await payload.create({
      collection: 'users',
      data: {
        email: 'local@test.dev',
        password: 'Local-Passw0rd!',
        roles: ['user'],
        activeOrganization: 'org-9',
      },
      overrideAccess: true,
    })
    // A local JWT session: Payload's local strategy resolves the full
    // document; the gate reshapes it to the same shape the cookie
    // session carries (reqUser: 'document').
    const gate = (await import('../collections.js')).accountControlsGateHook(
      wireOptions(baseOptions)
    )
    const req = {
      context: {},
      payload,
      headers: new Headers(),
      i18n: undefined,
      user: await payload.findByID({
        collection: 'users',
        id: created.id,
        depth: 0,
        overrideAccess: true,
      }),
    } as unknown as Parameters<
      ReturnType<typeof import('../collections.js').accountControlsGateHook>
    >[0]['req']
    await gate({ req, operation: 'read' } as never)
    const shaped = req.user as Record<string, unknown>
    expect(shaped?.activeOrganization).toBe('org-9')
    expect(shaped?.roles).toEqual(['user'])
    expect(shaped?.collection).toBe('users')
  })

  it('the default stays the projection', () => {
    const options: AuthLinkPluginOptions = { ...baseOptions, reqUser: undefined }
    const wired = wireOptions(options)
    expect(wired.reqUser).toBe('projection')
  })
})
