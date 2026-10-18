/**
 * Impersonation audit on the durable `onAudit` sink (CAP-8b, issue
 * #113): writes and reads an impersonated session causes OUTSIDE any
 * Payload collection operation are recorded, not only logged.
 *
 * - Verifying an impersonated session whose target has no users
 *   document yet links/provisions one; that write used to surface
 *   only as the `impersonated session used` log line.
 * - `GET /auth-link/organizations` stays allowed while impersonating
 *   but used to leave no audit record.
 *
 * Real engine: Payload on SQLite in memory, driven through
 * `handleEndpoints`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { AuditEvent } from '../options.js'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://impersonation-audit.test'
const SECRET = 'impersonation-audit-secret-32-chars'

const audited: AuditEvent[] = []
const stub = createStubProvider()
let config: SanitizedConfig
let payload: Payload
let operatorId = ''

function call(path: string, cookie: string): Promise<Response> {
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, { headers: { cookie } }),
  })
}

function session(providerUserId: string, email: string, actor?: string): string {
  return stub.issue({
    sessionId: `sess-${providerUserId}-${actor ?? 'self'}`,
    providerUserId,
    email,
    expiresAt: new Date(Date.now() + 3600_000),
    ...(actor === undefined ? {} : { actorProviderUserId: actor }),
  })
}

async function idOf(email: string): Promise<string | null> {
  const found = await payload.find({
    collection: 'users',
    where: { email: { equals: email } },
    overrideAccess: true,
    depth: 0,
  })
  const doc = found.docs[0]
  return doc === undefined ? null : String(doc.id)
}

function records(operation: string): AuditEvent[] {
  return audited.filter(
    (event) => event.message === 'impersonated operation' && event.fields.operation === operation
  )
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        organizations: { enabled: true },
        onAudit: (event) => {
          audited.push(event)
        },
      }),
    ],
  })
  payload = await getPayload({ config })
  // The operator signs in once, which links their own document.
  expect((await call('/auth-link/session', session('stub-operator', 'op@audit.test'))).status).toBe(
    200
  )
  operatorId = (await idOf('op@audit.test')) ?? ''
  expect(operatorId).not.toBe('')
}, 60_000)

beforeEach(() => {
  audited.length = 0
})

describe('impersonated verification that links the target (#113 item 9)', () => {
  it('records the provisioning write on onAudit, once', async () => {
    const cookie = session('stub-target', 'target@audit.test', 'stub-operator')
    expect(await idOf('target@audit.test')).toBeNull()
    expect((await call('/auth-link/session', cookie)).status).toBe(200)
    const targetId = await idOf('target@audit.test')
    expect(targetId).not.toBeNull()
    expect(records('linkIdentity')).toEqual([
      {
        message: 'impersonated operation',
        fields: {
          actorProviderUserId: 'stub-operator',
          actorKind: 'payload-user',
          actorUserId: operatorId,
          targetUserId: targetId,
          operation: 'linkIdentity',
          collection: 'users',
          id: targetId,
        },
      },
    ])
    // The target is linked now: the next impersonated request writes
    // nothing, so it records no link.
    audited.length = 0
    expect((await call('/auth-link/session', cookie)).status).toBe(200)
    expect(records('linkIdentity')).toEqual([])
  })

  it('a plain (not impersonated) first sign-in records nothing', async () => {
    expect(
      (await call('/auth-link/session', session('stub-plain', 'plain@audit.test'))).status
    ).toBe(200)
    expect(await idOf('plain@audit.test')).not.toBeNull()
    expect(audited.filter((event) => event.message === 'impersonated operation')).toEqual([])
  })
})

describe('GET /auth-link/organizations while impersonating (#113 item 10)', () => {
  it('stays allowed and is audited as a read', async () => {
    const cookie = session('stub-org-target', 'org-target@audit.test', 'stub-operator')
    expect((await call('/auth-link/session', cookie)).status).toBe(200)
    audited.length = 0
    const listed = await call('/auth-link/organizations', cookie)
    expect(listed.status).toBe(200)
    const targetId = await idOf('org-target@audit.test')
    expect(records('read')).toEqual([
      {
        message: 'impersonated operation',
        fields: {
          actorProviderUserId: 'stub-operator',
          actorKind: 'payload-user',
          actorUserId: operatorId,
          targetUserId: targetId,
          operation: 'read',
          endpoint: '/auth-link/organizations',
        },
      },
    ])
  })

  it('a plain list records nothing', async () => {
    const listed = await call('/auth-link/organizations', session('stub-operator', 'op@audit.test'))
    expect(listed.status).toBe(200)
    expect(audited.filter((event) => event.message === 'impersonated operation')).toEqual([])
  })
})
