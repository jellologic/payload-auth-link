/**
 * Pins the durable audit-sink recipe in `docs/audit.md`: the code
 * between the RECIPE markers is copied into the guide verbatim (the
 * guide adds the same imports from the published packages), so a
 * change to `AuditSink`, `LoggerPort`, or the event shapes breaks
 * this file before it can silently break the documented example.
 *
 * Also proves the delivery semantics the guide states: events reach
 * the sink synchronously, inside the audited operation, and a sink
 * that throws fails that operation.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { isRecord, nullLogger, type LoggerPort } from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type CollectionConfig,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { authLink, type AuthLinkPluginOptions } from '../index.js'
import { createStubProvider } from './stub-provider.js'

// RECIPE START
type AuditSink = NonNullable<AuthLinkPluginOptions['onAudit']>
type AuditEvent = Parameters<AuditSink>[0]

const hasRole = (user: unknown, role: string): boolean =>
  isRecord(user) && Array.isArray(user.roles) && user.roles.includes(role)

/** Append-only audit trail: rows are written only through `overrideAccess`. */
export const auditLogCollection: CollectionConfig = {
  slug: 'audit-log',
  admin: {
    useAsTitle: 'message',
    defaultColumns: ['message', 'operation', 'actorUserId', 'targetUserId', 'createdAt'],
  },
  access: {
    read: ({ req }) => hasRole(req.user, 'admin'),
    create: () => false,
    update: () => false,
    delete: () => false,
  },
  fields: [
    { name: 'message', type: 'text', required: true, index: true },
    { name: 'operation', type: 'text', index: true },
    { name: 'actorUserId', type: 'text', index: true },
    { name: 'targetUserId', type: 'text', index: true },
    { name: 'fields', type: 'json', required: true },
  ],
}

/**
 * `onAudit` is called synchronously and its return value is ignored,
 * so the write is started here and never awaited by the plugin.
 * Every failure is routed to `onError` (never an unhandled rejection).
 */
export function createPayloadAuditSink(options: {
  readonly payload: () => Promise<Payload>
  readonly onError: (cause: unknown, event: AuditEvent) => void
}): AuditSink {
  return (event) => {
    const text = (key: string): string | undefined => {
      const value = event.fields[key]
      return typeof value === 'string' ? value : undefined
    }
    void options
      .payload()
      .then((payload) =>
        payload.create({
          collection: 'audit-log',
          // No `req`: the row is written outside the audited operation's
          // transaction (a denied or rolled-back attempt stays recorded),
          // and the audit hook on this collection sees no impersonated
          // user, so writing an audit row never audits itself.
          overrideAccess: true,
          data: {
            message: event.message,
            operation: text('operation'),
            actorUserId: text('actorUserId'),
            targetUserId: text('targetUserId') ?? text('userId'),
            fields: { ...event.fields },
          },
        })
      )
      .catch((cause: unknown) => {
        options.onError(cause, event)
      })
  }
}

/**
 * Optional: forward selected logger-only events (see the table in
 * docs/audit.md) to the same sink. Message text is diagnostics, not
 * contract, so pin the set in a test of your own.
 */
export function withDurableMessages(
  logger: LoggerPort,
  sink: AuditSink,
  messages: ReadonlySet<string>
): LoggerPort {
  const forward = (message: string, fields: AuditEvent['fields'] | undefined): void => {
    if (messages.has(message)) {
      sink({ message, fields: fields ?? {} })
    }
  }
  const wrapped: LoggerPort = {
    ...logger,
    info: (message, fields) => {
      logger.info(message, fields)
      forward(message, fields)
    },
    warn: (message, fields) => {
      logger.warn(message, fields)
      forward(message, fields)
    },
    child: () => wrapped,
  }
  return wrapped
}
// RECIPE END

const ORIGIN = 'http://audit-recipe.test'
const SECRET = 'audit-recipe-secret-32-chars-min!'

let config: SanitizedConfig
let payload: Payload
let operatorId: string | number
let targetId: string | number
const sinkErrors: unknown[] = []
const stub = createStubProvider()
let resolvePayload: (value: Payload) => void = () => undefined
const payloadReady = new Promise<Payload>((resolve) => {
  resolvePayload = resolve
})
const recipeSink = createPayloadAuditSink({
  payload: () => payloadReady,
  onError: (cause) => {
    sinkErrors.push(cause)
  },
})
// Indirection so one test can swap in a throwing sink.
let activeSink: AuditSink = recipeSink

async function seedUser(email: string, providerUserId: string, roles: string[]) {
  const created = await payload.create({
    collection: 'users',
    data: {
      email,
      password: 'correct-horse-battery',
      roles,
      identities: [
        { providerId: 'stub', providerUserId, email, linkedAt: new Date().toISOString() },
      ],
    },
  })
  return created.id
}

const targetUser = () => ({
  id: String(targetId),
  collection: 'users',
  email: 'target@test.dev',
  roles: ['user'],
  actor: { kind: 'payload-user', providerUserId: 'stub-operator', userId: String(operatorId) },
})

async function auditRows(message: string) {
  const found = await payload.find({
    collection: 'audit-log',
    where: { message: { equals: message } },
    overrideAccess: true,
    limit: 100,
  })
  return found.docs
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      { slug: 'users', auth: true, fields: [] },
      { slug: 'posts', fields: [{ name: 'title', type: 'text' }] },
      auditLogCollection,
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        onAudit: (event) => {
          activeSink(event)
        },
        logger: withDurableMessages(
          nullLogger(),
          recipeSink,
          new Set(['impersonated session used'])
        ),
      }),
    ],
  })
  payload = await getPayload({ config })
  resolvePayload(payload)
  operatorId = await seedUser('operator@test.dev', 'stub-operator', ['admin'])
  targetId = await seedUser('target@test.dev', 'stub-target', ['user'])
  await payload.create({ collection: 'posts', data: { title: 'hello' } })
}, 60_000)

describe('documented durable audit sink (docs/audit.md)', () => {
  it('persists every impersonated operation as an id-only row', async () => {
    await payload.find({ collection: 'posts', user: targetUser(), overrideAccess: false })
    await vi.waitFor(async () => {
      const rows = await auditRows('impersonated operation')
      expect(rows.some((row) => row.operation === 'read')).toBe(true)
    })
    const [row] = (await auditRows('impersonated operation')).filter(
      (entry) => entry.operation === 'read'
    )
    expect(row).toMatchObject({
      actorUserId: String(operatorId),
      targetUserId: String(targetId),
      fields: {
        actorKind: 'payload-user',
        actorProviderUserId: 'stub-operator',
        collection: 'posts',
        operation: 'read',
      },
    })
    expect(JSON.stringify(row?.fields)).not.toContain('@test.dev')
    expect(sinkErrors).toEqual([])
  })

  it('persists a forwarded logger-only event through the same sink', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-recipe-impersonated',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-operator',
    })
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(response.status).toBe(200)
    await vi.waitFor(async () => {
      expect(await auditRows('impersonated session used')).toHaveLength(1)
    })
  })

  it('keeps the trail append-only and admin-readable only', async () => {
    const plain = { id: String(targetId), collection: 'users', email: 'x@y.z', roles: ['user'] }
    const admin = { id: String(operatorId), collection: 'users', email: 'a@y.z', roles: ['admin'] }
    await expect(
      payload.create({
        collection: 'audit-log',
        data: { message: 'forged', fields: {} },
        user: admin,
        overrideAccess: false,
      })
    ).rejects.toThrow()
    await expect(
      payload.find({ collection: 'audit-log', user: plain, overrideAccess: false })
    ).rejects.toThrow()
    const visible = await payload.find({
      collection: 'audit-log',
      user: admin,
      overrideAccess: false,
    })
    expect(visible.totalDocs).toBeGreaterThan(0)
  })

  it('routes a failed write to onError instead of throwing', async () => {
    const errors: unknown[] = []
    const failing = createPayloadAuditSink({
      payload: () => Promise.reject(new Error('db down')),
      onError: (cause) => {
        errors.push(cause)
      },
    })
    expect(() => failing({ message: 'impersonated operation', fields: {} })).not.toThrow()
    await vi.waitFor(() => {
      expect(errors).toHaveLength(1)
    })
  })

  it('fails the audited operation when a sink throws synchronously', async () => {
    activeSink = () => {
      throw new Error('sink refused')
    }
    try {
      await expect(
        payload.find({ collection: 'posts', user: targetUser(), overrideAccess: false })
      ).rejects.toThrow('sink refused')
    } finally {
      activeSink = recipeSink
    }
  })
})
