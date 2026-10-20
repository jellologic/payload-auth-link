/**
 * Scoped plugin writes (issue #144), on a real engine (Payload on
 * SQLite in memory) with a host users collection that carries a
 * REQUIRED host field (`name`).
 *
 * The chain this file pins (each step fails without its fix):
 * 1. A legacy row whose `name` is '' (the field became required after
 *    the row was created) fails Payload's full-document update
 *    validation — the update operation merges the stored document
 *    into the incoming data and validates every field — so ANY Local
 *    API update of that document is refused, and with the old
 *    full-document write the identity link (and the sign-in) failed
 *    with it. The link now goes through the database adapter and
 *    writes ONLY the plugin-owned fields: the user signs in, and the
 *    invalid host field is left exactly as it was.
 * 2. The identities child rows land intact: the adapter runs no field
 *    hooks, so the write mints the row ids Payload's `baseIDField`
 *    hook would have minted (the SQL child table's `id` is a NOT NULL
 *    PRIMARY KEY with no default — without the minted ids the insert
 *    fails).
 * 3. The scoped write runs no hooks: a host `beforeChange` hook sees
 *    nothing for the link. The provider-email resync still runs
 *    through the Local API (it relies on the proof-reset hook) and
 *    carries the `authLinkWriteMarker` for hosts that skip.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  authLinkWriteMarker,
  isRecord,
  type LogFields,
  type LoggerPort,
} from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type CollectionBeforeChangeHook,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://scoped-linking.test'
const SECRET = 'scoped-linking-secret-32-chars'

type LogCall = { readonly message: string; readonly fields: LogFields | undefined }
const warnCalls: LogCall[] = []
const errorCalls: LogCall[] = []
const capturingLogger: LoggerPort = {
  debug: () => undefined,
  info: () => undefined,
  warn: (message, fields) => {
    warnCalls.push({ message, fields })
  },
  error: (message, fields) => {
    errorCalls.push({ message, fields })
  },
  child: () => capturingLogger,
}

/**
 * The `authLinkWriteMarker` value (or absence) every users-collection
 * `beforeChange` hook saw, in order. The scoped adapter writes run no
 * hooks at all; the Local API writes carry the marker.
 */
const changeMarkerContexts: Array<unknown> = []
const recordChangeMarker: CollectionBeforeChangeHook = ({ req }) => {
  changeMarkerContexts.push(
    isRecord(req.context) ? (req.context[authLinkWriteMarker] ?? null) : null
  )
}

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

type Reply = { status: number; body: unknown }

async function rest(
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown } = {}
): Promise<Reply> {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    'x-auth-link-csrf': '1',
  }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body }
}

async function rawDoc(id: string | number): Promise<Record<string, unknown>> {
  const doc = await payload.findByID({
    collection: 'users',
    id,
    depth: 0,
    overrideAccess: true,
    showHiddenFields: true,
  })
  return doc
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
      {
        slug: 'users',
        auth: true,
        fields: [
          {
            name: 'name',
            type: 'text',
            required: true,
            admin: { description: 'Host-required display name.' },
          },
        ],
        hooks: { beforeChange: [recordChangeMarker] },
      },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        logger: capturingLogger,
      }),
    ],
  })
  payload = await getPayload({ config })
}, 60_000)

describe('a legacy row failing an unrelated required field still receives its identity link', () => {
  const owner = 'legacy@scoped.test'
  const password = 'legacy-password-1'
  let ownerId: string | number = ''

  it('setup: a proven user is created, then its name is wiped below the requirement', async () => {
    const created = await payload.create({
      collection: 'users',
      data: {
        email: owner,
        password,
        name: 'Original Name',
        roles: ['user'],
        linkable: true,
        linkableEmail: owner,
      },
      overrideAccess: true,
    })
    ownerId = created.id
    // The legacy row: created BEFORE the host made `name` required,
    // holding '' where the schema now demands a value.
    await payload.db.updateOne({
      collection: 'users',
      id: ownerId,
      data: { name: '' },
      returning: false,
    })
    expect(await rawDoc(ownerId).then((doc) => doc.name)).toBe('')
  })

  it('premise: a full-document Local API update is refused on the unrelated field', async () => {
    // What the OLD linkIdentity write hit: the update operation merges
    // the stored document into the incoming data and validates every
    // field, so even a write that never mentions `name` fails on it.
    await expect(
      payload.update({
        collection: 'users',
        id: ownerId,
        data: { roles: ['user'] },
        overrideAccess: true,
      })
    ).rejects.toMatchObject({
      name: 'ValidationError',
      data: { errors: [expect.objectContaining({ path: 'name' })] },
    })
  })

  it('the provider sign-in links the identity anyway, and the host field stays untouched', async () => {
    const before = await rawDoc(ownerId)
    const linked = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-legacy',
        providerUserId: 'stub-legacy',
        email: owner,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(linked.status).toBe(200)
    const after = await rawDoc(ownerId)
    expect(after.identities).toEqual([
      expect.objectContaining({
        providerId: 'stub',
        providerUserId: 'stub-legacy',
        email: owner,
      }),
    ])
    // The scoped write minted the row id Payload's `baseIDField` hook
    // would have minted (see the module doc).
    const row = (after.identities as Array<Record<string, unknown>>)[0]
    expect(typeof row?.id).toBe('string')
    expect(row?.id).not.toBe('')
    // The unrelated field was written by NOTHING: still the legacy ''.
    expect(after.name).toBe('')
    // The scoped write stamps no timestamp either (the adapter writes
    // only the given fields).
    expect(after.updatedAt).toBe(before.updatedAt)
    // The only warning is the best-effort password probe (the document
    // holds a local password) — the link itself is clean.
    expect(
      warnCalls.some(
        (call) =>
          call.message !==
          'identity linked to a document that also holds a local password; ensure both credential owners are the same person'
      )
    ).toBe(false)
    expect(errorCalls).toEqual([])
  })
})

describe('the write marker rides the Local API resync, never the scoped link', () => {
  const owner = 'resync@scoped.test'
  const password = 'resync-password-1'
  let ownerId: string | number = ''

  beforeAll(async () => {
    const created = await payload.create({
      collection: 'users',
      data: {
        email: owner,
        password,
        name: 'Resync User',
        roles: ['user'],
        linkable: true,
        linkableEmail: owner,
      },
      overrideAccess: true,
    })
    ownerId = created.id
  })

  it('the scoped link write runs no host hook (there is nothing to skip)', async () => {
    changeMarkerContexts.length = 0
    const linked = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-resync-1',
        providerUserId: 'stub-resync',
        email: owner,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(linked.status).toBe(200)
    expect((await rawDoc(ownerId)).identities).toEqual([
      expect.objectContaining({ providerUserId: 'stub-resync' }),
    ])
    expect(changeMarkerContexts).toEqual([])
  })

  it('the provider-email resync carries the marker on its Local API write', async () => {
    changeMarkerContexts.length = 0
    const resynced = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-resync-2',
        providerUserId: 'stub-resync',
        email: 'moved@scoped.test',
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(resynced.status).toBe(200)
    const after = await rawDoc(ownerId)
    expect(after.email).toBe('moved@scoped.test')
    // The proof moved with the resync (GHSA-8524) — the hook the Local
    // API path keeps running is what makes that safe.
    expect(after.linkableEmail).toBe('moved@scoped.test')
    expect(changeMarkerContexts).toEqual([{ op: 'resync-email' }])
  })
})
