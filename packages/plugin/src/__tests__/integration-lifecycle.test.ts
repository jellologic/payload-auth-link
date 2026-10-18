/**
 * CAP-14 lifecycle wiring (`lifecycle.ts`) and the issue #88
 * verified-email sync (`verified-email.ts`) on a real engine (Payload
 * on SQLite in memory), driven through a provider's
 * `onIdentityEvent` subscription exactly as the adapters emit.
 *
 * Pins the success path (a verified event for the address the linked
 * document already carries grants the bound proof and the host's
 * verified mirror) and every failure arm: application failure, the
 * linked-user lookup failing, a handler that throws (Error and
 * non-Error causes) — each logged, none thrown into the provider.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  createIdentityEventEmitter,
  defineProviderId,
  parseEmail,
  type Email,
  type IdentityEvent,
  type LogFields,
  type LoggerPort,
  type UserId,
} from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { authLink } from '../index.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { syncVerifiedEmail } from '../verified-email.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://lifecycle.test'
const SECRET = 'lifecycle-secret-32-characters!!'
const PROVIDER = defineProviderId('stub')

type LogCall = { readonly message: string; readonly fields: LogFields | undefined }
const infoCalls: LogCall[] = []
const errorCalls: LogCall[] = []
const logger: LoggerPort = {
  debug: () => undefined,
  info: (message, fields) => {
    infoCalls.push({ message, fields })
  },
  warn: () => undefined,
  error: (message, fields) => {
    errorCalls.push({ message, fields })
  },
  child: () => logger,
}

const stub = createStubProvider()
const emitter = createIdentityEventEmitter()
const options: AuthLinkPluginOptions = {
  baseUrl: ORIGIN,
  roles: ['admin', 'user'],
  defaultRole: 'user',
  providers: [{ ...stub.provider, onIdentityEvent: emitter.subscribe }],
  emailVerifiedField: 'emailVerified',
  logger,
}

let config: SanitizedConfig
let payload: Payload

function email(raw: string): Email {
  return parseEmail(raw)._unsafeUnwrap()
}

/** JIT-provision a linked user through the stub provider's session. */
async function provision(providerUserId: string, address: string): Promise<string | number> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, {
      headers: {
        origin: ORIGIN,
        cookie: stub.issue({
          sessionId: `sess-${providerUserId}`,
          providerUserId,
          email: address,
          expiresAt: new Date(Date.now() + 3_600_000),
        }),
      },
    }),
  })
  expect(response.status).toBe(200)
  const found = await payload.find({
    collection: 'users',
    where: { email: { equals: address } },
    overrideAccess: true,
    depth: 0,
  })
  const doc = found.docs[0]
  if (doc === undefined) {
    throw new Error('provisioned user not found')
  }
  return doc.id
}

async function rawDoc(id: string | number): Promise<Record<string, unknown>> {
  return payload.findByID({ collection: 'users', id, depth: 0, overrideAccess: true })
}

function verified(providerUserId: string, address: string): IdentityEvent {
  return { type: 'email-verified', providerId: PROVIDER, providerUserId, email: email(address) }
}

/** True for the repository's linked-identity lookup (`findByProviderIdentity`). */
function isIdentityLookup(args: unknown): boolean {
  return JSON.stringify(args).includes('identities.providerUserId')
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
        // The host's own verified mirror (payload-auth's layout).
        fields: [{ name: 'emailVerified', type: 'checkbox', defaultValue: false }],
      },
    ],
    plugins: [authLink(options)],
  })
  payload = await getPayload({ config })
}, 60_000)

afterEach(() => {
  vi.restoreAllMocks()
  infoCalls.length = 0
  errorCalls.length = 0
})

describe('identity events through the onInit subscription', () => {
  it('a verified event for the current address sets the mirror and the bound proof', async () => {
    const id = await provision('life-1', 'life-1@test.dev')
    // Withdraw the proof and the mirror: the post-import shape.
    await payload.update({
      collection: 'users',
      id,
      data: { linkable: false, linkableEmail: null, emailVerified: false },
      overrideAccess: true,
    })
    await emitter.emit(verified('life-1', 'life-1@test.dev'))
    const after = await rawDoc(id)
    expect(after.emailVerified).toBe(true)
    expect(after.linkable).toBe(true)
    expect(after.linkableEmail).toBe('life-1@test.dev')
    expect(
      infoCalls.some((call) => call.message === 'verified email synced onto the linked user')
    ).toBe(true)
    expect(errorCalls).toEqual([])
    // In step now: a repeat event writes nothing and logs no sync.
    infoCalls.length = 0
    const update = vi.spyOn(payload, 'update')
    await emitter.emit(verified('life-1', 'life-1@test.dev'))
    expect(update).not.toHaveBeenCalled()
    expect(
      infoCalls.some((call) => call.message === 'verified email synced onto the linked user')
    ).toBe(false)
  })

  it('a verified email change moves the address and proves it', async () => {
    const id = await provision('life-2', 'life-2@test.dev')
    await emitter.emit({
      type: 'email-changed',
      providerId: PROVIDER,
      providerUserId: 'life-2',
      email: email('life-2-moved@test.dev'),
      verified: true,
    })
    const after = await rawDoc(id)
    expect(after.email).toBe('life-2-moved@test.dev')
    expect(after.linkableEmail).toBe('life-2-moved@test.dev')
    expect(after.emailVerified).toBe(true)
  })

  it('an unverified change and a non-email event never touch the mirror', async () => {
    const id = await provision('life-3', 'life-3@test.dev')
    await payload.update({
      collection: 'users',
      id,
      data: { emailVerified: false },
      overrideAccess: true,
    })
    await emitter.emit({
      type: 'email-changed',
      providerId: PROVIDER,
      providerUserId: 'life-3',
      email: email('life-3-moved@test.dev'),
      verified: false,
    })
    await emitter.emit({
      type: 'identity-unlinked',
      providerId: PROVIDER,
      providerUserId: 'life-3',
    })
    const after = await rawDoc(id)
    expect(after.email).toBe('life-3@test.dev')
    expect(after.emailVerified).toBe(false)
    expect(after.identities).toEqual([])
  })

  it('an event for a provider user with no linked document is a no-op', async () => {
    const update = vi.spyOn(payload, 'update')
    await emitter.emit(verified('nobody', 'nobody@test.dev'))
    expect(update).not.toHaveBeenCalled()
    expect(errorCalls).toEqual([])
  })

  it('an application failure is logged, never thrown into the provider', async () => {
    await provision('life-4', 'life-4@test.dev')
    vi.spyOn(payload, 'find').mockRejectedValue(new Error('db down'))
    await expect(emitter.emit(verified('life-4', 'life-4@test.dev'))).resolves.toBeUndefined()
    const logged = errorCalls.find(
      (call) =>
        call.message === 'identity event application failed; read-time sync remains the backstop'
    )
    expect(logged?.fields).toMatchObject({
      type: 'email-verified',
      providerId: 'stub',
      providerUserId: 'life-4',
    })
  })

  it('a failed linked-user lookup after the application is logged and syncs nothing', async () => {
    const id = await provision('life-5', 'life-5@test.dev')
    await payload.update({
      collection: 'users',
      id,
      data: { emailVerified: false },
      overrideAccess: true,
    })
    // The applier's own lookup succeeds; the verified-email lookup
    // that follows it (the second identity lookup) fails.
    const real = payload.find.bind(payload)
    let lookups = 0
    vi.spyOn(payload, 'find').mockImplementation((args) => {
      if (isIdentityLookup(args)) {
        lookups += 1
        if (lookups === 2) {
          return Promise.reject(new Error('lookup failed'))
        }
      }
      return real(args)
    })
    await emitter.emit(verified('life-5', 'life-5@test.dev'))
    expect(lookups).toBe(2)
    const logged = errorCalls.find((call) => call.message === 'verified-email sync lookup failed')
    expect(logged?.fields).toMatchObject({ providerId: 'stub' })
    vi.restoreAllMocks()
    expect((await rawDoc(id)).emailVerified).toBe(false)
  })

  it('a handler that throws is caught and logged (Error and non-Error causes)', async () => {
    await provision('life-6', 'life-6@test.dev')
    vi.spyOn(payload, 'findByID').mockRejectedValueOnce(new Error('read exploded'))
    await expect(emitter.emit(verified('life-6', 'life-6@test.dev'))).resolves.toBeUndefined()
    expect(
      errorCalls.find((call) => call.message === 'identity event handler threw')?.fields
    ).toMatchObject({ type: 'email-verified', providerId: 'stub', error: 'read exploded' })
    errorCalls.length = 0
    vi.spyOn(payload, 'findByID').mockRejectedValueOnce('a bare string')
    await expect(emitter.emit(verified('life-6', 'life-6@test.dev'))).resolves.toBeUndefined()
    expect(
      errorCalls.find((call) => call.message === 'identity event handler threw')?.fields
    ).toMatchObject({ error: 'non-Error cause' })
  })
})

describe('syncVerifiedEmail', () => {
  it('an event for an address the document no longer carries proves nothing', async () => {
    const id = await provision('life-7', 'life-7@test.dev')
    await payload.update({
      collection: 'users',
      id,
      data: { emailVerified: false },
      overrideAccess: true,
    })
    const outcome = await syncVerifiedEmail(
      wireOptions(options),
      payload,
      id as unknown as UserId,
      email('someone-else@test.dev')
    )
    expect(outcome).toBe('unchanged')
    expect((await rawDoc(id)).emailVerified).toBe(false)
  })

  it('a non-record read is unchanged and writes nothing', async () => {
    const update = vi.fn()
    const fake = {
      findByID: () => Promise.resolve(null),
      update,
    } as unknown as Payload
    const outcome = await syncVerifiedEmail(
      wireOptions(options),
      fake,
      'x' as unknown as UserId,
      email('x@test.dev')
    )
    expect(outcome).toBe('unchanged')
    expect(update).not.toHaveBeenCalled()
  })

  it('without a mirror field only the proof is written', async () => {
    const id = await provision('life-8', 'life-8@test.dev')
    await payload.update({
      collection: 'users',
      id,
      data: { linkable: false, linkableEmail: null, emailVerified: false },
      overrideAccess: true,
    })
    const withoutMirror: AuthLinkPluginOptions = { ...options, emailVerifiedField: undefined }
    const outcome = await syncVerifiedEmail(
      wireOptions(withoutMirror),
      payload,
      id as unknown as UserId,
      email('life-8@test.dev')
    )
    expect(outcome).toBe('updated')
    const after = await rawDoc(id)
    expect(after.linkable).toBe(true)
    expect(after.emailVerified).toBe(false)
  })
})

describe('an unproven email change resets the verified mirror', () => {
  it('a self-service change clears emailVerified with the proof', async () => {
    const created = await payload.create({
      collection: 'users',
      data: {
        email: 'mirror-owner@test.dev',
        password: 'mirror-password-1',
        roles: ['user'],
        linkable: true,
        linkableEmail: 'mirror-owner@test.dev',
        emailVerified: true,
      },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      id: created.id,
      data: { email: 'mirror-moved@test.dev' },
      user: { ...created, collection: 'users' },
      overrideAccess: false,
    })
    const after = await rawDoc(created.id)
    expect(after.email).toBe('mirror-moved@test.dev')
    expect(after.linkable).toBe(false)
    // The mirror vouched for the OLD address; it must not vouch for
    // the new, unproven one.
    expect(after.emailVerified).toBe(false)
  })

  it("a role manager's change keeps the mirror (an operator decision)", async () => {
    const operator = await payload.create({
      collection: 'users',
      data: { email: 'mirror-operator@test.dev', password: 'mirror-password-2', roles: ['admin'] },
      overrideAccess: true,
    })
    const created = await payload.create({
      collection: 'users',
      data: {
        email: 'mirror-managed@test.dev',
        password: 'mirror-password-3',
        roles: ['user'],
        linkable: true,
        linkableEmail: 'mirror-managed@test.dev',
        emailVerified: true,
      },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      id: created.id,
      data: { email: 'mirror-managed-new@test.dev' },
      user: { ...operator, collection: 'users' },
      overrideAccess: false,
    })
    expect((await rawDoc(created.id)).emailVerified).toBe(true)
  })
})
