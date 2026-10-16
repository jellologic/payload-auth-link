/**
 * Fail-closed account controls and the provider-owned-credential
 * opt-out (GHSA-f4hj, issue #86):
 *
 * - an unreadable account status must REFUSE the request (503) at
 *   every enforcement point — the collection operation gate, the
 *   global operation gate, and the users access belt — never wave it
 *   through as "not suspended";
 * - `allowLocalCredentialsForLinkedDocs` is the documented escape
 *   hatch: with it, linked documents may sign in locally and run the
 *   forgot/reset flow; without it, both are refused (403).
 */
import { ProviderError, type LoggerPort } from '@payload-auth-link/core'
import { errAsync } from 'neverthrow'
import type { CollectionConfig, PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import {
  accountControlsGateHook,
  accountControlsGlobalGateHook,
  applyUsersCollection,
} from '../collections.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createAuthLinkStrategy } from '../strategy.js'
import { createStubProvider } from './stub-provider.js'

const errorSpy = vi.fn()

function spyLogger(): LoggerPort {
  const logger: LoggerPort = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: errorSpy,
    child: () => logger,
  }
  return logger
}

/** The HTTP status a hook/access call rejects with, or undefined when it passes. */
async function statusOfCall(call: () => unknown): Promise<number | undefined> {
  try {
    await call()
    return undefined
  } catch (error) {
    return (error as { status?: number }).status
  }
}

function wired(extra: Partial<AuthLinkPluginOptions> = {}) {
  return wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
    ...extra,
  })
}

/** A request whose account-status read fails (storage down). */
function failingRequest(
  findByID: ReturnType<typeof vi.fn<() => Promise<unknown>>> = vi.fn(() =>
    Promise.reject(new Error('db down'))
  )
) {
  const req = {
    user: { id: 'u1', collection: 'users', _strategy: 'local-jwt', roles: ['user'] },
    payload: { findByID },
    context: {},
  } as unknown as PayloadRequest
  return { req, findByID }
}

async function statusOf(promise: Promise<unknown>): Promise<number | undefined> {
  try {
    await promise
    return undefined
  } catch (error) {
    return (error as { status?: number }).status
  }
}

describe('account status read failure fails CLOSED (503)', () => {
  it('collection operation gate refuses, logs, and memoizes the failure per request', async () => {
    errorSpy.mockClear()
    const options = wired({ logger: spyLogger() })
    const hook = accountControlsGateHook(options)
    const { req, findByID } = failingRequest()
    const args = { req, operation: 'read', args: {}, collection: {}, context: {} }
    expect(await statusOfCall(() => hook(args as never))).toBe(503)
    expect(errorSpy).toHaveBeenCalledWith(
      'account status check failed; refusing the request',
      expect.objectContaining({ cause: expect.any(Error) as unknown })
    )
    // The memoized failure still refuses: a second gate on the same
    // request (another collection) does not re-read and pass.
    expect(await statusOfCall(() => hook(args as never))).toBe(503)
    expect(findByID).toHaveBeenCalledTimes(1)
  })

  it('global operation gate refuses', async () => {
    const hook = accountControlsGlobalGateHook(wired({ logger: spyLogger() }))
    const { req } = failingRequest()
    const args = { req, operation: 'findOne', args: {}, global: {}, context: {} }
    expect(await statusOfCall(() => hook(args as never))).toBe(503)
  })

  it('a suspended account is refused 401 by both gates', async () => {
    const options = wired({ logger: spyLogger() })
    const findByID = vi.fn(() =>
      Promise.resolve({ id: 'u1', suspendedUntil: new Date(Date.now() + 3_600_000).toISOString() })
    )
    const collectionGate = accountControlsGateHook(options)
    const globalGate = accountControlsGlobalGateHook(options)
    const first = failingRequest(findByID).req
    const second = failingRequest(findByID).req
    expect(await statusOfCall(() => collectionGate({ req: first } as never))).toBe(401)
    expect(await statusOfCall(() => globalGate({ req: second } as never))).toBe(401)
  })

  it('users access belt refuses with 503 for filled and default-filled access keys', async () => {
    const options = wired({ logger: spyLogger() })
    const [users] = applyUsersCollection([], options, createAuthLinkStrategy(options))
    const access = users?.access
    expect(access?.read).toBeTypeOf('function')
    expect(access?.update).toBeTypeOf('function')
    for (const key of ['read', 'update', 'delete', 'unlock'] as const) {
      const fn = access?.[key]
      if (fn === undefined) {
        throw new Error(`users.access.${key} missing`)
      }
      const { req } = failingRequest()
      expect(await statusOfCall(() => fn({ req } as never)), key).toBe(503)
    }
  })
})

function usersCollection(extra: Partial<AuthLinkPluginOptions> = {}): CollectionConfig {
  const options = wired({ logger: spyLogger(), ...extra })
  const [users] = applyUsersCollection([], options, createAuthLinkStrategy(options))
  if (users === undefined) {
    throw new Error('users collection missing')
  }
  return users
}

const linkedDoc = {
  id: 'linked-1',
  email: 'linked@test.dev',
  identities: [{ providerId: 'stub', providerUserId: 'p1' }],
}

async function runBeforeLogin(users: CollectionConfig): Promise<number | undefined> {
  const hooks = users.hooks?.beforeLogin ?? []
  expect(hooks.length).toBeGreaterThan(0)
  return statusOf(
    (async () => {
      for (const hook of hooks) {
        await hook({ user: linkedDoc, req: {} as PayloadRequest } as never)
      }
    })()
  )
}

async function runPasswordFlow(
  users: CollectionConfig,
  operation: 'forgotPassword' | 'resetPassword',
  target: Record<string, unknown> = linkedDoc
): Promise<{ status: number | undefined; find: ReturnType<typeof vi.fn> }> {
  const find = vi.fn(() => Promise.resolve({ docs: [target] }))
  const req = { payload: { find }, context: {} } as unknown as PayloadRequest
  const data =
    operation === 'forgotPassword' ? { email: 'linked@test.dev' } : { token: 'reset-token' }
  const status = await statusOf(
    (async () => {
      for (const hook of users.hooks?.beforeOperation ?? []) {
        await hook({ args: { data, req }, operation, req, collection: users } as never)
      }
    })()
  )
  return { status, find }
}

describe('allowLocalCredentialsForLinkedDocs (provider-owned credentials)', () => {
  it('default: linked docs are refused local sign-in and password issuance (403)', async () => {
    const users = usersCollection()
    expect(await runBeforeLogin(users)).toBe(403)
    const forgot = await runPasswordFlow(users, 'forgotPassword')
    expect(forgot.status).toBe(403)
    expect(forgot.find).toHaveBeenCalledTimes(1)
    const reset = await runPasswordFlow(users, 'resetPassword')
    expect(reset.status).toBe(403)
    expect(reset.find).toHaveBeenCalledWith(
      expect.objectContaining({ where: { resetPasswordToken: { equals: 'reset-token' } } })
    )
  })

  it('opt-out: linked docs may sign in locally and run forgot/reset', async () => {
    const users = usersCollection({ allowLocalCredentialsForLinkedDocs: true })
    expect(await runBeforeLogin(users)).toBeUndefined()
    const forgot = await runPasswordFlow(users, 'forgotPassword')
    expect(forgot.status).toBeUndefined()
    // The guard short-circuits before resolving the target document.
    expect(forgot.find).not.toHaveBeenCalled()
    const reset = await runPasswordFlow(users, 'resetPassword')
    expect(reset.status).toBeUndefined()
    // The reset still resolves its target: suspension is checked
    // before Payload writes the new password (issue #86).
    expect(reset.find).toHaveBeenCalledTimes(1)
  })

  it('resetPassword refuses a suspended document BEFORE the write, opt-out or not (401)', async () => {
    const suspendedPlain = {
      id: 'plain-1',
      email: 'plain@test.dev',
      identities: [],
      suspendedUntil: new Date(Date.now() + 60_000).toISOString(),
    }
    for (const users of [
      usersCollection(),
      usersCollection({ allowLocalCredentialsForLinkedDocs: true }),
    ]) {
      const reset = await runPasswordFlow(users, 'resetPassword', suspendedPlain)
      expect(reset.status).toBe(401)
      // forgot-password stays available to a suspended unlinked doc:
      // the token goes to the owner's inbox and the reset is gated.
      const forgot = await runPasswordFlow(users, 'forgotPassword', suspendedPlain)
      expect(forgot.status).toBeUndefined()
    }
  })

  it('opt-out still refuses a suspended linked doc (401)', async () => {
    const users = usersCollection({ allowLocalCredentialsForLinkedDocs: true })
    const suspended = { ...linkedDoc, suspendedUntil: new Date(Date.now() + 60_000).toISOString() }
    const status = await statusOf(
      (async () => {
        for (const hook of users.hooks?.beforeLogin ?? []) {
          await hook({ user: suspended, req: {} as PayloadRequest } as never)
        }
      })()
    )
    expect(status).toBe(401)
  })
})

describe("password issue guard: targets it cannot resolve keep Payload's response", () => {
  it('no token / unknown token pass through to Payload (enumeration-neutral)', async () => {
    const users = usersCollection()
    const find = vi.fn(() => Promise.resolve({ docs: [] }))
    const req = { payload: { find }, context: {} } as unknown as PayloadRequest
    for (const data of [{ token: '' }, { token: 'unknown-token' }, {}]) {
      const status = await statusOfCall(async () => {
        for (const hook of users.hooks?.beforeOperation ?? []) {
          await hook({
            args: { data, req },
            operation: 'resetPassword',
            req,
            collection: users,
          } as never)
        }
      })
      expect(status).toBeUndefined()
    }
    // Only the non-empty token was looked up.
    expect(find).toHaveBeenCalledTimes(1)
  })
})

describe('suspension revokes provider sessions best-effort (CAP-7)', () => {
  it('skips malformed/unknown identity rows and logs (never throws) a failed revoke', async () => {
    errorSpy.mockClear()
    const failing = createStubProvider({ id: 'failing' }).provider
    const revokeUserSessions = vi.fn(() =>
      errAsync(new ProviderError('failing', 'revokeUserSessions'))
    )
    const options = wired({
      logger: spyLogger(),
      providers: [{ ...failing, revokeUserSessions }],
    })
    const [users] = applyUsersCollection([], options, createAuthLinkStrategy(options))
    const doc = {
      id: 'u9',
      suspendedUntil: new Date(Date.now() + 3_600_000).toISOString(),
      identities: [
        'not-a-row',
        { providerId: 7, providerUserId: 'x' },
        { providerId: 'not-registered', providerUserId: 'x' },
        { providerId: 'failing', providerUserId: 'f-1' },
      ],
    }
    for (const hook of users?.hooks?.afterChange ?? []) {
      await hook({ doc, previousDoc: { id: 'u9', suspendedUntil: null } } as never)
    }
    expect(revokeUserSessions).toHaveBeenCalledTimes(1)
    expect(revokeUserSessions).toHaveBeenCalledWith('f-1')
    expect(errorSpy).toHaveBeenCalledWith(
      'suspend: provider session revoke failed',
      expect.objectContaining({ providerId: 'failing' })
    )
  })
})
