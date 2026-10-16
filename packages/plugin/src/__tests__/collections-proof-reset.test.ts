/**
 * Users-collection defaults that guard JIT linking and the lockout:
 *
 * - an email change outside the provider resync or a role manager's
 *   write resets the linking proof (and `_verified` on verify hosts);
 * - `unlock` defaults to role managers, never while impersonating,
 *   and a host's own `access.unlock` is kept.
 */
import { nullLogger } from '@payload-auth-link/core'
import type { CollectionConfig, PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { applyUsersCollection } from '../collections.js'
import { wireOptions } from '../options.js'
import { createAuthLinkStrategy } from '../strategy.js'
import { createStubProvider } from './stub-provider.js'

function users(existing: CollectionConfig[] = []): CollectionConfig {
  const options = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
    logger: nullLogger(),
  })
  const [collection] = applyUsersCollection(existing, options, createAuthLinkStrategy(options))
  if (collection === undefined) {
    throw new Error('users collection missing')
  }
  return collection
}

function request(user: unknown): PayloadRequest {
  return {
    user,
    context: {},
    payload: { findByID: vi.fn(() => Promise.resolve({ id: 'u1' })) },
  } as unknown as PayloadRequest
}

const plain = { id: 'u1', collection: 'users', roles: ['user'] }
const manager = { id: 'm1', collection: 'users', roles: ['admin'] }

async function runBeforeChange(
  collection: CollectionConfig,
  data: Record<string, unknown>,
  user: unknown,
  originalDoc: unknown = { id: 'u1', email: 'old@test.dev', linkable: true }
): Promise<Record<string, unknown>> {
  for (const hook of collection.hooks?.beforeChange ?? []) {
    await hook({
      collection,
      operation: 'update',
      data,
      originalDoc,
      req: request(user),
      context: {},
    } as never)
  }
  return data
}

describe('email change resets the linking proof', () => {
  it('clears linkable, linkableEmail and _verified on a verify host', async () => {
    const collection = { ...users([{ slug: 'users', auth: { verify: true }, fields: [] }]) }
    const data = await runBeforeChange(collection, { email: 'victim@test.dev' }, plain)
    expect(data).toMatchObject({ linkable: false, linkableEmail: null, _verified: false })
  })

  it('leaves _verified alone when the host does not verify', async () => {
    const data = await runBeforeChange(users(), { email: 'victim@test.dev' }, plain, {
      email: 'old@test.dev',
    })
    expect(data).toMatchObject({ linkable: false, linkableEmail: null })
    expect(data).not.toHaveProperty('_verified')
  })

  it('keeps the proof for a role manager, a same-write re-grant, or a case-only change', async () => {
    const collection = users()
    expect(await runBeforeChange(collection, { email: 'new@test.dev' }, manager)).toEqual({
      email: 'new@test.dev',
    })
    const regrant = { email: 'new@test.dev', linkable: true, linkableEmail: 'NEW@test.dev' }
    expect(await runBeforeChange(collection, { ...regrant }, plain)).toEqual(regrant)
    expect(await runBeforeChange(collection, { email: 'OLD@test.dev' }, plain)).toEqual({
      email: 'OLD@test.dev',
    })
    expect(await runBeforeChange(collection, { name: 'x' }, plain, null)).toEqual({ name: 'x' })
  })
})

describe('unlock access default', () => {
  const impersonated = {
    ...manager,
    actor: { kind: 'provider-only', providerUserId: 'op-1' },
  }

  it('admits role managers only, and never while impersonating', async () => {
    const unlock = users().access?.unlock
    if (unlock === undefined) {
      throw new Error('unlock access missing')
    }
    expect(await unlock({ req: request(manager) } as never)).toBe(true)
    expect(await unlock({ req: request(plain) } as never)).toBe(false)
    expect(await unlock({ req: request(impersonated) } as never)).toBe(false)
  })

  it("keeps the host's own unlock access", async () => {
    const own = vi.fn(() => true)
    const unlock = users([{ slug: 'users', auth: true, fields: [], access: { unlock: own } }])
      .access?.unlock
    expect(await unlock?.({ req: request(plain) } as never)).toBe(true)
    expect(own).toHaveBeenCalled()
  })
})

describe('emailVerifiedField validation', () => {
  function apply(existing: CollectionConfig[]): CollectionConfig[] {
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [createStubProvider().provider],
      logger: nullLogger(),
      emailVerifiedField: 'emailVerified',
    })
    return applyUsersCollection(existing, options, createAuthLinkStrategy(options))
  }

  it('refuses a mirror the users collection does not declare as a checkbox', () => {
    expect(() => apply([])).toThrow(/emailVerifiedField 'emailVerified'/)
    expect(() =>
      apply([{ slug: 'users', auth: true, fields: [{ name: 'emailVerified', type: 'text' }] }])
    ).toThrow(/must name a checkbox field/)
  })

  it('accepts a declared checkbox', () => {
    const [collection] = apply([
      { slug: 'users', auth: true, fields: [{ name: 'emailVerified', type: 'checkbox' }] },
    ])
    expect(collection?.slug).toBe('users')
  })
})
