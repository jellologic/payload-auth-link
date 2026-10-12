import { ForbiddenError, SessionInvalidError, type SessionUser } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import { requireRoles, requireSessionUser } from '../authz.js'
import type { SessionVerifier } from '../verify.js'

const admin: SessionUser = {
  id: 'user-1',
  collection: 'users',
  email: 'admin@example.com',
  roles: ['admin', 'user'],
}
const member: SessionUser = {
  id: 'user-2',
  collection: 'users',
  email: 'member@example.com',
  roles: ['user'],
}

function stubVerify(user: SessionUser | null): SessionVerifier {
  return vi.fn((): Promise<SessionUser | null> => Promise.resolve(user))
}

describe('requireSessionUser', () => {
  it('returns the verified user', async () => {
    await expect(requireSessionUser(new Headers(), stubVerify(member))).resolves.toBe(member)
  })

  it('throws SessionInvalidError for anonymous callers by default', async () => {
    await expect(requireSessionUser(new Headers(), stubVerify(null))).rejects.toBeInstanceOf(
      SessionInvalidError
    )
  })

  it('delegates to onAnonymous (e.g. redirect) instead of throwing', async () => {
    const onAnonymous = vi.fn((): never => {
      throw new Error('redirected')
    })
    await expect(requireSessionUser(new Headers(), stubVerify(null), onAnonymous)).rejects.toThrow(
      'redirected'
    )
    expect(onAnonymous).toHaveBeenCalledTimes(1)
  })
})

describe('requireRoles', () => {
  it('returns the user when every role is held', async () => {
    await expect(
      requireRoles(new Headers(), stubVerify(admin), { roles: ['admin', 'user'] })
    ).resolves.toBe(admin)
  })

  it('throws ForbiddenError naming the missing roles', async () => {
    const failure = await requireRoles(new Headers(), stubVerify(member), {
      roles: ['admin'],
    }).then(
      () => null,
      (error: unknown) => error
    )
    expect(failure).toBeInstanceOf(ForbiddenError)
    expect((failure as ForbiddenError).message).toContain('admin')
  })

  it('treats anonymous callers as authentication failures, not denials', async () => {
    await expect(
      requireRoles(new Headers(), stubVerify(null), { roles: ['admin'] })
    ).rejects.toBeInstanceOf(SessionInvalidError)
  })

  it('delegates denials to onDenied with the user', async () => {
    const onDenied = vi.fn((): never => {
      throw new Error('not-found')
    })
    await expect(
      requireRoles(new Headers(), stubVerify(member), { roles: ['admin'], onDenied })
    ).rejects.toThrow('not-found')
    expect(onDenied).toHaveBeenCalledWith(member)
  })
})
