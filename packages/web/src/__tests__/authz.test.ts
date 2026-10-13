import {
  ForbiddenError,
  InvalidConfigError,
  InvalidRoleError,
  MfaRequiredError,
  SessionInvalidError,
  type SessionUser,
} from '@payload-auth-link/core'
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

describe('requireRoles MFA (CAP-6)', () => {
  const mfaAdmin: SessionUser = {
    ...admin,
    assurance: { methods: ['password'], mfa: true },
  }
  const withheldAdmin: SessionUser = {
    ...member,
    assurance: { methods: 'unknown', mfa: 'unknown' },
    mfaRequired: true,
  }

  it('throws MfaRequiredError when requireMfa is set and proof is missing or unknown', async () => {
    await expect(
      requireRoles(new Headers(), stubVerify(admin), { roles: ['admin'], requireMfa: true })
    ).rejects.toBeInstanceOf(MfaRequiredError)
    await expect(
      requireRoles(new Headers(), stubVerify(mfaAdmin), { roles: ['admin'], requireMfa: true })
    ).resolves.toBe(mfaAdmin)
    await expect(
      requireRoles(new Headers(), stubVerify(admin), { roles: ['admin'] })
    ).resolves.toBe(admin)
  })

  it('surfaces withheld roles as a step-up error, not a flat forbidden', async () => {
    const onMfaRequired = vi.fn((): never => {
      throw new Error('step-up')
    })
    await expect(
      requireRoles(new Headers(), stubVerify(withheldAdmin), {
        roles: ['admin'],
        onMfaRequired,
      })
    ).rejects.toThrow('step-up')
    expect(onMfaRequired).toHaveBeenCalledWith(withheldAdmin)
  })
})

describe('requireRoles role validation (TYP-10)', () => {
  it('throws InvalidRoleError on a typo-cased role before reading the session', async () => {
    const verify = stubVerify(admin)
    await expect(requireRoles(new Headers(), verify, { roles: ['Admin'] })).rejects.toBeInstanceOf(
      InvalidRoleError
    )
    expect(verify).not.toHaveBeenCalled()
  })

  it('throws InvalidConfigError on an empty role list', async () => {
    await expect(
      requireRoles(new Headers(), stubVerify(admin), { roles: [] })
    ).rejects.toBeInstanceOf(InvalidConfigError)
  })
})
