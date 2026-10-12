import { InvalidEmailError, UserExistsError } from '@payload-auth-link/core'
import { WeakPasswordError } from '@payload-auth-link/provider-authjs'
import { describe, expect, it, vi } from 'vitest'
import { signupResponse } from './signup-response.js'

async function snapshot(response: Response): Promise<{ status: number; body: unknown }> {
  return { status: response.status, body: await response.json() }
}

describe('signupResponse (SEC-9)', () => {
  it('answers new and already-registered emails identically', async () => {
    const notifyExisting = vi.fn()
    const created = await snapshot(signupResponse(null, 'new@x.co', notifyExisting))
    const duplicate = await snapshot(
      signupResponse(new UserExistsError('old@x.co'), 'old@x.co', notifyExisting)
    )
    expect(duplicate).toEqual(created)
    expect(created).toEqual({ status: 200, body: { ok: true } })
    // The duplicate is reported out-of-band, never in the response.
    expect(notifyExisting).toHaveBeenCalledTimes(1)
    expect(notifyExisting).toHaveBeenCalledWith('old@x.co')
  })

  it('keeps existence-neutral input errors as 400 and storage failures generic', async () => {
    const weak = await snapshot(signupResponse(new WeakPasswordError(8), 'a@x.co', vi.fn()))
    expect(weak.status).toBe(400)
    const malformed = await snapshot(signupResponse(new InvalidEmailError('bad'), 'nope', vi.fn()))
    expect(malformed.status).toBe(400)
    const broken = await snapshot(signupResponse(new Error('db down'), 'a@x.co', vi.fn()))
    expect(broken).toEqual({ status: 500, body: { error: 'registration failed, try again later' } })
  })
})
