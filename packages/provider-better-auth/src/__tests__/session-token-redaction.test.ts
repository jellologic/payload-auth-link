import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  redactSessionTokens,
  reportSessionTokenExposure,
  resolveRevokeHandle,
  type RedactionHookContext,
} from '../session-token-redaction.js'

const minted = { session: { token: 'tok-new', id: 'sid' }, user: { id: 'u' } }

describe('redactSessionTokens (issue #113)', () => {
  it('leaves hand-off protocols and unknown paths alone', () => {
    const body = { session: { token: 'tok-new' }, token: 'tok-new' }
    expect(redactSessionTokens(undefined, body, minted)).toBeUndefined()
    expect(redactSessionTokens('/multi-session/set-active', body, minted)).toBeUndefined()
    expect(
      redactSessionTokens('/multi-session/list-device-sessions', [body], minted)
    ).toBeUndefined()
    expect(redactSessionTokens('/one-time-token/verify', body, minted)).toBeUndefined()
  })

  it('strips session.token from /get-session and nothing else', () => {
    expect(
      redactSessionTokens(
        '/get-session',
        { session: { id: 's', token: 't', expiresAt: 'x' }, user: { id: 'u' } },
        null
      )
    ).toEqual({ session: { id: 's', expiresAt: 'x' }, user: { id: 'u' } })
    expect(redactSessionTokens('/get-session', null, null)).toBeUndefined()
    expect(redactSessionTokens('/get-session', { session: { id: 's' } }, null)).toBeUndefined()
    expect(redactSessionTokens('/get-session', { session: 'odd' }, null)).toBeUndefined()
  })

  it('strips token from every /list-sessions entry', () => {
    expect(
      redactSessionTokens(
        '/list-sessions',
        [{ id: 'a', token: 'ta' }, { id: 'b', token: 'tb' }, 'odd'],
        null
      )
    ).toEqual([{ id: 'a' }, { id: 'b' }, 'odd'])
    expect(redactSessionTokens('/list-sessions', [{ id: 'a' }], null)).toBeUndefined()
    expect(redactSessionTokens('/list-sessions', { not: 'an array' }, null)).toBeUndefined()
  })

  it('strips only the token the response minted from other bodies', () => {
    expect(
      redactSessionTokens('/sign-in/email', { token: 'tok-new', user: { id: 'u' } }, minted)
    ).toEqual({ user: { id: 'u' } })
    expect(
      redactSessionTokens(
        '/passkey/verify-authentication',
        { session: { id: 'sid', token: 'tok-new' } },
        minted
      )
    ).toEqual({ session: { id: 'sid' } })
    expect(
      redactSessionTokens('/x', { token: 'tok-new', session: { token: 'tok-new' } }, minted)
    ).toEqual({ session: {} })
    // A value that only shares the key name (jwt `/token`, …) stays.
    expect(redactSessionTokens('/token', { token: 'a.jwt.value' }, minted)).toBeUndefined()
    expect(redactSessionTokens('/x', { session: { token: 'other' } }, minted)).toBeUndefined()
    // No minted session, nothing to compare against.
    expect(redactSessionTokens('/sign-in/email', { token: 'tok-new' }, null)).toBeUndefined()
    expect(
      redactSessionTokens('/sign-in/email', { token: 'tok-new' }, { session: { token: '' } })
    ).toBeUndefined()
    expect(redactSessionTokens('/sign-in/email', 'text', minted)).toBeUndefined()
  })
})

describe('resolveRevokeHandle (issue #113)', () => {
  function ctx(body: unknown, findOne?: (input: unknown) => Promise<unknown>) {
    return {
      body,
      context: findOne === undefined ? {} : { adapter: { findOne } },
    } as unknown as RedactionHookContext
  }

  it('resolves a session row id to its token', async () => {
    const findOne = vi.fn(() => Promise.resolve({ id: 'sid', token: 'tok' }))
    await expect(resolveRevokeHandle(ctx({ token: 'sid' }, findOne))).resolves.toEqual({
      context: { body: { token: 'tok' } },
    })
    expect(findOne).toHaveBeenCalledWith({
      model: 'session',
      where: [{ field: 'id', value: 'sid' }],
    })
  })

  it('passes anything else through unchanged', async () => {
    const none = () => Promise.resolve(null)
    await expect(resolveRevokeHandle(ctx({ token: 'raw-token' }, none))).resolves.toBeUndefined()
    await expect(
      resolveRevokeHandle(ctx({ token: 'sid' }, () => Promise.resolve({ token: '' })))
    ).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx({ token: '' }, none))).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx('body', none))).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx({ token: 'sid' }))).resolves.toBeUndefined()
  })
})

describe('reportSessionTokenExposure (issue #113)', () => {
  function logger(): { port: LoggerPort; warn: ReturnType<typeof vi.fn> } {
    const warn = vi.fn()
    return { port: { ...nullLogger(), warn }, warn }
  }

  it('warns for bearer() without requireSignature next to an exposing surface', () => {
    const exposed = logger()
    reportSessionTokenExposure([{ id: 'bearer' }], true, exposed.port)
    expect(exposed.warn).toHaveBeenCalledTimes(1)
    expect(exposed.warn).toHaveBeenCalledWith(
      expect.stringContaining('exposeSessionTokens: true'),
      expect.objectContaining({ setting: 'bearer' })
    )
    const multi = logger()
    reportSessionTokenExposure(
      [{ id: 'bearer', options: { requireSignature: false } }, { id: 'multi-session' }],
      true,
      multi.port
    )
    expect(multi.warn).toHaveBeenCalledTimes(2)
    expect(multi.warn).toHaveBeenCalledWith(
      expect.stringContaining('list-device-sessions'),
      expect.anything()
    )
  })

  it('stays quiet without bearer(), with requireSignature, or with nothing exposed', () => {
    const quiet = logger()
    reportSessionTokenExposure([{ id: 'multi-session' }], true, quiet.port)
    reportSessionTokenExposure(
      [{ id: 'bearer', options: { requireSignature: true } }, { id: 'multi-session' }],
      true,
      quiet.port
    )
    reportSessionTokenExposure([{ id: 'bearer' }], false, quiet.port)
    expect(quiet.warn).not.toHaveBeenCalled()
  })
})
