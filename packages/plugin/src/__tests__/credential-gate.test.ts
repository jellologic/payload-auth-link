/**
 * Unit edges of the authentication-time credential gate
 * (GHSA-mjvh, `credential-gate.ts`): which presented credential arms
 * it, and which read its hook vetoes. The real-engine walk is
 * `integration-local-credential-gate.test.ts`.
 */
import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import type { Payload, PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import {
  armLocalCredentialGate,
  banActive,
  disarmLocalCredentialGate,
  holdsLinkedIdentities,
  LOCAL_CREDENTIAL_GATE_KEY,
  localCredentialGateHook,
  localCredentialRefusal,
  suspensionActive,
} from '../credential-gate.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function wired(overrides: Partial<AuthLinkPluginOptions> = {}) {
  return wireOptions({
    baseUrl: 'http://gate.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
    logger: nullLogger(),
    ...overrides,
  })
}

function payloadWith(
  auth: unknown,
  jwtOrder: readonly string[] = ['JWT', 'Bearer', 'cookie']
): Payload {
  return {
    collections: auth === undefined ? {} : { users: { config: { auth } } },
    config: { auth: { jwtOrder }, cookiePrefix: 'payload' },
  } as unknown as Payload
}

function request(): PayloadRequest {
  return { context: {} } as unknown as PayloadRequest
}

function marker(req: PayloadRequest): unknown {
  return (req.context as Record<string, unknown>)[LOCAL_CREDENTIAL_GATE_KEY]
}

function base64url(value: string): string {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function jwtFor(claims: unknown): string {
  return `${base64url('{"alg":"HS256"}')}.${base64url(JSON.stringify(claims))}.sig`
}

const usersJwt = jwtFor({ id: 7, collection: 'users' })
const localAuth = { useAPIKey: true }

describe('armLocalCredentialGate', () => {
  it('reads the JWT channels in the configured order (Bearer, JWT, cookie)', () => {
    const options = wired()
    const bearer = request()
    armLocalCredentialGate(
      new Headers({ authorization: `Bearer ${usersJwt}` }),
      payloadWith(localAuth, ['Bearer']),
      bearer,
      options
    )
    expect(marker(bearer)).toEqual({ jwtUserId: '7', apiKey: false })
    const header = request()
    armLocalCredentialGate(
      new Headers({ authorization: `JWT ${usersJwt}` }),
      payloadWith(localAuth),
      header,
      options
    )
    expect(marker(header)).toEqual({ jwtUserId: '7', apiKey: false })
    const cookie = request()
    armLocalCredentialGate(
      new Headers({ cookie: `other=1; payload-token=${usersJwt}` }),
      payloadWith(localAuth),
      cookie,
      options
    )
    expect(marker(cookie)).toEqual({ jwtUserId: '7', apiKey: false })
  })

  it('arms for a users API key only when the collection uses API keys', () => {
    const options = wired()
    const headers = new Headers({ authorization: 'users API-Key secret' })
    const keyed = request()
    armLocalCredentialGate(headers, payloadWith(localAuth), keyed, options)
    expect(marker(keyed)).toEqual({ jwtUserId: null, apiKey: true })
    const keyless = request()
    armLocalCredentialGate(headers, payloadWith({}), keyless, options)
    expect(marker(keyless)).toBeUndefined()
  })

  it('arms nothing for credentials Payload would not read as a users JWT', () => {
    const options = wired()
    const cases: Headers[] = [
      new Headers(),
      new Headers({ cookie: 'payload-token=' }),
      new Headers({ authorization: 'JWT not-a-jwt' }),
      new Headers({ authorization: 'JWT a.%%%.c' }),
      new Headers({ authorization: `JWT a.${base64url('1')}.c` }),
      new Headers({ authorization: `JWT ${jwtFor({ id: 7, collection: 'admins' })}` }),
      new Headers({
        authorization: `JWT ${jwtFor({ id: { nested: true }, collection: 'users' })}`,
      }),
    ]
    for (const headers of cases) {
      const req = request()
      ;(req.context as Record<string, unknown>)[LOCAL_CREDENTIAL_GATE_KEY] = 'stale'
      armLocalCredentialGate(headers, payloadWith(localAuth), req, options)
      // A stale marker is cleared, never left to veto a later read.
      expect(marker(req)).toBeUndefined()
    }
  })

  it('skips collections without the local strategy, missing collections, and bare requests', () => {
    const options = wired()
    const headers = new Headers({ authorization: `JWT ${usersJwt}` })
    const disabled = request()
    armLocalCredentialGate(headers, payloadWith({ disableLocalStrategy: true }), disabled, options)
    expect(marker(disabled)).toBeUndefined()
    const missing = request()
    armLocalCredentialGate(headers, payloadWith(undefined), missing, options)
    expect(marker(missing)).toBeUndefined()
    expect(() =>
      armLocalCredentialGate(headers, payloadWith(localAuth), undefined, options)
    ).not.toThrow()
    const contextless = { context: undefined } as unknown as PayloadRequest
    armLocalCredentialGate(headers, payloadWith(localAuth), contextless, options)
    expect(contextless.context).toBeUndefined()
    expect(() => disarmLocalCredentialGate(undefined)).not.toThrow()
  })
})

describe('localCredentialGateHook', () => {
  const linked = [{ providerId: 'stub', providerUserId: 'p', email: 'a@b.c', linkedAt: 'x' }]

  function run(
    options: ReturnType<typeof wired>,
    gate: unknown,
    args: { doc: unknown; findMany?: boolean; overrideAccess?: boolean; query?: unknown }
  ) {
    const req = { context: { [LOCAL_CREDENTIAL_GATE_KEY]: gate } } as unknown as PayloadRequest
    const hook = localCredentialGateHook(options)
    const result = (hook as (input: unknown) => unknown)({
      doc: args.doc,
      findMany: args.findMany,
      overrideAccess: args.overrideAccess ?? true,
      query: args.query,
      req,
    })
    return { result, gate }
  }

  it('refuses the armed API-key lookup of a linked document, logging the reason', () => {
    const warn = vi.fn()
    const logger: LoggerPort = { ...nullLogger(), warn }
    const options = wired({ logger })
    const gate = { jwtUserId: null, apiKey: true }
    expect(() =>
      run(options, gate, {
        doc: { identities: linked },
        findMany: true,
        query: { and: [{ or: [{ apiKeyIndex: { equals: 'x' } }] }] },
      })
    ).toThrow('API keys are unavailable for provider-linked accounts')
    expect(gate.apiKey).toBe(false)
    expect(warn).toHaveBeenCalledWith('local credential refused at authentication', {
      strategy: 'api-key',
      reason: 'provider-owned-api-key',
    })
  })

  it('refuses the armed JWT lookup of a linked document once, then lets reads through', () => {
    const options = wired()
    const gate = { jwtUserId: '9', apiKey: false }
    expect(() => run(options, gate, { doc: { id: 9, identities: linked } })).toThrow(
      'Local sessions are unavailable'
    )
    expect(gate.jwtUserId).toBeNull()
    expect(run(options, gate, { doc: { id: 9, identities: linked } }).result).toEqual({
      id: 9,
      identities: linked,
    })
  })

  it('touches nothing but the strategies’ own reads', () => {
    const options = wired()
    const doc = { id: 9, identities: linked }
    // No context, no marker, an unrelated value, a non-override read, a non-record doc.
    const hook = localCredentialGateHook(options) as (input: unknown) => unknown
    expect(hook({ doc, overrideAccess: true, req: { context: undefined } })).toBe(doc)
    expect(run(options, undefined, { doc }).result).toBe(doc)
    expect(run(options, 'stale', { doc }).result).toBe(doc)
    expect(
      run(options, { jwtUserId: '9', apiKey: false }, { doc, overrideAccess: false }).result
    ).toBe(doc)
    expect(run(options, { jwtUserId: '9', apiKey: false }, { doc: null }).result).toBeNull()
    // Another document, a list read for a JWT, a key read without the index.
    expect(run(options, { jwtUserId: '8', apiKey: false }, { doc }).result).toBe(doc)
    expect(run(options, { jwtUserId: '9', apiKey: false }, { doc, findMany: true }).result).toBe(
      doc
    )
    for (const query of [
      undefined,
      'x',
      [{ email: { equals: 'a' } }],
      { email: { equals: 'a' } },
    ]) {
      expect(
        run(options, { jwtUserId: null, apiKey: true }, { doc, findMany: true, query }).result
      ).toBe(doc)
    }
    // An id-less JWT read never matches.
    expect(
      run(options, { jwtUserId: '9', apiKey: false }, { doc: { identities: linked } }).result
    ).toEqual({
      identities: linked,
    })
  })

  it('lets a live document through and honours the opt-in', () => {
    const doc = { id: 9, identities: linked }
    expect(run(wired(), { jwtUserId: '9', apiKey: false }, { doc: { id: 9 } }).result).toEqual({
      id: 9,
    })
    const optedIn = wired({ allowLocalCredentialsForLinkedDocs: true })
    expect(run(optedIn, { jwtUserId: '9', apiKey: false }, { doc }).result).toBe(doc)
  })
})

describe('account predicates', () => {
  it('treat non-documents as neither suspended nor linked', () => {
    const options = wired()
    expect(suspensionActive(null, options)).toBe(false)
    expect(holdsLinkedIdentities('x', options)).toBe(false)
    expect(localCredentialRefusal({}, 'local-jwt', options)).toBeNull()
  })

  it('read the configured suspension field', () => {
    const options = wired({ suspendedUntilField: 'bannedUntil' })
    const until = '2999-01-01T00:00:00.000Z'
    expect(suspensionActive({ bannedUntil: until }, options)).toBe(true)
    expect(suspensionActive({ suspendedUntil: until }, options)).toBe(false)
    expect(localCredentialRefusal({ bannedUntil: until }, 'api-key', options)).toBe('suspended')
  })
})

describe('banActive — the Better Auth ban on the users document (GHSA-6244)', () => {
  const FUTURE = '2999-01-01T00:00:00.000Z'
  const PAST = '2021-01-01T00:00:00.000Z'

  it('banned with no expiry is a permanent ban; an expiry in the past has lifted', () => {
    const options = wired()
    expect(banActive({ banned: true }, options)).toBe(true)
    expect(banActive({ banned: true, banExpires: FUTURE }, options)).toBe(true)
    expect(banActive({ banned: true, banExpires: PAST }, options)).toBe(false)
    expect(banActive({ banned: false }, options)).toBe(false)
    expect(banActive({ banned: 'true' }, options)).toBe(false)
    expect(banActive({}, options)).toBe(false)
    expect(banActive(null, options)).toBe(false)
  })

  it('an active ban refuses both local credential shapes; suspension wins the label', () => {
    const options = wired()
    const banned = { banned: true }
    expect(localCredentialRefusal(banned, 'local-jwt', options)).toBe('banned')
    expect(localCredentialRefusal(banned, 'api-key', options)).toBe('banned')
    expect(
      localCredentialRefusal({ banned: true, suspendedUntil: FUTURE }, 'api-key', options)
    ).toBe('suspended')
    expect(
      localCredentialRefusal({ banned: true, banExpires: PAST }, 'api-key', options)
    ).toBeNull()
  })
})
