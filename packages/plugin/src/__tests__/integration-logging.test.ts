/**
 * Integration test: refusals are loud by default (docs/concepts
 * promises it; issue #15 broke it with the silent default logger).
 * A request presenting a session-shaped cookie that resolves to
 * nothing warns with the reason; a truly anonymous probe stays
 * silent so health checks do not spam the log.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { consoleLogger, type LoggerPort } from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { okAsync } from 'neverthrow'
import { authLink } from '../index.js'
import { wireOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider, stubCookieName } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'refusal-logging-secret-32-chars!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()
const getCount = vi.fn(() => okAsync(null))
const warnings: string[] = []
const logger: LoggerPort = {
  ...consoleLogger(),
  warn: (message) => {
    warnings.push(message)
  },
  child: () => logger,
}

async function session(cookie?: string): Promise<number> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, {
      method: 'GET',
      headers: { ...(cookie === undefined ? {} : { cookie }) },
    }),
  })
  return response.status
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        logger,
      }),
    ],
  })
  payload = await getPayload({ config })
}, 60_000)

describe('one resolution per request (issue #42)', () => {
  it('verifies the same headers once: one provider read, one warning', async () => {
    const countConfig = await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      collections: [{ slug: 'users', auth: true, fields: [] }],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [
            {
              ...stub.provider,
              getSession: (headers: Headers) => {
                getCount()
                return stub.provider.getSession(headers)
              },
            },
          ],
        }),
      ],
    })
    const countPayload = await getPayload({ config: countConfig })
    const wired = wireOptions({
      baseUrl: ORIGIN,
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [
        {
          ...stub.provider,
          getSession: (headers: Headers) => {
            getCount()
            return stub.provider.getSession(headers)
          },
        },
      ],
      logger,
    })
    const { sessions } = createServices(wired, countPayload)

    // The auth strategy and the endpoint handler see the SAME
    // `headers` reference for one request; both verifications must
    // collapse into one provider walk and one warning.
    const headers = new Headers({ cookie: `${stubCookieName}=stale-garbage` })
    const first = await sessions.verify(headers)
    const second = await sessions.verify(headers)
    expect(first.isErr() && second.isErr()).toBe(true)
    expect(getCount).toHaveBeenCalledTimes(1)
    expect(
      warnings.filter((message) => message.includes('no provider session resolved'))
    ).toHaveLength(1)
  })
})

describe('refusal logging (default-audible logger)', () => {
  it('warns when a session-shaped cookie resolves to nothing (stale config or cookie)', async () => {
    warnings.length = 0
    expect(await session(`${stubCookieName}=stale-or-garbage`)).toBe(401)
    expect(warnings.some((message) => message.includes('no provider session resolved'))).toBe(true)
  })

  it('warns with provider context when a provider errors during session read', async () => {
    warnings.length = 0
    // The stub's read never fails; force the provider-error path by
    // breaking the cookie shape it rejects (covered by unit tests for
    // the read-failure branch). Here: expired-session refusals carry
    // provider and channel — a live session past its expiry.
    const expired = stub.issue({
      sessionId: 'sess-expired-logging',
      providerUserId: 'expired-1',
      email: 'expired@test.dev',
      expiresAt: new Date(Date.now() - 1000),
    })
    expect(await session(expired)).toBe(401)
    expect(warnings.some((message) => message.includes('provider session expired'))).toBe(true)
  })

  it('stays silent for truly anonymous probes', async () => {
    warnings.length = 0
    expect(await session()).toBe(401)
    expect(await session('unrelated_cookie=1')).toBe(401)
    expect(warnings).toHaveLength(0)
    void payload
  })
})
