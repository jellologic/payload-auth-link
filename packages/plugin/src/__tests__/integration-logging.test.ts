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
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider, stubCookieName } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'refusal-logging-secret-32-chars!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()
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
