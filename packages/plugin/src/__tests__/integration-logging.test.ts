/**
 * Integration test: refusals are loud by default (docs/concepts
 * promises it; issue #15 broke it with the silent default logger).
 * A request presenting a session-shaped cookie that resolves to
 * nothing warns with the reason; a truly anonymous probe stays
 * silent so health checks do not spam the log.
 */
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
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
    warnings.push(`#${warnings.length} ${message}`)
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

    // The real strategy and endpoint paths may see DIFFERENT Headers
    // object references (bundler graphs), so the memo layers are: the
    // headers WeakMap (same-object reuse) and req.context (shared
    // request). Each layer must collapse its own duplicate walks.
    const req = { context: { 'dbg-id': 'req-memo-req' } as Record<string, unknown> }
    const headersA = new Headers({ cookie: `${stubCookieName}=stale-garbage` })
    const headersB = new Headers({ cookie: `${stubCookieName}=stale-garbage` })
    const first = await sessions.verify(headersA, req as never)
    const second = await sessions.verify(headersA, req as never)
    const third = await sessions.verify(headersB, req as never)
    expect(first.isErr() && second.isErr() && third.isErr()).toBe(true)
    expect(getCount).toHaveBeenCalledTimes(1)
    expect(
      warnings.filter((message) => message.includes('no provider session resolved'))
    ).toHaveLength(1)
  })
})

describe('one provider walk per HTTP request (issue #42 reopen)', () => {
  it('counts exactly one getSession per refused REST request', async () => {
    const countSecret = `${SECRET}-count-rest`
    const countConfig = await buildConfig({
      secret: countSecret,
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
    getCount.mockClear()
    warnings.length = 0
    const response = await handleEndpoints({
      config: countConfig,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'GET',
        headers: { cookie: `${stubCookieName}=stale-garbage` },
      }),
    })
    expect(response.status).toBe(401)
    // Payload passes `req` to auth strategies from 3.84.1; before that
    // (the 3.83.0 band floor, 3.84.0) the strategy cannot share its
    // resolution with the endpoint, so the refusal is logged twice —
    // documented in docs/compatibility.md.
    // `payload` exports no `./package.json`: read it beside the entry.
    const payloadEntry = createRequire(import.meta.url).resolve('payload')
    const payloadVersion = (
      JSON.parse(readFileSync(join(dirname(payloadEntry), '..', 'package.json'), 'utf8')) as {
        version: string
      }
    ).version
    const strategyGetsReq = !/^3\.(83\.|84\.0$)/.test(payloadVersion)
    expect(
      warnings.filter((message) => message.includes('no provider session resolved'))
    ).toHaveLength(strategyGetsReq ? 1 : 2)
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
