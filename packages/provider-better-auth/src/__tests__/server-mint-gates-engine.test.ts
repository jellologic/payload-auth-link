/**
 * Credential-path matrix row 18 (docs/security-model.md) on a REAL
 * Better Auth engine: the `allowServerSessions` deny half and the mint
 * audit half, previously pinned only on the stub provider.
 *
 * - Deny: the default `'dev-only'` gate refuses a mint on any runtime
 *   but `NODE_ENV === 'development'` (vitest runs `test`), and a
 *   refused mint (gate or suspension) writes no BA session row and no
 *   audit event.
 * - Audit: a mint reaches the durable `onAudit` sink with `reason`,
 *   `actor`, the `sessionId` BA stored, the STORED expiry (read back
 *   from the engine's own session row), and the vouched `mfaProof`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  authLink,
  authLinkServer,
  ServerSessionsDisabledError,
  UserSuspendedError,
} from '@payload-auth-link/plugin'
import { buildConfig } from 'payload'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createHarness, createPayloadRef } from './engine-harness.js'

const ORIGIN = 'http://server-mint-gates.test'
const SECRET = 'server-mint-gates-engine-secret!!!'

const ref = createPayloadRef()
const engine = createBetterAuthEngine({
  getPayload: ref.getPayload,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})
const h = createHarness({ origin: ORIGIN, engine, ref })

const auditEvents: { message: string; fields: Record<string, unknown> }[] = []

function mintEvents(): { message: string; fields: Record<string, unknown> }[] {
  return auditEvents.filter((event) => event.message === 'server session created')
}

type SessionRow = { id: string; token: string; expiresAt: Date }

/** The BA session rows the engine itself stores for a user. */
async function sessionRows(email: string): Promise<SessionRow[]> {
  const ctx = await engine.auth.$context
  return await ctx.internalAdapter.listSessions(await h.baUserId(email))
}

beforeAll(async () => {
  await h.boot(
    await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          // The default gate, spelled out: 'dev-only'.
          allowServerSessions: 'dev-only',
          providers: [engine.provider],
          onAudit: (event) => {
            auditEvents.push(event)
          },
        }),
      ],
    })
  )
  await engine.auth.$context
}, 120_000)

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('row 18: server mint gates on a real Better Auth engine', () => {
  it("deny: 'dev-only' refuses a mint outside development — no row, no audit", async () => {
    const email = 'mint-gated@ba-mint.test'
    const { id } = await h.linkedUser(email)
    const before = await sessionRows(email)
    auditEvents.length = 0
    expect(process.env.NODE_ENV).not.toBe('development')
    await expect(
      authLinkServer(h.live()).createSessionFor(id, { reason: 'gate-test' })
    ).rejects.toBeInstanceOf(ServerSessionsDisabledError)
    vi.stubEnv('NODE_ENV', 'production')
    await expect(
      authLinkServer(h.live()).createSessionFor(id, { reason: 'gate-test' })
    ).rejects.toBeInstanceOf(ServerSessionsDisabledError)
    expect((await sessionRows(email)).map((row) => row.id)).toEqual(before.map((row) => row.id))
    expect(mintEvents()).toEqual([])
  })

  it('deny: a suspended user is refused even on development — no row, no audit', async () => {
    const email = 'mint-suspended@ba-mint.test'
    const { id } = await h.linkedUser(email)
    await h.suspend(id)
    // Suspension revokes the live sessions; nothing may be minted after.
    const before = await sessionRows(email)
    auditEvents.length = 0
    vi.stubEnv('NODE_ENV', 'development')
    await expect(
      authLinkServer(h.live()).createSessionFor(id, { reason: 'gate-test' })
    ).rejects.toBeInstanceOf(UserSuspendedError)
    expect((await sessionRows(email)).map((row) => row.id)).toEqual(before.map((row) => row.id))
    expect(mintEvents()).toEqual([])
  })

  it('audit: a development mint is audited with the STORED session id and expiry', async () => {
    const email = 'mint-audited@ba-mint.test'
    const { id } = await h.linkedUser(email)
    auditEvents.length = 0
    vi.stubEnv('NODE_ENV', 'development')
    const minted = await authLinkServer(h.live()).createSessionFor(id, {
      reason: 'support-login',
      actor: 'ops@ba-mint.test',
      ttlSeconds: 600,
      mfaProof: true,
    })
    const row = (await sessionRows(email)).find((candidate) => candidate.token === minted.token)
    if (row === undefined) {
      throw new Error('the minted session row is missing from the engine store')
    }
    // The handle is the row id, never the bearer token.
    expect(minted.sessionId).toBe(row.id)
    expect(minted.sessionId).not.toBe(minted.token)
    expect(mintEvents()).toEqual([
      {
        message: 'server session created',
        fields: {
          providerId: 'better-auth',
          userId: id,
          sessionId: row.id,
          reason: 'support-login',
          actor: 'ops@ba-mint.test',
          mfaProof: true,
          expiresAt: new Date(row.expiresAt).toISOString(),
        },
      },
    ])
    // The audited event never carries the token.
    expect(JSON.stringify(mintEvents())).not.toContain(minted.token)
    // The minted cookie resolves the same linked user.
    expect(await h.hostIdOf(minted.setCookie?.split(';')[0] ?? '')).toBe(id)
  })
})
