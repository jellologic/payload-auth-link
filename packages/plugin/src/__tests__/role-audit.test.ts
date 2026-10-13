import { parseRole, nullLogger, type LoggerPort } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import type { WiredOptions } from '../options.js'
import { auditStoredRoles } from '../role-audit.js'

function wired(logger: LoggerPort): WiredOptions {
  return {
    config: {
      roles: [parseRole('admin')._unsafeUnwrap(), parseRole('user')._unsafeUnwrap()],
      defaultRole: parseRole('user')._unsafeUnwrap(),
      map: {
        usersCollection: 'users',
        emailField: 'email',
        rolesField: 'roles',
        identitiesField: 'identities',
      },
    },
    registry: {
      ids: () => [],
      require: () => {
        throw new Error('not used')
      },
    },
    logger,
    tracer: { withSpan: (_n: unknown, _a: unknown, fn: () => Promise<unknown>) => fn() },
    clock: { now: () => new Date() },
    ids: { newId: () => 'id' },
    depth: 0,
    linkingPolicy: { kind: 'verified-email' },
    admitChannels: ['cookie'],
    userFields: {
      phoneField: 'phone',
      suspendedUntilField: 'suspendedUntil',
      suspendReasonField: 'suspendReason',
    },
    requireMfaForRoles: [],
    roleManagerRoles: [parseRole('admin')._unsafeUnwrap()],
    onAudit: null,
    organizations: null,
  } as unknown as WiredOptions
}

function capturing(): { logger: LoggerPort; warnings: string[] } {
  const warnings: string[] = []
  const logger: LoggerPort = {
    ...nullLogger(),
    warn: (message) => {
      warnings.push(message)
    },
    child: () => logger,
  }
  return { logger, warnings }
}

/** A payload.find stub: `docs` holds up to `limit` rows, `totalDocs` the rest. */
function stubPayload(
  docs: unknown[],
  totalDocs: number
): { payload: Payload; find: ReturnType<typeof vi.fn> } {
  const find = vi.fn(() =>
    Promise.resolve({ docs, totalDocs, hasNextPage: totalDocs > docs.length })
  )
  return { payload: { find } as unknown as Payload, find }
}

describe('role-config audit (B11)', () => {
  it('bounds the query (pagination stays on) and warns on the fetched window', async () => {
    const { logger, warnings } = capturing()
    const docs = [{ id: '1', roles: ['editor'] }]
    const { payload, find } = stubPayload(docs, 1)
    await auditStoredRoles(wired(logger), payload)
    const args = find.mock.calls[0]?.[0] as { limit?: number; pagination?: boolean }
    expect(args.limit).toBe(500)
    expect(args.pagination).toBeUndefined()
    expect(warnings[0]).toContain("'editor' (1)")
  })

  it('reaches the truncation note when more users exist than were fetched', async () => {
    // 500 fetched docs all carrying an unconfigured role; totalDocs
    // says there are 700 — the note must name the cap (issue #21:
    // with `pagination: false` it was unreachable and the query
    // unbounded).
    const { logger, warnings } = capturing()
    const docs = Array.from({ length: 500 }, (_unused, index) => ({
      id: String(index),
      roles: ['editor'],
    }))
    const { payload } = stubPayload(docs, 700)
    await auditStoredRoles(wired(logger), payload)
    expect(warnings[0]).toContain('(first 500 scanned)')
    expect(warnings[0]).toContain("'editor' (500)")
  })

  it('stays silent when every stored role is configured', async () => {
    const { logger, warnings } = capturing()
    const { payload } = stubPayload([{ id: '1', roles: ['admin', 'user'] }], 1)
    await auditStoredRoles(wired(logger), payload)
    expect(warnings).toHaveLength(0)
  })
})
