import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import type { CollectionConfig, GlobalConfig, PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import {
  composeAuditLogger,
  impersonatedCollectionAuditHook,
  impersonatedGlobalAuditHook,
  withImpersonationAuditCollections,
  withImpersonationAuditGlobals,
} from '../audit.js'

function capturingLogger(): { logger: LoggerPort; info: ReturnType<typeof vi.fn> } {
  const info = vi.fn()
  return { logger: { ...nullLogger(), info }, info }
}

function requestWith(user: unknown): PayloadRequest {
  return { user } as unknown as PayloadRequest
}

const impersonatedUser = {
  id: 'user-1',
  collection: 'users',
  email: 'target@test.dev',
  roles: ['user'],
  actor: { kind: 'provider-only', providerUserId: 'op-1' },
}

describe('impersonation audit hooks (CAP-8b)', () => {
  it('logs collection operations with actor, target, operation, collection, id', () => {
    const { logger, info } = capturingLogger()
    const hook = impersonatedCollectionAuditHook(logger)
    const result = hook({
      args: { id: 42 },
      collection: { slug: 'posts' },
      operation: 'updateByID',
      req: requestWith(impersonatedUser),
    } as unknown as Parameters<typeof hook>[0])
    expect(result).toBeUndefined()
    expect(info).toHaveBeenCalledWith('impersonated operation', {
      actorProviderUserId: 'op-1',
      actorKind: 'provider-only',
      targetUserId: 'user-1',
      operation: 'updateByID',
      collection: 'posts',
      id: '42',
    })
  })

  it('logs global operations under the global slug', () => {
    const { logger, info } = capturingLogger()
    const hook = impersonatedGlobalAuditHook(logger)
    const result: unknown = hook({
      args: {},
      global: { slug: 'settings' },
      operation: 'update',
      req: requestWith(impersonatedUser),
    } as unknown as Parameters<typeof hook>[0])
    expect(result).toBeUndefined()
    expect(info).toHaveBeenCalledWith('impersonated operation', {
      actorProviderUserId: 'op-1',
      actorKind: 'provider-only',
      targetUserId: 'user-1',
      operation: 'update',
      global: 'settings',
    })
  })

  it('FAIL-CLOSED: audits a present-but-malformed actor instead of going silent', () => {
    const { logger, info } = capturingLogger()
    const hook = impersonatedCollectionAuditHook(logger)
    const result = hook({
      args: { id: 42 },
      collection: { slug: 'posts' },
      operation: 'updateByID',
      req: requestWith({ ...impersonatedUser, actor: 'operator-1' }),
    } as unknown as Parameters<typeof hook>[0])
    expect(result).toBeUndefined()
    expect(info).toHaveBeenCalledWith('impersonated operation', {
      actorKind: 'malformed-actor',
      targetUserId: 'user-1',
      operation: 'updateByID',
      collection: 'posts',
      id: '42',
    })
  })

  it('stays silent for non-impersonated requests', () => {
    const { logger, info } = capturingLogger()
    const hook = impersonatedCollectionAuditHook(logger)
    const result = hook({
      args: {},
      collection: { slug: 'posts' },
      operation: 'find',
      req: requestWith({ id: 'user-1', collection: 'users', email: 'a@test.dev', roles: [] }),
    } as unknown as Parameters<typeof hook>[0])
    expect(result).toBeUndefined()
    expect(info).not.toHaveBeenCalled()
  })

  it('appends to every collection and global without mutating inputs', () => {
    const { logger } = capturingLogger()
    const existing = vi.fn()
    const collections: CollectionConfig[] = [
      { slug: 'posts', fields: [], hooks: { beforeOperation: [existing] } },
      { slug: 'pages', fields: [] },
    ]
    const audited = withImpersonationAuditCollections(collections, logger)
    expect(audited[0]?.hooks?.beforeOperation).toHaveLength(2)
    expect(audited[0]?.hooks?.beforeOperation?.[0]).toBe(existing)
    expect(audited[1]?.hooks?.beforeOperation).toHaveLength(1)
    expect(collections[0]?.hooks?.beforeOperation).toHaveLength(1)
    expect(collections[1]?.hooks).toBeUndefined()

    const globals: GlobalConfig[] = [{ slug: 'settings', fields: [] }]
    const auditedGlobals = withImpersonationAuditGlobals(globals, logger)
    expect(auditedGlobals[0]?.hooks?.beforeOperation).toHaveLength(1)
    expect(globals[0]?.hooks).toBeUndefined()
    expect(withImpersonationAuditGlobals(undefined, logger)).toEqual([])
  })
})

describe('durable audit sink (onAudit)', () => {
  it('fans every audit event out to the logger and the sink', () => {
    const { logger, info } = capturingLogger()
    const events: Array<{ message: string; fields: Record<string, unknown> }> = []
    const composed = composeAuditLogger(logger, (event) => {
      events.push(event)
    })
    const hook = impersonatedCollectionAuditHook(composed)
    void hook({
      args: { id: 7 },
      collection: { slug: 'posts' },
      operation: 'deleteByID',
      req: requestWith(impersonatedUser),
    } as unknown as Parameters<typeof hook>[0])
    expect(info).toHaveBeenCalledOnce()
    expect(events).toHaveLength(1)
    expect(events[0]?.message).toBe('impersonated operation')
    expect(events[0]?.fields).toMatchObject({ operation: 'deleteByID', id: '7' })
  })

  it('keeps non-audit log levels out of the sink', () => {
    const base = nullLogger()
    const events: unknown[] = []
    const composed = composeAuditLogger(base, (event) => events.push(event))
    composed.warn('not an audit event')
    composed.error('also not')
    composed.debug('nothing here either')
    expect(events).toHaveLength(0)
  })
})
