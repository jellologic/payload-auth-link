import { isRecord, type LoggerPort } from '@payload-auth-link/core'
import type {
  CollectionBeforeOperationHook,
  CollectionConfig,
  GlobalBeforeOperationHook,
  GlobalConfig,
  PayloadRequest,
} from 'payload'
import { impersonationStateFromRequest } from './access.js'

/**
 * Per-operation impersonation audit (CAP-8b).
 *
 * The auth strategy only sees "a session verified" — it has no
 * operation, collection, or document id, so it cannot be the audit
 * seam. Payload's `beforeOperation` hooks are: they run for every
 * collection and global operation with the operation name, the
 * collection/global config, the operation args, and `req.user`,
 * which the strategy has already populated with the resolved actor.
 * The plugin therefore appends one audit hook to every collection
 * and global in the host config. `beforeOperation` (not
 * `afterOperation`) is deliberate: attempts that are then denied —
 * a role change blocked while impersonating, for example — are
 * audited too.
 *
 * Only impersonated operations log; plain requests return
 * immediately. Fields carry ids only (actor, target, operation,
 * collection/global slug, document id when the operation names one)
 * — never tokens, emails, or document data.
 */
function auditOperation(
  logger: LoggerPort,
  req: PayloadRequest,
  fields: {
    readonly operation: string
    readonly collection?: string
    readonly global?: string
    readonly args: unknown
  }
): void {
  // Fail-closed: a present-but-malformed actor is audited too
  // (actorKind 'malformed-actor', no fabricated attribution) — an
  // unparseable impersonation marker must never vanish from audit.
  const state = impersonationStateFromRequest(req)
  if (state.kind === 'none') {
    return
  }
  const actor = state.kind === 'actor' ? state.actor : null
  const args: unknown = fields.args
  const documentId =
    isRecord(args) && (typeof args.id === 'string' || typeof args.id === 'number')
      ? String(args.id)
      : undefined
  const target: unknown = req.user
  const targetUserId =
    isRecord(target) && (typeof target.id === 'string' || typeof target.id === 'number')
      ? String(target.id)
      : undefined
  logger.info('impersonated operation', {
    ...(actor === null ? {} : { actorProviderUserId: actor.providerUserId }),
    actorKind: actor === null ? 'malformed-actor' : actor.kind,
    ...(actor?.kind === 'payload-user' ? { actorUserId: String(actor.userId) } : {}),
    ...(targetUserId === undefined ? {} : { targetUserId }),
    operation: fields.operation,
    ...(fields.collection === undefined ? {} : { collection: fields.collection }),
    ...(fields.global === undefined ? {} : { global: fields.global }),
    ...(documentId === undefined ? {} : { id: documentId }),
  })
}

/** Collection `beforeOperation` audit hook; leaves args untouched. */
export function impersonatedCollectionAuditHook(logger: LoggerPort): CollectionBeforeOperationHook {
  return ({ args, collection, operation, req }) => {
    auditOperation(logger, req, { operation, collection: collection.slug, args })
  }
}

/** Global `beforeOperation` audit hook; leaves args untouched. */
export function impersonatedGlobalAuditHook(logger: LoggerPort): GlobalBeforeOperationHook {
  return ({ args, global, operation, req }) => {
    auditOperation(logger, req, { operation, global: global.slug, args })
  }
}

/**
 * Append the audit hook to every collection, preserving existing
 * hooks and order. Pure config transform: inputs are never mutated.
 */
export function withImpersonationAuditCollections(
  collections: readonly CollectionConfig[],
  logger: LoggerPort
): CollectionConfig[] {
  const hook = impersonatedCollectionAuditHook(logger)
  return collections.map((collection) => ({
    ...collection,
    hooks: {
      ...collection.hooks,
      beforeOperation: [...(collection.hooks?.beforeOperation ?? []), hook],
    },
  }))
}

/** Append the audit hook to every global; see the collection form. */
export function withImpersonationAuditGlobals(
  globals: readonly GlobalConfig[] | undefined,
  logger: LoggerPort
): GlobalConfig[] {
  const hook = impersonatedGlobalAuditHook(logger)
  return (globals ?? []).map((global) => ({
    ...global,
    hooks: {
      ...global.hooks,
      beforeOperation: [...(global.hooks?.beforeOperation ?? []), hook],
    },
  }))
}
