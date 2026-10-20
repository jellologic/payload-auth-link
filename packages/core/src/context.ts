/**
 * The `req.context` key the ENGINE stamps on the Local API creates it
 * performs for Better Auth users (issue #132). The plugin's users
 * collection hook reads it to tell an engine-created row (whose id IS
 * the provider user id in adopt mode, and whose identities row can be
 * written at creation) apart from an operator-created document, which
 * must never gain a synthetic identity.
 */
export const engineCreateMarker = 'payload-auth-link:engine-create'

/**
 * The `req.context` key the PLUGIN stamps on the Local API writes it
 * performs for its own bookkeeping — provider-identity links,
 * provider-email and provider-phone resyncs, plugin-managed creates,
 * and role writes (issue #144, mirroring the migrate kit's
 * `MIGRATION_CONTEXT`). The writes run through the HOST app's Local
 * API, so the users collection's `beforeChange` / `afterChange` hooks
 * fire for each one. A host hook that triggers outward side effects
 * (a CRM sync, an email, a webhook, re-indexing) skips them for
 * payload-auth-link's own bookkeeping writes by checking this key:
 *
 * ```ts
 * import { authLinkWriteMarker } from '@payload-auth-link/core'
 *
 * // in a users-collection hook:
 * if (req.context?.[authLinkWriteMarker] !== undefined) return
 * ```
 *
 * The plugin's scoped identity writes go straight through the
 * database adapter (`payload.db.updateOne`), which runs no hooks at
 * all — those writes carry no marker because there is nothing to
 * skip (the same asymmetry the migrate kit documents).
 */
export const authLinkWriteMarker = 'payload-auth-link:write'

/** The plugin write a marked Local API call performs (issue #144). */
export type AuthLinkWriteOp =
  /** A plugin-managed user create (JIT provisioning, credential registration). */
  | 'create'
  /**
   * The identity row written at creation for adopt-mode engine
   * creates (`idStrategy: 'payload'`). The collection hook that
   * performs that write stamps its own `engineCreateMarker` instead;
   * the op is named here so hosts can match it across both markers.
   */
  | 'identity-at-creation'
  /** A provider identity linked to an existing user. */
  | 'link-identity'
  /** The provider's verified email synced onto the user. */
  | 'resync-email'
  /** The provider's verified phone synced onto the user. */
  | 'resync-phone'
  /** A role write through the governance flow. */
  | 'set-roles'
  /** A provider identity removed from a user. */
  | 'unlink-identity'

/** The value the plugin stores under {@link authLinkWriteMarker} in `req.context`. */
export type AuthLinkWriteMarker = {
  readonly op: AuthLinkWriteOp
}
