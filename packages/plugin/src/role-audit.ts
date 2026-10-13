import type { Payload } from 'payload'
import type { WiredOptions } from './options.js'

/**
 * B11 role-config audit. Roles are stored on user docs as plain
 * slugs while the configured set lives in plugin options, so a role
 * removed (or renamed) in `authLink({ roles })` leaves stored values
 * behind silently. Reads already drop unconfigured roles (B11 filter
 * in `toRoles`), but the operator must learn at startup — once, as
 * one aggregate warning — not from a broken permission report later.
 *
 * Runs on `onInit`, before any request can mint a session. Failures
 * degrade to a warning: the audit must never block a boot.
 */
export async function auditStoredRoles(wired: WiredOptions, payload: Payload): Promise<void> {
  const configured = new Set<string>(wired.config.roles)
  const rolesField = wired.config.map.rolesField
  try {
    const found = await payload.find({
      collection: wired.config.map.usersCollection,
      // `exists` instead of `not_in`: array-field `not_in` semantics
      // vary per adapter, while the per-doc narrowing below is exact.
      // Pagination stays on (default): `limit` bounds the fetch to
      // 500 docs and `totalDocs` counts the rest — with
      // `pagination: false` the limit is ignored (unbounded query)
      // and the truncation note below could never fire.
      where: { [rolesField]: { exists: true } },
      limit: 500,
      depth: 0,
      overrideAccess: true,
    })
    const counts = new Map<string, number>()
    let affectedDocs = 0
    for (const doc of found.docs) {
      const value: unknown = (doc as Record<string, unknown>)[rolesField]
      if (!Array.isArray(value)) {
        continue
      }
      let docAffected = false
      for (const entry of value) {
        if (typeof entry === 'string' && !configured.has(entry)) {
          counts.set(entry, (counts.get(entry) ?? 0) + 1)
          docAffected = true
        }
      }
      if (docAffected) {
        affectedDocs += 1
      }
    }
    if (affectedDocs === 0) {
      return
    }
    const detail = [...counts.entries()].map(([roleName, count]) => `'${roleName}' (${count})`)
    const truncated =
      found.totalDocs > found.docs.length ? ` (first ${found.docs.length} scanned)` : ''
    wired.logger.warn(
      `payload-auth-link: ${affectedDocs} user doc(s)${truncated} carry roles outside the ` +
        `configured set: ${detail.join(', ')}. They stopped granting in sessions; reassign ` +
        'affected users, then remove the stale values. See docs/upgrading.md (role removal runbook).'
    )
  } catch (error) {
    wired.logger.warn(
      `payload-auth-link: role-config audit failed; continuing without it: ${
        error instanceof Error ? error.message : String(error)
      }`
    )
  }
}
