import { isRecord, type Email, type UserId } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import type { WiredOptions } from './options.js'

/**
 * Verified-email sync for an ALREADY-LINKED user (issue #88).
 *
 * `setEmail` grants the linking proof when a verified provider event
 * MOVES the address — but a user who verifies the address they
 * already carry (the post-import verification: imported unverified,
 * pre-linked by identity, verified later) used to change nothing: the
 * `linkable` proof stayed off and the host's own verified mirror (e.g.
 * payload-auth's `emailVerified`) stayed `false`.
 *
 * The provider just verified this exact address for the identity that
 * is linked to this document, which is the same proof `setEmail`
 * grants on a change: the proof is bound to the address
 * (`linkableEmail`), and the configured mirror is set `true`. Writes
 * only what differs, so the per-update provider hook stays a no-op
 * once in step. Never sets the mirror `false` (only the proof reset on
 * an unproven email change does, `collections.ts`).
 */
export async function syncVerifiedEmail(
  wired: WiredOptions,
  payload: Payload,
  userId: UserId,
  email: Email
): Promise<'updated' | 'unchanged'> {
  const collection = wired.config.map.usersCollection
  const doc: unknown = await payload.findByID({
    collection,
    id: userId,
    depth: 0,
    overrideAccess: true,
  })
  if (!isRecord(doc)) {
    return 'unchanged'
  }
  // Only the CURRENT address: an event for an address the document no
  // longer carries (or never carried) proves nothing about it.
  if (doc[wired.config.map.emailField] !== email) {
    return 'unchanged'
  }
  const data: Record<string, unknown> = {}
  if (doc.linkable !== true || doc.linkableEmail !== email) {
    data.linkable = true
    data.linkableEmail = email
  }
  const mirror = wired.emailVerifiedField
  if (mirror !== null && doc[mirror] !== true) {
    data[mirror] = true
  }
  if (Object.keys(data).length === 0) {
    return 'unchanged'
  }
  await payload.update({ collection, id: userId, data, overrideAccess: true })
  return 'updated'
}
