import type { Payload } from 'payload'
import { closeAbortedPass, openRun, recordRunEntries } from './binding.js'
import { targetSlugsOf, type IdentityCheck } from './guards.js'
import { capturedKeys, captureBefore, updateKeepingTimestamp } from './host-writes.js'
import { signManifest } from './manifest-mac.js'
import type { FieldWrite, ImportManifest, Unmappable } from './types.js'

/**
 * The adopt-mode pre-link (issues #49, #88): `migrate adopt-prelink`.
 *
 * In adopt mode the users collection IS Better Auth's user table
 * (`schemaMap.user`, `idStrategy: 'payload'`), so Better Auth's user id
 * for a document is the document id. What adopt mode does NOT do by
 * itself is link the plugin side: without an identity row, the first
 * provider sign-in reaches JIT linking, which links an existing
 * document only on the verified-email proof (`linkable === true` with
 * `linkableEmail` equal to the document email).
 *
 * This command mirrors exactly what the importer writes on the host
 * users (issue #69):
 *
 * - ONE `better-auth` identity per user, `providerUserId` = the
 *   document id (other providers' identity rows are kept);
 * - with `grantLinkableFromVerified` (`--grant-linkable-from-verified`)
 *   only: `linkable: true` + `linkableEmail: <email>` for users whose
 *   verified-email field (`emailVerified` on payload-auth layouts) is
 *   `true` — grant-only, never revoked. Off by default: that flag is a
 *   mirror that can be stale for an address changed after it was
 *   verified, and the proof lets ANOTHER provider's sign-in for the
 *   address link to the document (the GHSA-v6mr outcome). The
 *   better-auth identity resolves every user without it.
 *
 * Dry run by default. `--apply` records every prior value in a manifest
 * (first capture wins, sealed, mode 0600) so `rollback --manifest`
 * restores the documents exactly, `updatedAt` included. The write
 * itself keeps each document's `updatedAt` (issue #116); the Local
 * API's full-document write does re-create hasMany child rows (such as
 * `users_role`) with new surrogate row ids — values and order intact.
 * The write carries the kit's migration context marker
 * (`MIGRATION_CONTEXT`, host-writes.ts) so host hooks can skip their
 * outward side effects (issue #123).
 *
 * The users collection is the ONLY one this command writes: the
 * invitations table is not among its written tables, so invitation
 * rows carrying the legacy JSON-encoded role strings (issue #142) are
 * NOT normalized here — rewrite them by hand (the doctor reports them
 * as `legacy-invitation-roles`).
 */

export type PrelinkOptions = {
  readonly payload: Payload
  readonly apply: boolean
  readonly manifest: ImportManifest | null
  readonly manifestPath: string
  /** Users collection slug. Defaults to `users`. */
  readonly usersSlug?: string | undefined
  /** The users' verified-email checkbox. Defaults to `emailVerified`. */
  readonly verifiedField?: string | undefined
  /** Email field. Defaults to `email`. */
  readonly emailField?: string | undefined
  readonly now?: () => Date
  readonly log?: (message: string) => void
  /**
   * Accept an unsigned or 0.6.0 manifest (`--allow-unsigned-manifest`) —
   * for the dry run only: such a manifest is never resumed by `--apply`.
   */
  readonly allowUnsignedManifest?: boolean | undefined
  /** Resume a signed 0.7.0 manifest that names no database (`--allow-unbound-manifest`). */
  readonly allowUnboundManifest?: boolean | undefined
  /**
   * Grant the linking proof from the verified-email field
   * (`--grant-linkable-from-verified`). Off by default — see above.
   */
  readonly grantLinkableFromVerified?: boolean | undefined
  /** How this environment identifies itself (GHSA-xw9m-ph95-84rx). */
  readonly identity?: IdentityCheck | undefined
}

export type PrelinkResult = {
  readonly users: number
  /** Documents that received (or would receive) the better-auth identity. */
  readonly linked: number
  /** Documents already carrying the exact identity. */
  readonly alreadyLinked: number
  /** Verified documents granted (or to be granted) the linking proof. */
  readonly proofGranted: number
  /** Users without a verified email: identity only, no linking proof. */
  readonly unverified: number
  /**
   * Verified documents NOT granted the proof because
   * `grantLinkableFromVerified` is off (they still get the identity).
   */
  readonly proofWithheld: number
  readonly unmappable: readonly Unmappable[]
  readonly fieldWrites: number
}

type IdentityRow = {
  readonly id?: unknown
  readonly providerId?: unknown
  readonly providerUserId?: unknown
  readonly email?: unknown
  readonly linkedAt?: unknown
}

function identitiesOf(doc: Record<string, unknown>): IdentityRow[] {
  const raw = doc['identities']
  return Array.isArray(raw)
    ? raw.filter((row): row is IdentityRow => typeof row === 'object' && row !== null)
    : []
}

export async function prelinkUsers(options: PrelinkOptions): Promise<PrelinkResult> {
  const { payload, apply, log = () => {}, now = () => new Date() } = options
  const usersSlug = options.usersSlug ?? 'users'
  const verifiedField = options.verifiedField ?? 'emailVerified'
  const emailField = options.emailField ?? 'email'
  // Resuming re-signs the old entries: only a signed manifest of THIS
  // database's open pre-link run is resumed (GHSA-crrr-3cg7-f6jw).
  const { carried, binding } = await openRun({
    payload,
    manifest: options.manifest,
    kind: 'adopt-prelink',
    apply,
    slugs: targetSlugsOf(),
    now,
    log,
    allowUnsignedManifest: options.allowUnsignedManifest,
    allowUnboundManifest: options.allowUnboundManifest,
    identity: options.identity,
  })
  const grantLinkable = options.grantLinkableFromVerified === true
  const fieldWrites: FieldWrite[] = [...(carried?.fieldWrites ?? [])]
  const captured = capturedKeys(fieldWrites)

  type Planned = {
    readonly id: string | number
    readonly email: string
    readonly writeIdentity: boolean
    readonly grantProof: boolean
    readonly keep: IdentityRow[]
  }
  const planned: Planned[] = []
  const unmappable: Unmappable[] = []
  let users = 0
  let alreadyLinked = 0
  let unverified = 0
  let proofWithheld = 0

  // Plan the WHOLE collection before any write: a conflicting identity
  // anywhere aborts the run with nothing written.
  for (let page = 1; ; page += 1) {
    const batch = await payload.find({
      collection: usersSlug,
      depth: 0,
      limit: 200,
      page,
      sort: 'id',
      overrideAccess: true,
    })
    for (const doc of batch.docs as unknown as Record<string, unknown>[]) {
      users += 1
      const id = doc['id']
      const email = doc[emailField]
      if ((typeof id !== 'string' && typeof id !== 'number') || typeof email !== 'string') {
        unmappable.push({
          model: 'user',
          key: String(id),
          reason: `document has no usable id/'${emailField}'`,
        })
        continue
      }
      const providerUserId = String(id)
      const identities = identitiesOf(doc)
      const own = identities.filter((row) => row.providerId === 'better-auth')
      const conflicting = own.filter((row) => String(row.providerUserId) !== providerUserId)
      if (conflicting.length > 0) {
        unmappable.push({
          model: 'user',
          key: providerUserId,
          reason: `user #${providerUserId} already carries a better-auth identity for a different provider user id; adopt mode serves the document id as the Better Auth user id — resolve the link by hand first`,
        })
        continue
      }
      const verified = doc[verifiedField] === true
      if (!verified) {
        unverified += 1
      }
      const writeIdentity = own.length !== 1
      const wantsProof = verified && (doc['linkable'] !== true || doc['linkableEmail'] !== email)
      if (wantsProof && !grantLinkable) {
        proofWithheld += 1
      }
      const grantProof = grantLinkable && wantsProof
      if (!writeIdentity) {
        alreadyLinked += 1
      }
      if (writeIdentity || grantProof) {
        planned.push({
          id,
          email,
          writeIdentity,
          grantProof,
          keep: identities.filter((row) => row.providerId !== 'better-auth'),
        })
      }
    }
    if (!batch.hasNextPage) {
      break
    }
  }

  const linked = planned.filter((row) => row.writeIdentity).length
  const proofGranted = planned.filter((row) => row.grantProof).length
  if (unmappable.length > 0) {
    log(`ABORT: ${unmappable.length} unmappable user(s); nothing was written`)
    // Nothing was written: an aborted fresh run is closed, a resumed
    // one keeps what it carried (issue #116).
    if (apply && binding !== null) {
      await closeAbortedPass(payload, 'adopt-prelink', binding, carried, 'adopt-prelink --apply')
    }
    return {
      users,
      linked: 0,
      alreadyLinked,
      proofGranted: 0,
      unverified,
      proofWithheld,
      unmappable,
      fieldWrites: 0,
    }
  }

  let fieldWriteCount = 0
  if (apply && binding !== null) {
    const persist = async (): Promise<void> => {
      const manifest: ImportManifest = signManifest(payload.secret, {
        version: 4,
        kind: 'adopt-prelink',
        createdAt: binding.createdAt,
        databaseId: binding.databaseId,
        runId: binding.runId,
        sourceDatabase: '(adopt mode: the target app database)',
        options: { sessions: 'carry' },
        created: [],
        fieldWrites,
        finalized: false,
        sourceCounts: {},
        totals: { user: users, linked, proofGranted },
      })
      const { writeManifest } = await import('./lifecycle.js')
      writeManifest(manifest, options.manifestPath)
      await recordRunEntries(
        payload,
        'adopt-prelink',
        binding,
        fieldWrites.length,
        'adopt-prelink --apply'
      )
    }
    try {
      for (const row of planned) {
        const { newlyCaptured, before } = await captureBefore({
          payload,
          collection: usersSlug,
          id: row.id,
          fields: ['identities', 'linkable', 'linkableEmail'],
          captured,
          into: fieldWrites,
          scope: binding,
        })
        fieldWriteCount += newlyCaptured
        const data: Record<string, unknown> = {}
        if (row.writeIdentity) {
          data.identities = [
            ...row.keep.map((identity) => ({
              providerId: identity.providerId,
              providerUserId: identity.providerUserId,
              email: identity.email,
              linkedAt: identity.linkedAt,
            })),
            {
              providerId: 'better-auth',
              providerUserId: String(row.id),
              email: row.email,
              linkedAt: now().toISOString(),
            },
          ]
        }
        if (row.grantProof) {
          data.linkable = true
          data.linkableEmail = row.email
        }
        // The pre-link is bookkeeping, not a user edit (issue #116):
        // the document keeps its updatedAt. Marked (op 'adopt-prelink')
        // so host hooks can skip outward side effects (issue #123).
        await updateKeepingTimestamp(payload, {
          collection: usersSlug,
          id: row.id,
          data,
          updatedAt: before?.['updatedAt'],
          op: 'adopt-prelink',
        })
      }
    } catch (error) {
      // Record what was written before the failure, so the run can be
      // resumed or rolled back (issue #116).
      try {
        await persist()
      } catch (persistError) {
        throw new Error(
          `${error instanceof Error ? error.message : String(error)} — and the manifest could not be written afterwards (${persistError instanceof Error ? persistError.message : String(persistError)})`,
          { cause: persistError }
        )
      }
      throw error
    }
    await persist()
  }
  return {
    users,
    linked,
    alreadyLinked,
    proofGranted,
    unverified,
    proofWithheld,
    unmappable,
    fieldWrites: fieldWriteCount,
  }
}
