import type { Payload } from 'payload'
import {
  assertCreatedRowsScoped,
  assertNoFinalizeMarker,
  databaseIdentity,
  holdsEntries,
  newRunId,
  openRuns,
  readRun,
  recordRun,
  type IdentityCheck,
  type RunRecord,
} from './guards.js'
import { authenticateManifest, isBound, type ManifestTrust } from './manifest-mac.js'
import type { ImportManifest, ManifestKind, TargetSlugMap } from './types.js'

/**
 * Manifest ↔ database binding (GHSA-crrr-3cg7-f6jw).
 *
 * A manifest is a file; the database it drives is not. Every write the
 * kit makes from a manifest therefore checks the DATABASE's own record
 * first, kept in Payload's key-value store:
 *
 * - a database id, minted on the first `--apply` (or `adopt-prelink
 *   --apply`), which every version-4 manifest names inside its
 *   signature — a manifest from another environment (a rehearsal clone
 *   sharing `PAYLOAD_SECRET`) names another id and is refused;
 * - one record per run (a random nonce, also signed into the manifest):
 *   open, rolled back, or finalized. Only an OPEN run is resumed or
 *   rolled back, so a stale copy of a rolled-back run's manifest
 *   changes nothing. At most ONE run is open at a time (issue #116):
 *   two open runs would each hold rows the other's rollback or finalize
 *   cannot see.
 *
 * The database id alone does not tell a database from its clone (a
 * copy taken after the first `--apply` carries the same record), so the
 * record also keeps a server fingerprint (Postgres) and the operator's
 * environment id — see `databaseIdentity` (GHSA-xw9m-ph95-84rx).
 *
 * Unsigned manifests (pre-0.6.0) and 0.6.0 manifests whose signature
 * does not cover `finalized` are TERMINAL: they may be rolled back or
 * finalized, never resumed — a resume would re-sign their (unverifiable)
 * entries into a manifest every later command trusts.
 */

/** The database and run a manifest write belongs to. */
export type RunBinding = {
  readonly databaseId: string
  readonly runId: string
  readonly createdAt: string
}

const anotherDatabase =
  'the manifest was written against a different database (its database id is not this database’s) — never resume or roll back with a manifest from another environment or another run; nothing was changed'

/** Count of version-1 plaintext prior values in the manifest. */
export function plaintextWrites(manifest: Pick<ImportManifest, 'fieldWrites'>): number {
  return manifest.fieldWrites.filter((write) => write.before !== undefined).length
}

/**
 * Check a bound manifest against the database's record: same database,
 * a run the database knows, of the manifest's kind. Returns the run's
 * record. Fails closed when the store cannot be read.
 */
export async function boundRun(
  payload: Payload,
  manifest: ImportManifest & { readonly databaseId: string; readonly runId: string },
  action: string,
  identity?: IdentityCheck
): Promise<RunRecord> {
  const databaseId = await databaseIdentity(payload, { create: false, action, check: identity })
  if (databaseId !== manifest.databaseId) {
    throw new Error(anotherDatabase)
  }
  const run = await readRun(payload, manifest.runId, action)
  if (
    run === null ||
    run.kind !== (manifest.kind ?? 'import') ||
    (run.databaseId !== undefined && run.databaseId !== databaseId)
  ) {
    throw new Error(
      `this database holds no record of the manifest's run — never resume or roll back with a manifest from another environment or another run; nothing was changed`
    )
  }
  return run
}

/** A short description of open runs, for a refusal. */
function describeRuns(runs: readonly (RunRecord & { readonly runId: string })[]): string {
  return runs
    .map(
      (run) =>
        `${run.kind} run ${run.runId} started ${run.createdAt}${run.entries === undefined ? '' : ` (${run.entries} manifest entr${run.entries === 1 ? 'y' : 'ies'})`}`
    )
    .join('; ')
}

/**
 * Mint a new run on this database (creating its id on first use).
 * `exclusive` (every run a pass WRITES under): refuse while another
 * open run may hold rows (issue #116) — a second one would hold rows
 * the first one's rollback or finalize cannot see. A run minted only
 * to record a rollback of an unbound manifest is not exclusive.
 */
export async function startRun(
  payload: Payload,
  kind: ManifestKind,
  createdAt: string,
  action: string,
  options: { readonly exclusive: boolean; readonly identity?: IdentityCheck | undefined }
): Promise<RunBinding> {
  const databaseId = await databaseIdentity(payload, {
    create: true,
    action,
    check: options.identity,
  })
  if (databaseId === null) {
    throw new Error(`${action}: could not record this database's migration id`)
  }
  if (options.exclusive) {
    // A run known to hold nothing (its pass aborted before writing)
    // blocks nothing; one that may hold rows — or is still running —
    // does.
    const open = (await openRuns(payload, databaseId, action)).filter(holdsEntries)
    if (open.length > 0) {
      throw new Error(
        `another migration run is still open on this database (${describeRuns(open)}): finish it first — resume it with its manifest (--manifest), roll it back, or finalize it. Two open runs would each hold rows the other's rollback or finalize cannot see. Nothing was written. If that run's manifest is lost, see "A run whose manifest is lost" in docs/migrating-from-payload-auth.md`
      )
    }
  }
  const runId = newRunId()
  await recordRun(payload, runId, { kind, createdAt, state: 'open', databaseId }, action)
  return { databaseId, runId, createdAt }
}

/**
 * Record how many entries the run's manifest now holds (issue #116),
 * right after the manifest is written: an open run known to hold none
 * never blocks a `finalize`.
 */
export async function recordRunEntries(
  payload: Payload,
  kind: ManifestKind,
  binding: RunBinding,
  entries: number,
  action: string
): Promise<void> {
  await recordRun(
    payload,
    binding.runId,
    {
      kind,
      createdAt: binding.createdAt,
      state: 'open',
      databaseId: binding.databaseId,
      entries,
    },
    action
  )
}

/**
 * A pass that aborted before writing anything (issue #116): a FRESH
 * run is closed — it holds nothing and has no manifest, so leaving it
 * open would only clutter the database's record — while a resumed run
 * stays open with the entries it carried.
 */
export async function closeAbortedPass(
  payload: Payload,
  kind: ManifestKind,
  binding: RunBinding,
  carried: ImportManifest | null,
  action: string
): Promise<void> {
  if (carried !== null) {
    await recordRunEntries(
      payload,
      kind,
      binding,
      carried.created.length + carried.fieldWrites.length,
      action
    )
    return
  }
  await recordRun(
    payload,
    binding.runId,
    {
      kind,
      createdAt: binding.createdAt,
      state: 'rolled-back',
      databaseId: binding.databaseId,
      entries: 0,
    },
    action
  )
}

/**
 * Refuse a `finalize` while ANOTHER open run may hold rows (issue
 * #116): the finalize marker blocks every later rollback on this
 * database, so finalizing an empty run would strand the rows of the
 * run that holds them.
 */
export async function assertNoOtherRowBearingRun(
  payload: Payload,
  databaseId: string,
  runId: string | null,
  action: string
): Promise<void> {
  const others = (await openRuns(payload, databaseId, action)).filter(
    (run) => run.runId !== runId && holdsEntries(run)
  )
  if (others.length > 0) {
    throw new Error(
      `another migration run is still open on this database and may hold rows (${describeRuns(others)}): finalizing would block its rollback for good. Finalize or roll back THAT run (with its manifest) first; nothing was changed`
    )
  }
}

/** What an `--apply` pass builds on. */
export type OpenedRun = {
  /** The earlier manifest whose entries this pass merges, or `null` (a fresh run). */
  readonly carried: ImportManifest | null
  /** The run this pass writes (`null` on a dry run). */
  readonly binding: RunBinding | null
}

/**
 * Decide what an `--apply` (import or `adopt-prelink`) builds on, and
 * refuse — before anything is written — every manifest it must not
 * resume:
 *
 * - another command's manifest, an edited one, a finalized one;
 * - an unsigned or 0.6.0 manifest (terminal: roll it back or finalize);
 * - one holding plaintext prior values (only a pre-0.6.0 manifest
 *   writes them; a signed manifest carrying any was laundered by an
 *   earlier resume);
 * - created rows outside the kit's own targets;
 * - a version-4 manifest from another database, or whose run this
 *   database does not hold open. A run the database records as rolled
 *   back starts FRESH: the manifest's entries are not carried;
 * - a 0.7.0 (unbound) manifest without `allowUnboundManifest`, or on a
 *   database that records a finalized migration;
 * - a FRESH run while another run is open (issue #116);
 * - a database whose migration record was copied from another one
 *   (GHSA-xw9m-ph95-84rx; see `databaseIdentity`).
 *
 * A dry run only authenticates the manifest.
 */
export async function openRun(options: {
  readonly payload: Payload
  readonly manifest: ImportManifest | null
  readonly kind: ManifestKind
  readonly apply: boolean
  readonly slugs: TargetSlugMap
  readonly now: () => Date
  readonly log: (message: string) => void
  readonly allowUnsignedManifest?: boolean | undefined
  readonly allowUnboundManifest?: boolean | undefined
  /** How this environment identifies itself (clone detection). */
  readonly identity?: IdentityCheck | undefined
}): Promise<OpenedRun> {
  const { payload, manifest, kind, apply, log, identity } = options
  const action = kind === 'import' ? 'from-payload-auth --apply' : 'adopt-prelink --apply'
  const fresh = (createdAt: string): Promise<RunBinding> =>
    startRun(payload, kind, createdAt, action, { exclusive: true, identity })
  if (manifest === null) {
    return {
      carried: null,
      binding: apply ? await fresh(options.now().toISOString()) : null,
    }
  }
  if ((manifest.kind ?? 'import') !== kind) {
    throw new Error(
      `the manifest belongs to ${manifest.kind ?? 'import'}, not ${kind} — pass a different --manifest`
    )
  }
  const trust: ManifestTrust = authenticateManifest(payload.secret, manifest, {
    allowUnsigned: options.allowUnsignedManifest,
  })
  if (!apply) {
    return { carried: manifest, binding: null }
  }
  if (trust !== 'signed') {
    throw new Error(
      `the manifest is ${trust === 'unsigned' ? 'unsigned (written before 0.6.0)' : 'signed by migrate 0.6.0, whose signature does not cover finalized'}: such a manifest is never resumed or re-signed. Roll it back (rollback --allow-unsigned-manifest) or finalize it, or pass a different --manifest for a new run; nothing was written`
    )
  }
  if (manifest.finalized) {
    throw new Error(
      kind === 'import'
        ? 'the migration is finalized; a finalized manifest is not resumed — keep it as the record, and pass a different --manifest for a new run'
        : 'the pre-link is finalized; nothing to pre-link'
    )
  }
  if (plaintextWrites(manifest) > 0) {
    throw new Error(
      'the manifest holds plaintext prior values (a pre-0.6.0 manifest resumed by an older kit): it is never resumed. Roll it back (with --allow-plaintext-restore after reviewing them) or finalize it; nothing was written'
    )
  }
  assertCreatedRowsScoped(
    kind === 'adopt-prelink' ? { ...manifest, kind: 'adopt-prelink' } : manifest,
    options.slugs
  )
  if (isBound(manifest)) {
    const run = await boundRun(payload, manifest, action, identity)
    if (run.state === 'finalized') {
      throw new Error(
        kind === 'import'
          ? 'the database records this migration as finalized; a finalized run is not resumed — pass a different --manifest for a new run'
          : 'the database records this pre-link as finalized; nothing to pre-link'
      )
    }
    if (run.state === 'rolled-back') {
      log(
        'the manifest names a run this database records as rolled back: starting a fresh run (none of its entries are carried)'
      )
      // A fresh run — refused while another run is open (issue #116:
      // a stale manifest must not open a second run beside the live one).
      return { carried: null, binding: await fresh(options.now().toISOString()) }
    }
    return {
      carried: manifest,
      binding: {
        databaseId: manifest.databaseId,
        runId: manifest.runId,
        createdAt: manifest.createdAt,
      },
    }
  }
  // A fully signed 0.7.0 manifest: genuine, but it names no database.
  if (options.allowUnboundManifest !== true) {
    throw new Error(
      'the manifest was written by migrate 0.7.0 or earlier and names no database, so it cannot prove it belongs to THIS one. If it was written against this database by this run, re-run with --allow-unbound-manifest (the resume binds it to this database); otherwise pass a different --manifest'
    )
  }
  await assertNoFinalizeMarker(payload, action)
  return { carried: manifest, binding: await fresh(manifest.createdAt) }
}
