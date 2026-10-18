import { existsSync, readFileSync } from 'node:fs'
import { writePrivateFile } from '../private-file.js'
import type { Payload } from 'payload'
import { boundRun, plaintextWrites, startRun, type RunBinding } from './binding.js'
import {
  assertCreatedRowsScoped,
  assertNoFinalizeMarker,
  baIdMismatch,
  expectedBaId,
  hostRolesField,
  recordFinalizeMarker,
  recordRun,
  targetSlugsOf,
} from './guards.js'
import { restoreCaptured } from './host-writes.js'
import { authenticateManifest, isBound, signManifest } from './manifest-mac.js'
import {
  defaultTargetSlugs,
  type CreatedRow,
  resolveSourceTables,
  sourceModelNames,
  type ResolvedSourceTables,
  type ImportManifest,
} from './types.js'

/**
 * Manifest lifecycle (issue #50): `verify` checks both sides, `rollback`
 * undoes exactly what the manifest records, and `finalize` records the
 * point of no return (a database marker plus the re-signed manifest) so
 * the source tables may be dropped — by the operator, as a separate
 * later step.
 */

/**
 * The importer's default manifest location: the CURRENT WORKING
 * DIRECTORY. Pass `--manifest` to put it somewhere access-controlled;
 * it holds ids and sealed values only (no emails in the clear) and is
 * written with mode 0600. Keep it until `finalize` + your soak period
 * ends, then delete it (docs/migrating-from-payload-auth.md).
 */
export const defaultManifestPath = 'payload-auth-link-migration.json'

/** The `adopt-prelink` default manifest location (cwd; same rules). */
export const defaultPrelinkManifestPath = 'payload-auth-link-prelink.json'

export function readManifest(path: string): ImportManifest | null {
  if (!existsSync(path)) {
    return null
  }
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'))
  const version =
    typeof parsed === 'object' && parsed !== null
      ? (parsed as { version?: unknown }).version
      : undefined
  if (version !== 1 && version !== 2 && version !== 3 && version !== 4) {
    throw new Error(`manifest at ${path} is not a version-1/2/3/4 import manifest`)
  }
  return parsed as ImportManifest
}

/**
 * Write the manifest owner-read/write only (0600, issue #88) — on
 * create AND on every rewrite, so a manifest created by an older kit
 * is tightened too.
 */
export function writeManifest(manifest: ImportManifest, path: string): void {
  writePrivateFile(path, `${JSON.stringify(manifest, null, 2)}\n`)
}

export type VerifyIssue = {
  readonly code: string
  readonly detail: string
}

export type VerifyResult = {
  readonly ok: boolean
  readonly issues: readonly VerifyIssue[]
  readonly checks: readonly { readonly name: string; readonly passed: boolean }[]
}

/**
 * `verify` checks an IMPORT: source rows against the `ba-*` copies the
 * importer keyed by `baId`. An adopt-mode app (issue #113) copies
 * nothing — its Better Auth models ARE the payload-auth tables — so
 * there is nothing for it to compare. Say so, instead of the misleading
 * "declares none of the target collections" / "baId cannot be queried".
 */
export const verifyAdoptUnsupported =
  'verify checks an IMPORT (the ba-* copies keyed by baId), and this config serves Better Auth in ADOPT mode: nothing was copied, so there is nothing for verify to compare. Verify an adopt cutover with the checksum procedure in docs/migrating-from-payload-auth.md ("Verifying an adopt cutover"), and adopt-prelink with its dry run (it reports every user as already linked)'

/**
 * Verify (issues #50, #68, #69): fail closed on the source layout
 * (the probe runs first), per-model counts match EXACTLY (zero never
 * skips; every mapped model is either counted or explicitly
 * null-mapped), every source user has exactly one target row, every
 * imported user resolves through exactly one `better-auth` identity
 * pointing at their ba-users id, every credential account resolves to
 * its user, every API key carries its hash with a resolvable owner,
 * and every member/invitation references an existing org and user.
 * Exits non-zero on any mismatch (the caller maps `ok` to the exit
 * code).
 */
export async function verifyImport(options: {
  readonly payload: Payload
  readonly sourceConnectionString: string
  readonly slugs?: Readonly<Record<string, string>> | undefined
  /** Model → source table map (issue #68); defaults to the default layout. */
  readonly sourceTables?: Readonly<Record<string, string | null>> | undefined
  /** Whether the import carried sessions; `drop` skips the session count. */
  readonly sessions?: 'carry' | 'drop' | undefined
  /** Injectable clock: what counts as an expired source session. */
  readonly now?: (() => Date) | undefined
}): Promise<VerifyResult> {
  const { payload, sourceConnectionString } = options
  const slugs: Record<string, string> = {
    ...defaultTargetSlugs,
    ...(options.slugs ?? {}),
  }
  const sourceTables: ResolvedSourceTables = resolveSourceTables(options.sourceTables)
  const sessions = options.sessions ?? 'carry'
  const issues: VerifyIssue[] = []
  const checks: { name: string; passed: boolean }[] = []
  // Adopt mode (issue #113): the user target carries no baId — nothing
  // was imported, so nothing is compared.
  const userTarget = payload.collections[String(slugs['user'])]
  if (
    userTarget === undefined ||
    !userTarget.config.flattenedFields.some((field) => field.name === 'baId')
  ) {
    return {
      ok: false,
      issues: [{ code: 'verify-adopt-unsupported', detail: verifyAdoptUnsupported }],
      checks,
    }
  }
  const check = (name: string, passed: boolean, detail?: string): void => {
    checks.push({ name, passed })
    if (!passed && detail !== undefined) {
      issues.push({ code: 'verify-mismatch', detail })
    }
  }

  const targetCounts = async (collection: string): Promise<number> => {
    const counted = await payload.count({ collection, overrideAccess: true })
    return counted.totalDocs
  }

  // Source side, read directly.
  const { openSource, probeSourceLayout, readSourceUsers, countTables } =
    await import('./source.js')
  const client = await openSource(sourceConnectionString)
  try {
    // Fail closed (issue #68): a missing mapped table or column aborts
    // the check with an actionable report instead of reading zeros.
    const probe = await probeSourceLayout(client, sourceTables)
    if (probe.length > 0) {
      for (const issue of probe) {
        issues.push({ code: 'source-table-missing', detail: issue.reason })
      }
      return { ok: false, issues, checks }
    }
    const sourceCounts = await countTables(
      client,
      sourceModelNames.map((model) => sourceTables[model]).filter((t): t is string => t !== null)
    )
    const users = await readSourceUsers(client, sourceTables)

    // 1. per-model counts match EXACTLY (issue #68) — zero never skips.
    // A null-mapped model is recorded as skipped-by-config, visibly.
    const countPairs: readonly {
      readonly label: string
      readonly table: string | null
      readonly collection: string
    }[] = [
      { label: 'users', table: sourceTables['users'], collection: String(slugs['user']) },
      { label: 'accounts', table: sourceTables['accounts'], collection: String(slugs['account']) },
      {
        label: 'verifications',
        table: sourceTables['verifications'],
        collection: String(slugs['verification']),
      },
      { label: 'api keys', table: sourceTables['api_keys'], collection: String(slugs['apikey']) },
      { label: 'jwks', table: sourceTables['jwks'], collection: String(slugs['jwks']) },
      {
        label: 'organizations',
        table: sourceTables['organizations'],
        collection: String(slugs['organization']),
      },
      { label: 'members', table: sourceTables['members'], collection: String(slugs['member']) },
      {
        label: 'invitations',
        table: sourceTables['invitations'],
        collection: String(slugs['invitation']),
      },
    ]
    for (const pair of countPairs) {
      if (pair.table === null) {
        checks.push({
          name: `count ${pair.label} (skipped: null-mapped — not installed on the source)`,
          passed: true,
        })
        continue
      }
      const expected = sourceCounts[pair.table] ?? 0
      const actual = await targetCounts(pair.collection)
      check(
        `count ${pair.label}`,
        actual === expected,
        `expected exactly ${expected} ${pair.label} in ${pair.collection}, found ${actual}`
      )
    }
    if (sessions === 'drop') {
      checks.push({
        name: 'count sessions (skipped: the import dropped them)',
        passed: true,
      })
    } else if (sourceTables['sessions'] === null) {
      checks.push({
        name: 'count sessions (skipped: null-mapped — not installed on the source)',
        passed: true,
      })
    } else {
      // Sessions are LIVE data after go-live (issue #88): sign-ins add
      // ba-sessions rows, and Better Auth deletes expired rows when a
      // lookup meets them. So the check is scoped to the IMPORTED rows
      // (deterministic `sess-<source id>` baIds): every unexpired source
      // session must be present; sessions created after cutover and
      // expired sessions already cleaned up are reported, never failed.
      const nowMs = (options.now ?? (() => new Date()))().getTime()
      const sourceSessions = await client.query(
        `SELECT id, expires_at FROM ${sourceTables['sessions']}`
      )
      const target = await payload.find({
        collection: String(slugs['session']),
        depth: 0,
        pagination: false,
        overrideAccess: true,
        select: { baId: true },
      })
      const targetBaIds = new Set(
        target.docs.map((doc) => String((doc as Record<string, unknown>)['baId']))
      )
      let missingLive = 0
      let cleanedExpired = 0
      const imported = new Set<string>()
      for (const row of sourceSessions.rows as { id: unknown; expires_at: unknown }[]) {
        const baId = `sess-${String(row.id)}`
        imported.add(baId)
        if (targetBaIds.has(baId)) {
          continue
        }
        const expires = row.expires_at instanceof Date ? row.expires_at.getTime() : Number.NaN
        if (Number.isFinite(expires) && expires <= nowMs) {
          cleanedExpired += 1
        } else {
          missingLive += 1
        }
      }
      const created = [...targetBaIds].filter((baId) => !imported.has(baId)).length
      check(
        'imported sessions present (unexpired source sessions)',
        missingLive === 0,
        `${missingLive} unexpired source session(s) missing from ${String(slugs['session'])}`
      )
      checks.push({
        name: `sessions after cutover (info): ${created} created since the import, ${cleanedExpired} expired imported session(s) already cleaned up`,
        passed: true,
      })
    }

    // 2. every source user has exactly one target row and its host doc.
    let userMatches = 0
    let userIssues = 0
    for (const user of users) {
      const found = await payload.find({
        collection: String(slugs['user']),
        where: { baId: { equals: user.id } },
        limit: 2,
        depth: 0,
        pagination: false,
        overrideAccess: true,
      })
      if (found.totalDocs !== 1) {
        userIssues += 1
        continue
      }
      userMatches += 1
    }
    check(
      'each source user has exactly one target row',
      userIssues === 0,
      `${userIssues} user(s) without exactly one ${String(slugs['user'])} row`
    )
    void userMatches

    // 2b. every imported user resolves through EXACTLY ONE better-auth
    // identity pointing at their ba-users id (issue #69) — that is the
    // lookup findByProviderIdentity issues on the next provider
    // sign-in. The host docs also carry the stored roles (issue #68's
    // users_role accounting) whenever the host declares the field.
    // The roles field the app configured on authLink (issue #110: a
    // hard-coded `roles` silently skipped the check on `role` layouts).
    const rolesField = hostRolesField(payload)
    let identityIssues = 0
    let roleMismatchDocs = 0
    let hostDocsWithRoles = 0
    for (const user of users) {
      const hostId = Number(user.id)
      if (!Number.isSafeInteger(hostId)) {
        identityIssues += 1
        continue
      }
      let doc: unknown
      try {
        doc = await payload.findByID({
          collection: 'users',
          id: hostId,
          depth: 0,
          overrideAccess: true,
        })
      } catch {
        identityIssues += 1
        continue
      }
      if (typeof doc !== 'object' || doc === null) {
        identityIssues += 1
        continue
      }
      const record = doc as Record<string, unknown>
      const identities = Array.isArray(record['identities'])
        ? (record['identities'] as readonly unknown[])
        : []
      const resolving = identities.filter(
        (entry) =>
          typeof entry === 'object' &&
          entry !== null &&
          (entry as Record<string, unknown>)['providerId'] === 'better-auth' &&
          String((entry as Record<string, unknown>)['providerUserId']) === String(user.id)
      )
      if (identities.length !== 1 || resolving.length !== 1) {
        identityIssues += 1
      }
      const roles = record[rolesField]
      if (Array.isArray(roles)) {
        hostDocsWithRoles += 1
        const stored = new Set(roles.map((role) => String(role)))
        if (!user.roles.every((role) => stored.has(role))) {
          roleMismatchDocs += 1
        }
      }
    }
    check(
      'every imported user resolves through one better-auth identity',
      identityIssues === 0,
      `${identityIssues} user(s) without exactly one better-auth identity resolving to their ba-users id`
    )
    if (hostDocsWithRoles > 0) {
      check(
        'source roles carried onto the host docs',
        roleMismatchDocs === 0,
        `${roleMismatchDocs} host doc(s) missing stored role values in '${rolesField}'`
      )
    } else if (sourceTables['users_role'] !== null && users.some((user) => user.roles.length > 0)) {
      checks.push({
        name: `source roles carried onto the host docs (skipped: the host users carry no '${rolesField}' field)`,
        passed: true,
      })
    }

    // 3. every credential account resolves to its user.
    const accounts = await payload.find({
      collection: String(slugs['account']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    const baUserIds = new Set<string>()
    const baUsers = await payload.find({
      collection: String(slugs['user']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    for (const doc of baUsers.docs) {
      baUserIds.add(String((doc as Record<string, unknown>).baId))
    }
    let orphanAccounts = 0
    let credentialAccounts = 0
    for (const doc of accounts.docs) {
      const record = doc as Record<string, unknown>
      if (!baUserIds.has(String(record.userId))) {
        orphanAccounts += 1
      }
      if (record.providerId === 'credential') {
        credentialAccounts += 1
        if (typeof record.password !== 'string' || record.password === '') {
          orphanAccounts += 1
        }
      }
    }
    check(
      'every account resolves to its user (credential hashes intact)',
      orphanAccounts === 0,
      `${orphanAccounts} account(s) with a missing user or empty credential hash`
    )
    const sourceAccountsCount =
      sourceTables['accounts'] === null ? 0 : (sourceCounts[sourceTables['accounts']] ?? 0)
    check(
      'credential accounts carry hashes',
      sourceAccountsCount === 0 || credentialAccounts > 0,
      'no credential account carries a password hash'
    )

    // 3b. bans carried (issue #88): a banned source user stays banned.
    // The importer refuses to run when banned users exist and the
    // target declares no `banned` field, so here the field is present
    // whenever it matters.
    const bannedSource = users.filter((user) => user.banned === true)
    if (bannedSource.length > 0) {
      let notBanned = 0
      for (const user of bannedSource) {
        const found = await payload.find({
          collection: String(slugs['user']),
          where: { baId: { equals: user.id } },
          limit: 1,
          depth: 0,
          overrideAccess: true,
        })
        const doc = found.docs[0] as Record<string, unknown> | undefined
        if (doc?.['banned'] !== true) {
          notBanned += 1
        }
      }
      check(
        'banned source users stay banned',
        notBanned === 0,
        `${notBanned} banned source user(s) are not banned on ${String(slugs['user'])}`
      )
    }

    // 4. API keys: hash present, owner resolves, rate-limit state kept.
    const keys = await payload.find({
      collection: String(slugs['apikey']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    let brokenKeys = 0
    for (const doc of keys.docs) {
      const record = doc as Record<string, unknown>
      if (typeof record.key !== 'string' || record.key === '') {
        brokenKeys += 1
        continue
      }
      // The satellite's user reference is `referenceId` on BA 1.7's own
      // schema and `userId` in 1.6-era layouts.
      const owner = record.referenceId ?? record.userId
      if (!baUserIds.has(String(owner))) {
        brokenKeys += 1
      }
    }
    check(
      'every API key carries its hash and resolves to a user',
      brokenKeys === 0,
      `${brokenKeys} API key(s) without a hash or user`
    )

    // 5. members/invitations reference existing orgs and users.
    const orgIds = new Set<string>()
    const orgs = await payload.find({
      collection: String(slugs['organization']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    for (const doc of orgs.docs) {
      orgIds.add(String((doc as Record<string, unknown>).baId))
    }
    const members = await payload.find({
      collection: String(slugs['member']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    let brokenMembers = 0
    for (const doc of members.docs) {
      const record = doc as Record<string, unknown>
      if (!orgIds.has(String(record.organizationId)) || !baUserIds.has(String(record.userId))) {
        brokenMembers += 1
      }
    }
    check(
      'every member references an existing org and user',
      brokenMembers === 0,
      `${brokenMembers} member(s) with dangling references`
    )
    const invitations = await payload.find({
      collection: String(slugs['invitation']),
      limit: 1000,
      depth: 0,
      pagination: false,
      overrideAccess: true,
    })
    let brokenInvitations = 0
    for (const doc of invitations.docs) {
      const record = doc as Record<string, unknown>
      if (!orgIds.has(String(record.organizationId))) {
        brokenInvitations += 1
      }
    }
    check(
      'every invitation references an existing org',
      brokenInvitations === 0,
      `${brokenInvitations} invitation(s) with dangling references`
    )
  } finally {
    await client.end()
  }

  return { ok: issues.length === 0, issues, checks }
}

/** Options of {@link rollbackImport}. */
export type RollbackOptions = {
  readonly payload: Payload
  readonly manifest: ImportManifest
  readonly log?: (message: string) => void
  /**
   * When given, the manifest at this path is RESET after a successful
   * rollback (issue #88): no created rows, no field writes, no totals —
   * so a later `--apply` starts from the restored state instead of
   * building on stale entries.
   */
  readonly manifestPath?: string | undefined
  readonly now?: (() => Date) | undefined
  /** Target slugs the import ran with (`--slugs`); defaults to the ba-* set. */
  readonly slugs?: Readonly<Record<string, string>> | undefined
  /**
   * Accept a manifest without a full signature (`--allow-unsigned-manifest`):
   * a pre-0.6.0 manifest without a MAC, or a 0.6.0 manifest whose MAC
   * does not cover `finalized`. The operator vouches that nobody edited
   * it and that it was written against THIS database.
   */
  readonly allowUnsignedManifest?: boolean | undefined
  /**
   * Let a rollback driven by an UNSIGNED (pre-0.6.0) manifest delete the
   * rows it lists (`--allow-unsigned-deletes`). Without it, an unsigned
   * manifest may only restore sealed field values.
   */
  readonly allowUnsignedDeletes?: boolean | undefined
  /**
   * Restore version-1 PLAINTEXT prior values (`--allow-plaintext-restore`,
   * GHSA-crrr-3cg7-f6jw). Nothing vouches for a value stored in the
   * clear — not even a signature an older kit added when it resumed the
   * manifest — so the operator reviews them and opts in separately.
   */
  readonly allowPlaintextRestore?: boolean | undefined
  /**
   * Accept a fully signed manifest written by migrate 0.7.0 or earlier,
   * which names no database (`--allow-unbound-manifest`): the operator
   * vouches it was written against THIS database.
   */
  readonly allowUnboundManifest?: boolean | undefined
}

/**
 * Rollback (issue #50): delete the created rows in reverse order and
 * restore every captured field value. The manifest records exactly
 * what to undo — nothing else is touched, and the source tables were
 * never modified.
 *
 * Before anything is written, rollback refuses: a finalized manifest,
 * or a database that records ANY finalized migration (the marker
 * `finalize` writes — whatever kind the manifest claims; GHSA-crrr);
 * a key-value store it cannot read (fail closed); a manifest that
 * fails its signature; a version-4 manifest naming another database,
 * or a run this database does not hold open; a 0.7.0 manifest (no
 * database binding) without `allowUnboundManifest`; created rows
 * outside the import's own target collections (signed or not), or
 * whose row no longer carries the importer's deterministic `baId`;
 * any delete driven by an unsigned manifest without
 * `allowUnsignedDeletes`; and any plaintext prior value without
 * `allowPlaintextRestore`. A row already absent is fine (the goal is
 * "absent"); a delete that FAILS (a foreign key, a hook, a permission)
 * aborts the rollback with the rows named, before any field is
 * restored or the manifest reset — so it can be re-run once fixed.
 * Success records the run as rolled back in the database, so no copy
 * of this manifest drives a second rollback.
 */
export async function rollbackImport(
  options: RollbackOptions
): Promise<{ deleted: number; restored: number }> {
  const { payload, manifest, log = () => {} } = options
  const now = options.now ?? (() => new Date())
  if (manifest.finalized) {
    // The point of no return: after `finalize`, the manifest's rows are
    // the migration's history, not a TODO to undo.
    throw new Error('the migration is finalized; rollback is no longer possible')
  }
  // Every row below is deleted, and every field restored, with
  // overrideAccess: only a manifest this app signed may drive that.
  const trust = authenticateManifest(payload.secret, manifest, {
    allowUnsigned: options.allowUnsignedManifest,
  })
  if (trust === 'signed-legacy' && options.allowUnsignedManifest !== true) {
    throw new Error(
      "the manifest was signed by migrate 0.6.0, whose signature does not cover the 'finalized' flag. If you are sure this migration was never finalized and nobody has edited the manifest, re-run with --allow-unsigned-manifest"
    )
  }
  // The database's own record of `finalize`, independent of the file —
  // ANY finalized migration on this database, and an unreadable store
  // refuses too (GHSA-crrr-3cg7-f6jw).
  await assertNoFinalizeMarker(payload, 'rollback')
  // The database's record of THIS manifest: its database and its run.
  let binding: RunBinding | null = null
  if (isBound(manifest)) {
    const run = await boundRun(payload, manifest, 'rollback')
    if (run.state === 'finalized') {
      throw new Error(
        'the database records this migration as finalized; rollback is no longer possible (the manifest file does not override that)'
      )
    }
    if (run.state === 'rolled-back') {
      if (manifest.created.length === 0 && manifest.fieldWrites.length === 0) {
        log('rollback: the run was already rolled back; nothing to do')
        return { deleted: 0, restored: 0 }
      }
      throw new Error(
        'the database records this run as rolled back: this manifest is a stale copy, and replaying it would restore values captured before later changes. Nothing was changed'
      )
    }
    binding = { databaseId: manifest.databaseId, runId: manifest.runId, createdAt: run.createdAt }
  } else if (trust === 'signed' && options.allowUnboundManifest !== true) {
    throw new Error(
      'the manifest was written by migrate 0.7.0 or earlier and names no database, so it cannot prove it belongs to THIS one (a rehearsal clone sharing PAYLOAD_SECRET would accept it). If it was written against this database, re-run with --allow-unbound-manifest; nothing was changed'
    )
  }
  assertCreatedRowsScoped(manifest, targetSlugsOf(options.slugs))
  const plaintext = plaintextWrites(manifest)
  if (
    trust === 'unsigned' &&
    options.allowUnsignedDeletes !== true &&
    manifest.created.length > 0
  ) {
    throw new Error(
      `the manifest is unsigned: --allow-unsigned-manifest lets it restore sealed field values only, and it lists ${manifest.created.length} row(s) to delete. Review the manifest's created rows, then re-run with --allow-unsigned-deletes as well — nothing was changed`
    )
  }
  if (plaintext > 0 && options.allowPlaintextRestore !== true) {
    throw new Error(
      `the manifest holds ${plaintext} plaintext prior value(s) (written by a pre-0.6.0 kit), which nothing vouches for. Review them, then re-run with --allow-plaintext-restore — nothing was changed`
    )
  }

  // Pre-flight every created row BEFORE the first delete: a present row
  // must still carry the importer's deterministic baId for its source
  // key (the imported row, not one that took its id since).
  const present: CreatedRow[] = []
  const foreign: string[] = []
  let absent = 0
  for (const row of [...manifest.created].reverse()) {
    const doc = await findRow(payload, row)
    if (doc === null) {
      absent += 1
    } else if (baIdMismatch(row, doc)) {
      foreign.push(`${row.collection}#${String(row.id)} (${row.sourceKey})`)
    } else if (trust === 'unsigned' && !(await importedUserProvenance(payload, row))) {
      // An imported user's baId is the source id with NO prefix, so on
      // its own it cannot tell an imported ba-users row from a live
      // one. The importer's users are the host's own documents (the
      // source layout's user id IS the host id): an unsigned manifest
      // may delete a ba-users row only when that host document exists
      // (GHSA-crrr-3cg7-f6jw). Signed manifests' rows are the app's own.
      foreign.push(
        `${row.collection}#${String(row.id)} (${row.sourceKey}: no host document with that id)`
      )
    } else {
      present.push(row)
    }
  }
  if (foreign.length > 0) {
    throw new Error(
      `${foreign.length} created row(s) no longer carry the baId the importer gave them, so they are not the imported rows: ${listSome(foreign, ', ')}. Refusing to delete anything`
    )
  }

  let deleted = 0
  const failed: string[] = []
  for (const row of present) {
    try {
      await payload.delete({ collection: row.collection, id: row.id, overrideAccess: true })
      deleted += 1
    } catch (error) {
      if ((await findRow(payload, row)) === null) {
        // Removed concurrently: the goal state is "row absent".
        absent += 1
        continue
      }
      failed.push(
        `${row.collection}#${String(row.id)}: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
  if (failed.length > 0) {
    for (const line of failed) {
      log(`rollback: FAILED to delete ${line}`)
    }
    throw new Error(
      `rollback deleted ${deleted} row(s) but could not delete ${failed.length}: ${listSome(failed, '; ')}. No field value was restored and the manifest was kept — fix the cause (e.g. rows that reference them) and re-run rollback`
    )
  }
  if (absent > 0) {
    log(`rollback: ${absent} created row(s) were already absent`)
  }
  // Captured values go back through the adapter, one write per
  // document, `updatedAt` included — see host-writes.ts for why.
  const restored = await restoreCaptured(payload, manifest, {
    rolesField: hostRolesField(payload),
    allowPlaintext: options.allowPlaintextRestore === true,
  })
  // The run is closed in the DATABASE: no copy of this manifest drives
  // a second rollback, and the next --apply starts a fresh run. An
  // unbound manifest closes a run minted for the record.
  const kind = manifest.kind ?? 'import'
  const closed: RunBinding =
    binding ?? (await startRun(payload, kind, manifest.createdAt, 'rollback'))
  await recordRun(
    payload,
    closed.runId,
    { kind, createdAt: closed.createdAt, state: 'rolled-back' },
    'rollback'
  )
  if (options.manifestPath !== undefined) {
    const reset: ImportManifest = signManifest(payload.secret, {
      version: 4,
      kind,
      createdAt: closed.createdAt,
      databaseId: closed.databaseId,
      runId: closed.runId,
      sourceDatabase: manifest.sourceDatabase,
      options: manifest.options,
      created: [],
      fieldWrites: [],
      finalized: false,
      sourceCounts: manifest.sourceCounts,
      totals: {},
      rolledBackAt: now().toISOString(),
    })
    writeManifest(reset, options.manifestPath)
  }
  log(`rollback: ${deleted} row(s) deleted, ${restored} field value(s) restored`)
  return { deleted, restored }
}

/**
 * Whether a created `user:` row is provably an imported user: the host
 * `users` document with the source id exists. Rows of every other
 * model carry a model prefix in their `baId`, which live Better Auth
 * rows never have.
 */
async function importedUserProvenance(payload: Payload, row: CreatedRow): Promise<boolean> {
  const expected = expectedBaId(row.sourceKey)
  if (expected === null || expected.model !== 'user') {
    return true
  }
  const hostId = /^\d+$/.test(expected.baId) ? Number(expected.baId) : expected.baId
  const host: unknown = await payload.findByID({
    collection: 'users',
    id: hostId,
    depth: 0,
    overrideAccess: true,
    disableErrors: true,
  })
  return host !== null && host !== undefined
}

/** The created row as stored, or `null` when it does not exist. */
async function findRow(payload: Payload, row: CreatedRow): Promise<unknown> {
  const doc: unknown = await payload.findByID({
    collection: row.collection,
    id: row.id,
    depth: 0,
    overrideAccess: true,
    disableErrors: true,
  })
  return doc ?? null
}

function listSome(items: readonly string[], separator: string): string {
  return `${items.slice(0, 10).join(separator)}${items.length > 10 ? `${separator}…` : ''}`
}

/** Options of {@link finalizeManifest}. */
export type FinalizeOptions = {
  readonly payload: Payload
  readonly manifest: ImportManifest
  /** Where the finalized manifest is written. */
  readonly path: string
  readonly now?: (() => Date) | undefined
  /** Accept a manifest without a full signature (`--allow-unsigned-manifest`). */
  readonly allowUnsignedManifest?: boolean | undefined
}

/**
 * Finalize (issue #50): the point of no return. Records a one-way
 * marker in the target database (Payload's key-value store) that every
 * later rollback checks independently of the file, then marks the
 * manifest `finalized`. A signed manifest is re-signed (the signature
 * covers the flag); a version-4 manifest must name THIS database and a
 * run it does not record as rolled back, and its run is recorded as
 * finalized. An unsigned or 0.6.0 manifest is never re-signed
 * (GHSA-crrr-3cg7-f6jw): its flag is set, and the database marker is
 * what every later command trusts. Idempotent: finalizing a finalized
 * manifest re-records the marker.
 */
export async function finalizeManifest(options: FinalizeOptions): Promise<ImportManifest> {
  const { payload, manifest } = options
  const trust = authenticateManifest(payload.secret, manifest, {
    allowUnsigned: options.allowUnsignedManifest,
  })
  const kind = manifest.kind ?? 'import'
  if (isBound(manifest)) {
    const run = await boundRun(payload, manifest, 'finalize')
    if (run.state === 'rolled-back') {
      throw new Error(
        'the database records this run as rolled back; there is nothing to finalize (run --apply for a new run first)'
      )
    }
  }
  const finalizedAt = manifest.finalizedAt ?? (options.now ?? (() => new Date()))().toISOString()
  // The database marker first: a finalize that cannot record it fails
  // with the manifest unchanged.
  await recordFinalizeMarker(payload, manifest, finalizedAt)
  if (isBound(manifest)) {
    await recordRun(
      payload,
      manifest.runId,
      { kind, createdAt: manifest.createdAt, state: 'finalized' },
      'finalize'
    )
  }
  const flagged: ImportManifest = { ...manifest, finalized: true, finalizedAt }
  const finalized: ImportManifest =
    trust === 'signed' ? signManifest(payload.secret, flagged) : flagged
  writeManifest(finalized, options.path)
  return finalized
}
