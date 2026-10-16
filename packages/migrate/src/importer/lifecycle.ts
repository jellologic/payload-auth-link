import { existsSync, readFileSync } from 'node:fs'
import { writePrivateFile } from '../private-file.js'
import type { Payload } from 'payload'
import { restoreCaptured } from './host-writes.js'
import {
  defaultTargetSlugs,
  resolveSourceTables,
  sourceModelNames,
  type ResolvedSourceTables,
  type ImportManifest,
} from './types.js'

/**
 * Manifest lifecycle (issue #50): `verify` checks both sides, `rollback`
 * undoes exactly what the manifest records, and `finalize` marks the
 * manifest so the source tables may be dropped — by the operator, as a
 * separate later step.
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
  if (version !== 1 && version !== 2) {
    throw new Error(`manifest at ${path} is not a version-1/2 import manifest`)
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
      const roles = record['roles']
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
        `${roleMismatchDocs} host doc(s) missing stored role values`
      )
    } else if (sourceTables['users_role'] !== null && users.some((user) => user.roles.length > 0)) {
      checks.push({
        name: 'source roles carried onto the host docs (skipped: the host users carry no roles field)',
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

/**
 * Rollback (issue #50): delete the created rows in reverse order and
 * restore every captured field value. The manifest records exactly
 * what to undo — nothing else is touched, and the source tables were
 * never modified.
 */
export async function rollbackImport(options: {
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
}): Promise<{ deleted: number; restored: number }> {
  const { payload, manifest, log = () => {} } = options
  if (manifest.finalized) {
    // The point of no return: after `finalize`, the manifest's rows are
    // the migration's history, not a TODO to undo.
    throw new Error('the migration is finalized; rollback is no longer possible')
  }
  let deleted = 0
  for (const row of [...manifest.created].reverse()) {
    try {
      await payload.delete({ collection: row.collection, id: row.id, overrideAccess: true })
      deleted += 1
    } catch {
      // Already gone (a crash after delete, a manual cleanup) — the
      // goal state is "row absent", so absence is success.
      log(`rollback: ${row.collection}#${row.id} already absent`)
    }
  }
  // Captured values go back through the adapter, one write per
  // document, `updatedAt` included — see host-writes.ts for why.
  const restored = await restoreCaptured(payload, manifest)
  if (options.manifestPath !== undefined) {
    const reset: ImportManifest = {
      ...manifest,
      version: 2,
      created: [],
      fieldWrites: [],
      totals: {},
      rolledBackAt: (options.now ?? (() => new Date()))().toISOString(),
    }
    writeManifest(reset, options.manifestPath)
  }
  log(`rollback: ${deleted} row(s) deleted, ${restored} field value(s) restored`)
  return { deleted, restored }
}

/** Finalize (issue #50): the point of no return — mark the manifest. */
export function finalizeManifest(manifest: ImportManifest, path: string): ImportManifest {
  if (manifest.finalized) {
    return manifest
  }
  const finalized: ImportManifest = { ...manifest, finalized: true }
  writeManifest(finalized, path)
  return finalized
}
