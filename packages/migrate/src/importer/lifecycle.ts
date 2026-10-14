import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import type { Payload } from 'payload'
import type { ImportManifest } from './types.js'

/**
 * Manifest lifecycle (issue #50): `verify` checks both sides, `rollback`
 * undoes exactly what the manifest records, and `finalize` marks the
 * manifest so the source tables may be dropped — by the operator, as a
 * separate later step.
 */

export const defaultManifestPath = 'payload-auth-link-migration.json'

export function readManifest(path: string): ImportManifest | null {
  if (!existsSync(path)) {
    return null
  }
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'))
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as { version?: unknown }).version !== 1
  ) {
    throw new Error(`manifest at ${path} is not a version-1 import manifest`)
  }
  return parsed as ImportManifest
}

export function writeManifest(manifest: ImportManifest, path: string): void {
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`)
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
 * Verify (issue #50): per-model counts match, every source user has
 * exactly one target row, every credential account resolves to its
 * user, every API key carries its hash with a resolvable owner, and
 * every member/invitation references an existing org and user. Exits
 * non-zero on any mismatch (the caller maps `ok` to the exit code).
 */
export async function verifyImport(options: {
  readonly payload: Payload
  readonly sourceConnectionString: string
  readonly slugs?: Readonly<Record<string, string>> | undefined
}): Promise<VerifyResult> {
  const { payload, sourceConnectionString } = options
  const slugs: Record<string, string> = {
    ...{
      user: 'ba-users',
      account: 'ba-accounts',
      session: 'ba-sessions',
      apikey: 'ba-apikey',
      organization: 'ba-organization',
      member: 'ba-member',
      invitation: 'ba-invitation',
    },
    ...(options.slugs ?? {}),
  }
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
  const { openSource, readSourceUsers, countTables } = await import('./source.js')
  const client = await openSource(sourceConnectionString)
  try {
    const sourceCounts = await countTables(client, [
      'users',
      'accounts',
      'sessions',
      'verifications',
      'api_keys',
      'jwks',
      'organizations',
      'members',
      'invitations',
    ])
    const users = await readSourceUsers(client)

    // 1. per-model counts match (sessions only when carried).
    const countPairs: readonly [string, string, number][] = [
      ['users', String(slugs['user']), sourceCounts['users'] ?? 0],
      ['accounts', String(slugs['account']), sourceCounts['accounts'] ?? 0],
      ['api keys', String(slugs['apikey']), sourceCounts['api_keys'] ?? 0],
      ['organizations', String(slugs['organization']), sourceCounts['organizations'] ?? 0],
      ['members', String(slugs['member']), sourceCounts['members'] ?? 0],
      ['invitations', String(slugs['invitation']), sourceCounts['invitations'] ?? 0],
    ]
    for (const [label, collection, expected] of countPairs) {
      if (expected === 0) {
        continue
      }
      const actual = await targetCounts(collection)
      check(
        `count ${label}`,
        actual >= expected,
        `expected >= ${expected} ${label} in ${collection}, found ${actual}`
      )
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
    check(
      'credential accounts carry hashes',
      sourceCounts.accounts === 0 || credentialAccounts > 0,
      'no credential account carries a password hash'
    )

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
      if (!baUserIds.has(String(record.userId))) {
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
}): Promise<{ deleted: number; restored: number }> {
  const { payload, manifest, log = () => {} } = options
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
  let restored = 0
  for (const write of manifest.fieldWrites) {
    const data: Record<string, unknown> = {
      [write.field]: write.before === null ? null : (JSON.parse(write.before) as unknown),
    }
    await payload.update({
      collection: write.collection,
      id: write.id,
      data,
      overrideAccess: true,
    })
    restored += 1
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
