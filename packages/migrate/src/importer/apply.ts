import { isRecord } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { assertCreatedRowsScoped, finalizeMarkerState, hostRolesField } from './guards.js'
import { capturedKeys, captureBefore } from './host-writes.js'
import { authenticateManifest, signManifest } from './manifest-mac.js'
import {
  readFlatRows,
  openSource,
  readSourceUsers,
  type SourceRow,
  type SourceUser,
} from './source.js'
import {
  defaultTargetSlugs,
  resolveSourceTables,
  type CreatedRow,
  type ResolvedSourceTables,
  type TargetSlugMap,
  type FieldWrite,
  type ImportManifest,
  type ImportPlan,
  type ImportResult,
  type PlanRow,
  type Unmappable,
} from './types.js'

/**
 * Apply side (issue #50): copy payload-auth rows into the
 * payload-auth-link collections through the Payload Local API.
 *
 * - Password hashes, OAuth tokens, API-key hashes, and jwks carry over
 *   VERBATIM (payload-auth used Better Auth's own hashing).
 * - Row timestamps (`createdAt`/`updatedAt`) carry from the source rows
 *   for every model whose source table has them (issue #88).
 * - Better Auth plugin user state carries (issue #88): admin-plugin
 *   `banned`/`banReason`/`banExpires`/`role` and the anonymous plugin's
 *   `isAnonymous`, whenever the source has the column AND the target
 *   `ba-users` collection declares the field. A banned or anonymous
 *   source user whose state the target cannot hold is UNMAPPABLE — the
 *   run aborts before writing; a banned user never imports unbanned.
 * - `linkable` + `linkableEmail` are granted from VERIFIED emails only
 *   (grant-only: an existing proof is never revoked); unverified users
 *   are reported by the plan, never linked.
 * - Sessions default to `carry` so nobody is logged out: the carried
 *   rows keep their tokens, and with the same `advanced.cookiePrefix`
 *   the existing cookies keep working.
 * - Idempotent and resumable: every target row carries a deterministic
 *   `baId` derived from the source id (`acct-<source id>`), so a
 *   re-run after a crash finds its own earlier rows and skips them.
 * - Every created row and every host field write lands in the
 *   manifest — the FIRST captured prior value per field wins, sealed —
 *   so `rollback` is exact and the source tables stay untouched.
 */

export type ApplyOptions = {
  readonly payload: Payload
  readonly sourceConnectionString: string
  readonly apply: boolean
  readonly sessions: 'carry' | 'drop'
  readonly manifest: ImportManifest | null
  /** Written (merged) on `apply`; required when `apply` is true. */
  readonly manifestPath: string
  readonly sourceCounts: Readonly<Record<string, number>>
  readonly sourceDatabase: string
  /** Target collection slugs; defaults must match the engine wiring. */
  readonly slugs?: Readonly<Record<string, string>> | undefined
  /**
   * Source-side model → table map (issue #68). Defaults to
   * payload-auth's layout; a `null` model is treated as not installed.
   */
  readonly sourceTables?: Readonly<Record<string, string | null>> | undefined
  /** Injectable clock for deterministic `linkedAt` stamps. */
  readonly now?: () => Date
  readonly log?: (message: string) => void
  /** Resume from a pre-0.6.0 manifest that has no MAC (`--allow-unsigned-manifest`). */
  readonly allowUnsignedManifest?: boolean | undefined
}

const slugsOf = (overrides?: Readonly<Record<string, string>>): TargetSlugMap => ({
  ...defaultTargetSlugs,
  ...(overrides ?? {}),
})

function textOrNull(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined
}

function numberOrNull(value: unknown): number | undefined {
  if (value === null || value === undefined) {
    return undefined
  }
  const numeric = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(numeric) ? numeric : undefined
}

/** The source row's timestamps, when its layout has them (issue #88). */
function stamps(row: SourceRow): { createdAt?: string; updatedAt?: string } {
  return {
    ...(row.created_at instanceof Date ? { createdAt: row.created_at.toISOString() } : {}),
    ...(row.updated_at instanceof Date ? { updatedAt: row.updated_at.toISOString() } : {}),
  }
}

const timestampColumns = ['created_at', 'updated_at'] as const

/**
 * Rows for one mapped model. A `null` mapping records the model as
 * not installed (issue #68) — no read, no rows; anything else goes
 * through the strict `readFlatRows` (a missing mapped table throws;
 * the probe aborts the run first). Row timestamps are read when the
 * layout has them.
 */
async function readMapped(
  client: Awaited<ReturnType<typeof openSource>>,
  table: string | null,
  columns: readonly string[]
): Promise<SourceRow[]> {
  return table === null ? [] : readFlatRows(client, table, columns, timestampColumns)
}

/** Field names a target collection declares (top level, flattened). */
function targetFieldNames(payload: Payload, slug: string): ReadonlySet<string> {
  const collection = payload.collections[slug]
  const names = new Set<string>()
  for (const field of collection?.config.flattenedFields ?? []) {
    names.add(field.name)
  }
  return names
}

/**
 * Plugin user state the target must be able to hold (issue #88),
 * checked BEFORE any write: a banned user whose target has no `banned`
 * field would import unbanned; an anonymous user without `isAnonymous`
 * would import as a full account.
 */
export function pluginStateUnmappable(
  users: readonly SourceUser[],
  targetFields: ReadonlySet<string>,
  targetSlug: string
): Unmappable[] {
  const found: Unmappable[] = []
  for (const user of users) {
    if (user.banned === true && !targetFields.has('banned')) {
      found.push({
        model: 'user',
        key: user.id,
        reason: `user #${user.id} is banned on the source, but '${targetSlug}' declares no 'banned' field — add Better Auth's admin() plugin to the engine (autoDeclare derives banned/banReason/banExpires) so the ban carries`,
      })
    }
    if (user.isAnonymous === true && !targetFields.has('isAnonymous')) {
      found.push({
        model: 'user',
        key: user.id,
        reason: `user #${user.id} is anonymous on the source, but '${targetSlug}' declares no 'isAnonymous' field — add Better Auth's anonymous() plugin to the engine, or remove anonymous users before importing`,
      })
    }
  }
  return found
}

/** Plugin user state carried onto the ba-users row (issue #88). */
function pluginUserState(
  user: SourceUser,
  targetFields: ReadonlySet<string>
): Record<string, unknown> {
  const state: Record<string, unknown> = {}
  if (user.banned !== null && targetFields.has('banned')) {
    state.banned = user.banned
  }
  if (user.banReason !== null && targetFields.has('banReason')) {
    state.banReason = user.banReason
  }
  if (user.banExpires !== null && targetFields.has('banExpires')) {
    state.banExpires = user.banExpires.toISOString()
  }
  if (user.isAnonymous !== null && targetFields.has('isAnonymous')) {
    state.isAnonymous = user.isAnonymous
  }
  // Better Auth's admin plugin stores roles as one comma-separated
  // string; payload-auth kept them in the users_role child table.
  if (user.roles.length > 0 && targetFields.has('role')) {
    state.role = user.roles.join(',')
  }
  return state
}

/** Find an existing target row by `baId` — the resumable dedupe key. */
async function findByBaId(payload: Payload, collection: string, baId: string): Promise<boolean> {
  const found = await payload.find({
    collection,
    where: { baId: { equals: baId } },
    limit: 1,
    depth: 0,
    pagination: false,
    overrideAccess: true,
  })
  return found.docs.length > 0
}

/** Create one target row, deduped by its deterministic baId. */
async function createDeduped(
  payload: Payload,
  collection: string,
  baId: string,
  data: Record<string, unknown>,
  created: CreatedRow[],
  sourceKey: string
): Promise<boolean> {
  if (await findByBaId(payload, collection, baId)) {
    return false
  }
  const doc: unknown = await payload.create({
    collection,
    data: { baId, ...data },
    overrideAccess: true,
  })
  if (typeof doc === 'object' && doc !== null && 'id' in doc) {
    const id: unknown = doc['id']
    if (typeof id === 'string' || typeof id === 'number') {
      created.push({ collection, id, sourceKey })
    }
  }
  return true
}

/**
 * The identity rows pre-populated on the host user (issue #69): ONE
 * `better-auth` identity per imported user, `providerUserId` set to
 * the ba-users row this import created for them. The engine-created
 * models key their rows by `baId` and serve Better Auth's own
 * `user.id` from that column, so the value here — the deterministic
 * `baId` derived from the source user id — is exactly what
 * `findByProviderIdentity` queries back
 * (`{ providerId: 'better-auth', providerUserId: <BA user id> }`).
 *
 * Every imported user gets the identity — verified or not,
 * credential-only included: the import itself proves the
 * BA-user↔document binding, so identity resolution never depends on
 * the (verified-only) `linkable` proof, which keeps its current
 * granting below. An unverified user who verifies their email later
 * resolves to their ORIGINAL document on the next sign-in instead of
 * being provisioned a fresh one.
 */
function identityRows(
  user: SourceUser,
  now: () => Date
): { providerId: string; providerUserId: string; email: string; linkedAt: string }[] {
  return [
    {
      providerId: 'better-auth',
      providerUserId: String(user.id),
      email: user.email,
      linkedAt: now().toISOString(),
    },
  ]
}

/** The host user document as stored (depth 0). */
async function hostDoc(payload: Payload, id: number): Promise<Record<string, unknown> | null> {
  const doc: unknown = await payload.findByID({
    collection: 'users',
    id,
    depth: 0,
    overrideAccess: true,
  })
  return isRecord(doc) ? doc : null
}

/** The doc already carries exactly the identity the import writes. */
function hasExactIdentity(doc: Record<string, unknown> | null, user: SourceUser): boolean {
  const identities = doc?.['identities']
  if (!Array.isArray(identities) || identities.length !== 1) {
    return false
  }
  const only: unknown = identities[0]
  return (
    isRecord(only) &&
    only['providerId'] === 'better-auth' &&
    String(only['providerUserId']) === String(user.id) &&
    only['email'] === user.email
  )
}

/** Same stored values, same order. */
function sameValues(stored: unknown, wanted: readonly string[]): boolean {
  return (
    Array.isArray(stored) &&
    stored.length === wanted.length &&
    stored.every((value, index) => String(value) === wanted[index])
  )
}

export async function applyImport(options: ApplyOptions): Promise<ImportResult> {
  const {
    payload,
    sourceConnectionString,
    apply,
    sessions,
    log = () => {},
    now = () => new Date(),
  } = options
  const slugs = slugsOf(options.slugs)
  const sourceTables: ResolvedSourceTables = resolveSourceTables(options.sourceTables)
  if (options.manifest !== null) {
    // Resuming merges the old entries and re-signs them: never launder
    // an edited manifest into a signed one, never sign created rows
    // outside the import's own targets, and never resume a migration
    // the database records as finalized.
    const trust = authenticateManifest(payload.secret, options.manifest, {
      allowUnsigned: options.allowUnsignedManifest,
    })
    assertCreatedRowsScoped(options.manifest, slugs)
    const finalized =
      options.manifest.finalized ||
      (apply &&
        (await finalizeMarkerState(payload, options.manifest, {
          anyOfKind: trust !== 'signed',
        })) === 'finalized')
    if (apply && finalized) {
      throw new Error(
        'the migration is finalized; a finalized manifest is not resumed — keep it as the record, and pass a different --manifest for a new run'
      )
    }
  }
  const rolesField = hostRolesField(payload)
  const created: CreatedRow[] = [...(options.manifest?.created ?? [])]
  const fieldWrites: FieldWrite[] = [...(options.manifest?.fieldWrites ?? [])]
  // First capture wins (issue #88): fields captured by an earlier pass
  // keep their pre-import value.
  const captured = capturedKeys(fieldWrites)
  // Per-PASS totals (issue #88): a re-apply reports what this pass
  // planned, never the sum of every pass.
  const totals: Record<string, number> = {}
  const planRows: PlanRow[] = []
  const unmappable: Unmappable[] = []
  let createdCount = 0
  let skippedCount = 0
  let fieldWriteCount = 0

  const record = (row: PlanRow): void => {
    planRows.push(row)
  }

  const client = await openSource(sourceConnectionString)
  try {
    const users = await readSourceUsers(client, sourceTables)
    const baUserFields = targetFieldNames(payload, slugs.user)

    // --- 0. target-capability gate (issue #88) ---------------------------
    // Runs before ANY write: plugin state the target cannot hold aborts
    // the run instead of importing a banned user unbanned.
    const blocked = pluginStateUnmappable(users, baUserFields, slugs.user)
    if (blocked.length > 0) {
      log(
        `ABORT: ${blocked.length} user(s) carry state the target cannot hold; nothing was written`
      )
      return {
        created: 0,
        skipped: 0,
        fieldWrites: 0,
        plan: { rows: [], unmappable: blocked, sessions, warnings: [] },
      }
    }

    const seenUsers = new Set<string>()

    // --- 1. ba-users + host field writes ---------------------------------
    for (const user of users) {
      const baId = String(user.id)
      if (seenUsers.has(baId)) {
        unmappable.push({ model: 'user', key: baId, reason: 'duplicate source id' })
        continue
      }
      seenUsers.add(baId)
      totals.user = (totals.user ?? 0) + 1
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.user,
            baId,
            {
              email: user.email,
              name: user.name ?? '',
              emailVerified: user.emailVerified,
              ...(user.image === null ? {} : { image: user.image }),
              ...pluginUserState(user, baUserFields),
              createdAt: user.createdAt.toISOString(),
              updatedAt: user.updatedAt.toISOString(),
            },
            created,
            `user:${baId}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
        // Host-side writes on the EXISTING Payload user (the source
        // layout's user id IS the host id): identities, roles, and the
        // verified-email linking proof. The prior values (and the
        // doc's updatedAt) are captured first — once — so rollback
        // restores the pre-import document exactly.
        const hostId = Number(baId)
        if (Number.isSafeInteger(hostId)) {
          // Only the values that DIFFER are written (issue #110): a
          // second --apply over an imported user is a true no-op — no
          // Local API update, so no fresh `updatedAt`, `linkedAt`, or
          // re-created hasMany child rows.
          const current = await hostDoc(payload, hostId)
          const writes: Record<string, unknown> = {}
          if (!hasExactIdentity(current, user)) {
            writes.identities = identityRows(user, now)
          }
          if (
            user.roles.length > 0 &&
            current !== null &&
            rolesField in current &&
            !sameValues(current[rolesField], user.roles)
          ) {
            // Stored role values pass through unchanged (issue #56: the
            // storage edge owns translation; the map is the app's).
            writes[rolesField] = user.roles
          }
          if (
            user.emailVerified &&
            (current?.['linkable'] !== true || current['linkableEmail'] !== user.email)
          ) {
            // Grant-only: the proof is bound to the address (both
            // fields), and an existing proof is never revoked here.
            writes.linkable = true
            writes.linkableEmail = user.email
          }
          if (Object.keys(writes).length > 0) {
            // The prior values (and the doc's updatedAt) are captured
            // first — once — so rollback restores the pre-import doc.
            const { newlyCaptured } = await captureBefore({
              payload,
              collection: 'users',
              id: hostId,
              fields: ['identities', rolesField, 'linkable', 'linkableEmail'],
              captured,
              into: fieldWrites,
            })
            fieldWriteCount += newlyCaptured
            await payload.update({
              collection: 'users',
              id: hostId,
              data: writes,
              overrideAccess: true,
            })
          }
        }
      }
      record({
        model: 'user',
        sourceTable: sourceTables['users'] ?? 'users',
        targetCollection: slugs.user,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
    }

    const tally = (model: string, sourceTable: string, target: string, isNew: boolean): void => {
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model,
        sourceTable,
        targetCollection: target,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
    }

    // --- 2. accounts (hashes verbatim) ------------------------------------
    const accountsTable = sourceTables['accounts']
    for (const user of users) {
      for (const account of user.accounts) {
        totals.account = (totals.account ?? 0) + 1
        const baId = `acct-${account.id}`
        const isNew = apply
          ? await createDeduped(
              payload,
              slugs.account,
              baId,
              {
                accountId: account.accountId,
                providerId: account.providerId,
                userId: String(user.id),
                ...(account.password === null ? {} : { password: account.password }),
                ...(account.accessToken === null ? {} : { accessToken: account.accessToken }),
                ...(account.refreshToken === null ? {} : { refreshToken: account.refreshToken }),
                ...(account.idToken === null ? {} : { idToken: account.idToken }),
                ...(account.scope === null ? {} : { scope: account.scope }),
                ...(account.accessTokenExpiresAt === null
                  ? {}
                  : { accessTokenExpiresAt: account.accessTokenExpiresAt.toISOString() }),
                ...(account.refreshTokenExpiresAt === null
                  ? {}
                  : { refreshTokenExpiresAt: account.refreshTokenExpiresAt.toISOString() }),
                ...(account.createdAt === null
                  ? {}
                  : { createdAt: account.createdAt.toISOString() }),
                ...(account.updatedAt === null
                  ? {}
                  : { updatedAt: account.updatedAt.toISOString() }),
              },
              created,
              `account:${account.id}`
            )
          : false
        tally('account', accountsTable ?? 'accounts', slugs.account, isNew)
      }
    }

    // --- 3. sessions (carry keeps every token) -----------------------------
    const sessionsTable = sourceTables['sessions']
    if (sessions === 'carry') {
      const rows = await readMapped(client, sessionsTable, [
        'id',
        'user_id',
        'token',
        'expires_at',
        'ip_address',
        'user_agent',
      ])
      for (const row of rows) {
        totals.session = (totals.session ?? 0) + 1
        const baId = `sess-${String(row.id)}`
        const isNew = apply
          ? await createDeduped(
              payload,
              slugs.session,
              baId,
              {
                userId: String(row.user_id),
                token: String(row.token),
                expiresAt:
                  row.expires_at instanceof Date
                    ? row.expires_at.toISOString()
                    : now().toISOString(),
                ...(textOrNull(row.ip_address) === undefined
                  ? {}
                  : { ipAddress: textOrNull(row.ip_address) }),
                ...(textOrNull(row.user_agent) === undefined
                  ? {}
                  : { userAgent: textOrNull(row.user_agent) }),
                ...stamps(row),
              },
              created,
              `session:${String(row.id)}`
            )
          : false
        tally('session', sessionsTable ?? 'sessions', slugs.session, isNew)
      }
    }

    // --- 4. verifications ---------------------------------------------------
    const verificationsTable = sourceTables['verifications']
    const verifications = await readMapped(client, verificationsTable, [
      'id',
      'identifier',
      'value',
      'expires_at',
    ])
    for (const row of verifications) {
      totals.verification = (totals.verification ?? 0) + 1
      const baId = `ver-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.verification,
            baId,
            {
              identifier: String(row.identifier),
              value: String(row.value),
              expiresAt:
                row.expires_at instanceof Date ? row.expires_at.toISOString() : now().toISOString(),
              ...stamps(row),
            },
            created,
            `verification:${String(row.id)}`
          )
        : false
      tally('verification', verificationsTable ?? 'verifications', slugs.verification, isNew)
    }

    // --- 5. api keys (hash, prefix, metadata, rate-limit state) --------------
    const apiKeysTable = sourceTables['api_keys']
    const apiKeys = await readMapped(client, apiKeysTable, [
      'id',
      'config_id',
      'name',
      'start',
      'prefix',
      'key',
      // payload-auth stores the satellite's owner as reference_id — the
      // same name @better-auth/api-key 1.7 uses (`referenceId`).
      'reference_id',
      'refill_interval',
      'refill_amount',
      'last_refill_at',
      'enabled',
      'rate_limit_enabled',
      'rate_limit_time_window',
      'rate_limit_max',
      'request_count',
      'remaining',
      'last_request',
      'expires_at',
      'permissions',
      'metadata',
    ])
    for (const row of apiKeys) {
      totals.apikey = (totals.apikey ?? 0) + 1
      const baId = `key-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.apikey,
            baId,
            {
              configId: textOrNull(row.config_id) ?? '',
              ...(textOrNull(row.name) === undefined ? {} : { name: textOrNull(row.name) }),
              ...(textOrNull(row.start) === undefined ? {} : { start: textOrNull(row.start) }),
              ...(textOrNull(row.prefix) === undefined ? {} : { prefix: textOrNull(row.prefix) }),
              key: String(row.key),
              // @better-auth/api-key 1.7 names the owner `referenceId`;
              // `userId` is offered for 1.6-era target schemas (Payload
              // drops it where the collection has no such field).
              userId: String(row.reference_id),
              referenceId: String(row.reference_id),
              ...(numberOrNull(row.refill_interval) === undefined
                ? {}
                : { refillInterval: numberOrNull(row.refill_interval) }),
              ...(numberOrNull(row.refill_amount) === undefined
                ? {}
                : { refillAmount: numberOrNull(row.refill_amount) }),
              ...(row.last_refill_at instanceof Date
                ? { lastRefillAt: row.last_refill_at.toISOString() }
                : {}),
              ...(row.enabled === null ? {} : { enabled: row.enabled === true }),
              ...(row.rate_limit_enabled === null
                ? {}
                : { rateLimitEnabled: row.rate_limit_enabled === true }),
              ...(numberOrNull(row.rate_limit_time_window) === undefined
                ? {}
                : { rateLimitTimeWindow: numberOrNull(row.rate_limit_time_window) }),
              ...(numberOrNull(row.rate_limit_max) === undefined
                ? {}
                : { rateLimitMax: numberOrNull(row.rate_limit_max) }),
              ...(numberOrNull(row.request_count) === undefined
                ? {}
                : { requestCount: numberOrNull(row.request_count) }),
              ...(numberOrNull(row.remaining) === undefined
                ? {}
                : { remaining: numberOrNull(row.remaining) }),
              ...(row.last_request instanceof Date
                ? { lastRequest: row.last_request.toISOString() }
                : {}),
              ...(row.expires_at instanceof Date
                ? { expiresAt: row.expires_at.toISOString() }
                : {}),
              ...(textOrNull(row.permissions) === undefined
                ? {}
                : { permissions: textOrNull(row.permissions) }),
              ...(textOrNull(row.metadata) === undefined
                ? {}
                : { metadata: textOrNull(row.metadata) }),
              ...stamps(row),
            },
            created,
            `apikey:${String(row.id)}`
          )
        : false
      tally('apikey', apiKeysTable ?? 'api_keys', slugs.apikey, isNew)
    }

    // --- 6. jwks --------------------------------------------------------------
    const jwksTable = sourceTables['jwks']
    const jwks = await readMapped(client, jwksTable, ['id', 'public_key', 'private_key'])
    for (const row of jwks) {
      totals.jwks = (totals.jwks ?? 0) + 1
      const baId = `jwks-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.jwks,
            baId,
            {
              publicKey: String(row.public_key),
              privateKey: String(row.private_key),
              ...stamps(row),
            },
            created,
            `jwks:${String(row.id)}`
          )
        : false
      tally('jwks', jwksTable ?? 'jwks', slugs.jwks, isNew)
    }

    // --- 7. organization plugin rows ---------------------------------------
    const organizationsTable = sourceTables['organizations']
    const organizations = await readMapped(client, organizationsTable, [
      'id',
      'name',
      'slug',
      'logo',
      'metadata',
    ])
    for (const row of organizations) {
      totals.organization = (totals.organization ?? 0) + 1
      const baId = `org-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.organization,
            baId,
            {
              name: String(row.name),
              slug: String(row.slug),
              ...(textOrNull(row.logo) === undefined ? {} : { logo: textOrNull(row.logo) }),
              ...(textOrNull(row.metadata) === undefined
                ? {}
                : { metadata: textOrNull(row.metadata) }),
              ...stamps(row),
            },
            created,
            `organization:${String(row.id)}`
          )
        : false
      tally('organization', organizationsTable ?? 'organizations', slugs.organization, isNew)
    }

    const membersTable = sourceTables['members']
    const members = await readMapped(client, membersTable, [
      'id',
      'organization_id',
      'user_id',
      'role',
    ])
    for (const row of members) {
      totals.member = (totals.member ?? 0) + 1
      const baId = `member-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.member,
            baId,
            {
              organizationId: `org-${String(row.organization_id)}`,
              userId: String(row.user_id),
              ...(textOrNull(row.role) === undefined ? {} : { role: textOrNull(row.role) }),
              ...stamps(row),
            },
            created,
            `member:${String(row.id)}`
          )
        : false
      tally('member', membersTable ?? 'members', slugs.member, isNew)
    }

    const invitationsTable = sourceTables['invitations']
    const invitations = await readMapped(client, invitationsTable, [
      'id',
      'organization_id',
      'email',
      'role',
      'status',
      'expires_at',
      'inviter_id',
    ])
    for (const row of invitations) {
      totals.invitation = (totals.invitation ?? 0) + 1
      const baId = `inv-${String(row.id)}`
      const isNew = apply
        ? await createDeduped(
            payload,
            slugs.invitation,
            baId,
            {
              organizationId: `org-${String(row.organization_id)}`,
              email: String(row.email),
              ...(textOrNull(row.role) === undefined ? {} : { role: textOrNull(row.role) }),
              ...(textOrNull(row.status) === undefined ? {} : { status: textOrNull(row.status) }),
              ...(row.expires_at instanceof Date
                ? { expiresAt: row.expires_at.toISOString() }
                : {}),
              ...(typeof row.inviter_id === 'number' ? { inviterId: String(row.inviter_id) } : {}),
              ...stamps(row),
            },
            created,
            `invitation:${String(row.id)}`
          )
        : false
      tally('invitation', invitationsTable ?? 'invitations', slugs.invitation, isNew)
    }

    log(
      `plan: ${planRows.length} row group(s), ${createdCount} created, ${skippedCount} skipped, ${fieldWriteCount} field value(s) captured`
    )
    if (apply) {
      // The manifest is the run's contract: merge this pass onto any
      // resumed run's rows and write it back (issue #50).
      const manifest: ImportManifest = signManifest(payload.secret, {
        version: 3,
        kind: 'import',
        createdAt: options.manifest?.createdAt ?? now().toISOString(),
        sourceDatabase: options.sourceDatabase,
        options: { sessions },
        created,
        fieldWrites,
        finalized: options.manifest?.finalized ?? false,
        sourceCounts: options.sourceCounts,
        totals,
      })
      const { writeManifest } = await import('./lifecycle.js')
      writeManifest(manifest, options.manifestPath)
    }
    const plan: ImportPlan = {
      rows: planRows,
      unmappable,
      sessions,
      warnings: [],
    }
    return {
      created: createdCount,
      skipped: skippedCount,
      fieldWrites: fieldWriteCount,
      plan,
    }
  } finally {
    await client.end()
  }
}

/** Collapse per-row plan entries into one line per model (dry-run print). */
export function summarizePlanRows(rows: readonly PlanRow[]): PlanRow[] {
  const byModel = new Map<string, PlanRow>()
  for (const row of rows) {
    const existing = byModel.get(row.model)
    if (existing === undefined) {
      byModel.set(row.model, { ...row })
      continue
    }
    byModel.set(row.model, {
      ...existing,
      rows: existing.rows + row.rows,
      skipped: existing.skipped + row.skipped,
    })
  }
  return [...byModel.values()]
}
