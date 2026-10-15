import type { Payload } from 'payload'
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
} from './types.js'

/**
 * Apply side (issue #50): copy payload-auth rows into the
 * payload-auth-link collections through the Payload Local API.
 *
 * - Password hashes, OAuth tokens, API-key hashes, and jwks carry over
 *   VERBATIM (payload-auth used Better Auth's own hashing).
 * - `linkable` + `linkableEmail` are granted from VERIFIED emails only;
 *   unverified users are reported by the plan, never linked.
 * - Sessions default to `carry` so nobody is logged out: the carried
 *   rows keep their tokens, and with the same `advanced.cookiePrefix`
 *   the existing cookies keep working.
 * - Idempotent and resumable: every target row carries a deterministic
 *   `baId` derived from the source id (`acct-<source id>`), so a
 *   re-run after a crash finds its own earlier rows and skips them.
 * - Every created row and every field write lands in the manifest, so
 *   `rollback` is exact and the source tables stay untouched.
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

/**
 * Rows for one mapped model. A `null` mapping records the model as
 * not installed (issue #68) — no read, no rows; anything else goes
 * through the strict `readFlatRows` (a missing mapped table throws;
 * the probe aborts the run first).
 */
async function readMapped(
  client: Awaited<ReturnType<typeof openSource>>,
  table: string | null,
  columns: readonly string[]
): Promise<SourceRow[]> {
  return table === null ? [] : readFlatRows(client, table, columns)
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

/** Capture a host field's current value for the rollback manifest. */
async function captureBefore(
  payload: Payload,
  hostId: number,
  field: string
): Promise<string | null> {
  const doc: unknown = await payload.findByID({
    collection: 'users',
    id: hostId,
    depth: 0,
    overrideAccess: true,
  })
  if (typeof doc !== 'object' || doc === null || !(field in doc)) {
    return null
  }
  return JSON.stringify((doc as Record<string, unknown>)[field] ?? null)
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
  const created: CreatedRow[] = [...(options.manifest?.created ?? [])]
  const fieldWrites: FieldWrite[] = [...(options.manifest?.fieldWrites ?? [])]
  const totals: Record<string, number> = { ...(options.manifest?.totals ?? {}) }
  const planRows: PlanRow[] = []
  const unmappable: { model: string; key: string; reason: string }[] = []
  let createdCount = 0
  let skippedCount = 0
  let fieldWriteCount = 0

  const record = (row: PlanRow): void => {
    planRows.push(row)
  }

  const client = await openSource(sourceConnectionString)
  try {
    const users = await readSourceUsers(client, sourceTables)
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
        // verified-email linking proof. Captured `before` values make
        // rollback exact.
        const hostId = Number(baId)
        if (Number.isSafeInteger(hostId)) {
          const writes: Record<string, unknown> = {
            identities: identityRows(user, now),
            linkable: user.emailVerified,
          }
          const fields: readonly string[] = ['identities', 'roles', 'linkable', 'linkableEmail']
          for (const field of fields) {
            fieldWrites.push({
              collection: 'users',
              id: hostId,
              field,
              before: await captureBefore(payload, hostId, field),
            })
          }
          fieldWriteCount += fields.length
          if (user.roles.length > 0) {
            // Stored role values pass through unchanged (issue #56: the
            // storage edge owns translation; the map is the app's).
            writes.roles = user.roles
          }
          if (user.emailVerified) {
            writes.linkableEmail = user.email
          }
          await payload.update({
            collection: 'users',
            id: hostId,
            data: writes,
            overrideAccess: true,
          })
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
              },
              created,
              `account:${account.id}`
            )
          : false
        if (apply) {
          if (isNew) {
            createdCount += 1
          } else {
            skippedCount += 1
          }
        }
        record({
          model: 'account',
          sourceTable: accountsTable ?? 'accounts',
          targetCollection: slugs.account,
          rows: 1,
          skipped: isNew ? 0 : apply ? 1 : 0,
          unmappable: [],
        })
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
        'created_at',
        'updated_at',
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
                ...(row.created_at instanceof Date
                  ? { createdAt: row.created_at.toISOString() }
                  : {}),
                ...(row.updated_at instanceof Date
                  ? { updatedAt: row.updated_at.toISOString() }
                  : {}),
              },
              created,
              `session:${String(row.id)}`
            )
          : false
        if (apply) {
          if (isNew) {
            createdCount += 1
          } else {
            skippedCount += 1
          }
        }
        record({
          model: 'session',
          sourceTable: sessionsTable ?? 'sessions',
          targetCollection: slugs.session,
          rows: 1,
          skipped: isNew ? 0 : apply ? 1 : 0,
          unmappable: [],
        })
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
            },
            created,
            `verification:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'verification',
        sourceTable: verificationsTable ?? 'verifications',
        targetCollection: slugs.verification,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
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
      // payload-auth stores the satellite's userId as referenceId
      // (the #49 field map's source side).
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
              // The satellite's user reference arrives as referenceId in
              // payload-auth layouts; BA 1.7's own schema names it the
              // same, so the target field is offered both names.
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
            },
            created,
            `apikey:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'apikey',
        sourceTable: apiKeysTable ?? 'api_keys',
        targetCollection: slugs.apikey,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
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
            },
            created,
            `jwks:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'jwks',
        sourceTable: jwksTable ?? 'jwks',
        targetCollection: slugs.jwks,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
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
            },
            created,
            `organization:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'organization',
        sourceTable: organizationsTable ?? 'organizations',
        targetCollection: slugs.organization,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
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
            },
            created,
            `member:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'member',
        sourceTable: membersTable ?? 'members',
        targetCollection: slugs.member,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
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
            },
            created,
            `invitation:${String(row.id)}`
          )
        : false
      if (apply) {
        if (isNew) {
          createdCount += 1
        } else {
          skippedCount += 1
        }
      }
      record({
        model: 'invitation',
        sourceTable: invitationsTable ?? 'invitations',
        targetCollection: slugs.invitation,
        rows: 1,
        skipped: isNew ? 0 : apply ? 1 : 0,
        unmappable: [],
      })
    }

    log(
      `plan: ${planRows.length} row group(s), ${createdCount} created, ${skippedCount} skipped, ${fieldWriteCount} field writes`
    )
    if (apply) {
      // The manifest is the run's contract: merge this pass onto any
      // resumed run's rows and write it back (issue #50).
      const manifest: ImportManifest = {
        version: 1,
        createdAt: options.manifest?.createdAt ?? now().toISOString(),
        sourceDatabase: options.sourceDatabase,
        options: { sessions },
        created,
        fieldWrites,
        finalized: options.manifest?.finalized ?? false,
        sourceCounts: options.sourceCounts,
        totals: {
          ...options.sourceCounts,
          ...(options.manifest?.totals ?? {}),
          ...totals,
        },
      }
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
