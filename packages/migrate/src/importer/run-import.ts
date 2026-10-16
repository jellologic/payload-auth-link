import { isRecord } from '@payload-auth-link/core'
import { pathToFileURL } from 'node:url'
import { applyImport, summarizePlanRows } from './apply.js'
import { prelinkUsers, type PrelinkResult } from './prelink.js'
import {
  defaultManifestPath,
  defaultPrelinkManifestPath,
  finalizeManifest,
  readManifest,
  rollbackImport,
  verifyImport,
  type VerifyResult,
} from './lifecycle.js'
import {
  countTables,
  findOrphans,
  openSource,
  probeSourceLayout,
  readSourceUsers,
  unverifiedEmails,
  type SourceLayoutIssue,
} from './source.js'
import {
  defaultTargetSlugs,
  parseSourceMapJson,
  presentTables,
  resolveSourceTables,
  type ImportManifest,
  type ImportPlan,
  type ImportResult,
  type ResolvedSourceTables,
  type TargetSlugMap,
} from './types.js'

/**
 * The import commands (issue #50): `from-payload-auth` (dry-run by
 * default, `--apply` writes), `verify`, `rollback`, `finalize`.
 *
 * Dry run prints planned row counts per model, collisions, and
 * anything unmappable; unmappable data aborts `--apply` before any
 * write. The manifest records every created row and field change;
 * source tables are never modified — `finalize` only marks the
 * manifest, and dropping them stays the operator's later step.
 */

export type ImportCommandOptions = {
  readonly configPath: string
  readonly databaseUrl: string
  readonly apply: boolean
  readonly sessions: 'carry' | 'drop'
  readonly manifestPath?: string | undefined
  readonly slugsJson?: string | undefined
  /**
   * The `--source-map` JSON (issue #68): model → source table name, or
   * `null` for "model not installed". Missing mapped tables abort the
   * run before anything is written without it.
   */
  readonly sourceMapJson?: string | undefined
  readonly json?: boolean
  readonly log?: (message: string) => void
  readonly loadPayload?: (configPath: string) => Promise<import('payload').Payload>
}

const log_ = (options: Pick<ImportCommandOptions, 'log'>): ((message: string) => void) =>
  options.log ?? (() => {})

/** A config module loaded and unwrapped (default / promise), not booted. */
type LoadedConfigModule = {
  readonly config: unknown
}

/**
 * Load the config MODULE only — no `getPayload`, no database pool.
 * The pre-flight (#75) inspects this to refuse untouched payload-auth
 * configs before any boot can hang on them.
 */
async function loadConfigModule(configPath: string): Promise<LoadedConfigModule> {
  const mod = (await import(pathToFileURL(configPath).href)) as { default: unknown }
  let config: unknown = isRecord(mod) && 'default' in mod ? mod.default : mod
  if (typeof (config as Partial<Promise<unknown>> | undefined)?.then === 'function') {
    config = await config
  }
  return { config }
}

/**
 * The collection slugs a config module declares, read structurally —
 * sanitized and unsanitized configs both carry the array.
 */
function configCollectionSlugs(config: unknown): readonly string[] {
  if (!isRecord(config) || !Array.isArray(config['collections'])) {
    return []
  }
  const slugs: string[] = []
  for (const entry of config['collections']) {
    if (isRecord(entry) && typeof entry['slug'] === 'string') {
      slugs.push(entry['slug'])
    }
  }
  return slugs
}

/**
 * Pre-flight (#75): every TARGET collection must exist in the config
 * BEFORE Payload boots. The importer writes the plugin's own
 * `ba-*` collections — running it against an untouched payload-auth
 * app's config has nothing to write to, and the boot's database pool
 * would keep the process alive forever after the failure. Fail here,
 * fast, with the fix in the message.
 */
function assertTargetCollections(config: unknown, slugs: TargetSlugMap): void {
  const declared = new Set(configCollectionSlugs(config))
  const missing = [...Object.values(slugs)].filter((slug) => !declared.has(slug))
  if (missing.length > 0) {
    throw new Error(
      `this config declares none of the payload-auth-link target collections (missing: ${missing.join(', ')}). ` +
        'The importer runs against the TARGET config — the app that boots payload-auth-link (adopt or ba-* collections) — ' +
        'not against the untouched payload-auth app. Install the plugin in this config first (docs/migrating-from-payload-auth.md).'
    )
  }
}

/**
 * Boot the loaded config with a watchdog (#75): a boot that never
 * settles must fail loudly after a bounded wait, not park the CLI
 * forever.
 *
 * A FRESH, uncached instance (issue #88): `getPayload`'s module cache
 * would hand a later command in the same process the instance an
 * earlier command already destroyed. The caller owns the instance and
 * destroys it (pool, crons) when the command ends.
 */
async function bootPayload(config: unknown): Promise<import('payload').Payload> {
  const { BasePayload } = await import('payload')
  const boot = new BasePayload().init({
    config: config as Parameters<InstanceType<typeof BasePayload>['init']>[0]['config'],
  })
  let timer: NodeJS.Timeout | undefined
  const watchdog = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error('payload did not finish booting within 120s — refusing to hang'))
    }, 120_000)
  })
  void watchdog.catch(() => {})
  try {
    return await Promise.race([boot, watchdog])
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer)
    }
  }
}

function slugsOf(options: ImportCommandOptions): TargetSlugMap {
  if (options.slugsJson === undefined) {
    return { ...defaultTargetSlugs }
  }
  const parsed: unknown = JSON.parse(options.slugsJson)
  if (!isRecord(parsed)) {
    throw new Error('--slugs must be a JSON object of model -> collection slug')
  }
  return { ...defaultTargetSlugs, ...(parsed as Record<string, string>) }
}

/**
 * The shared boot path for the payload-backed commands (#75): load the
 * config module, REFUSE configs that declare no target collections
 * (the untouched payload-auth app's config — the importer would boot a
 * database pool and then have nothing to write to), then boot under
 * the watchdog. `loadPayload` injection skips the module reload — the
 * host's injected boot owns the target wiring, and the config path may
 * be a placeholder the loader never reads.
 */
async function bootTargetPayload(
  options: ImportCommandOptions,
  requireTargets = true
): Promise<import('payload').Payload> {
  if (options.loadPayload !== undefined) {
    return options.loadPayload(options.configPath)
  }
  const { config } = await loadConfigModule(options.configPath)
  if (requireTargets) {
    assertTargetCollections(config, slugsOf(options))
  }
  return bootPayload(config)
}

/**
 * Run `work` against the target Payload and ALWAYS release it
 * (issue #88): an instance this command booted is destroyed —
 * database pool closed, crons stopped — whether `work` succeeds or
 * throws, so the CLI exits after a successful run instead of idling
 * on open handles. An injected `loadPayload` instance belongs to the
 * caller and is left running.
 */
async function withTargetPayload<T>(
  options: ImportCommandOptions,
  work: (payload: import('payload').Payload) => Promise<T>,
  requireTargets = true
): Promise<T> {
  const payload = await bootTargetPayload(options, requireTargets)
  try {
    return await work(payload)
  } finally {
    if (options.loadPayload === undefined) {
      await releasePayload(payload)
    }
  }
}

/**
 * Destroy a booted Payload AND close its connection pool (issue #88).
 * `payload.destroy()` stops crons and resets the adapter, but the SQL
 * adapters' `destroy` leaves the driver pool open — and
 * `@payloadcms/db-postgres` checks one client out of the pool at
 * connect time and never releases it, so even `pool.end()` would wait
 * forever. Those are exactly the handles that kept a finished CLI
 * alive. The pool is reached structurally: every checked-out client
 * is released-and-destroyed, then `pool.end()` (bounded); SQLite/libsql
 * closes its `client`.
 */
async function releasePayload(payload: import('payload').Payload): Promise<void> {
  const db: unknown = payload.db
  await payload.destroy()
  if (!isRecord(db)) {
    return
  }
  const pool = db['pool']
  if (isRecord(pool) && typeof pool['end'] === 'function') {
    const clients: unknown = pool['_clients']
    if (Array.isArray(clients)) {
      for (const client of (clients as unknown[]).slice()) {
        if (isRecord(client) && typeof client['release'] === 'function') {
          try {
            // `true` destroys the connection instead of returning it.
            ;(client['release'] as (destroy: boolean) => void).call(client, true)
          } catch {
            // Already released (an idle client) — `end()` closes it.
          }
        }
      }
    }
    let timer: NodeJS.Timeout | undefined
    await Promise.race([
      (pool['end'] as () => Promise<void>).call(pool),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 5_000)
        timer.unref()
      }),
    ])
    if (timer !== undefined) {
      clearTimeout(timer)
    }
    return
  }
  const client = db['client']
  if (isRecord(client) && typeof client['close'] === 'function') {
    ;(client['close'] as () => void).call(client)
  }
}

/**
 * Pre-flight only (no boot): refuse configs that declare no target
 * collections. Runs before EVERYTHING — including the source-database
 * probe — so the untouched payload-auth app's config fails here, fast,
 * with the fix in the message (#75).
 */
async function preFlightTargets(options: ImportCommandOptions): Promise<void> {
  if (options.loadPayload !== undefined) {
    return
  }
  const { config } = await loadConfigModule(options.configPath)
  assertTargetCollections(config, slugsOf(options))
}

/** The resolved source layout (`--source-map` over the default layout). */
function sourceTablesOf(options: ImportCommandOptions): ResolvedSourceTables {
  return resolveSourceTables(
    options.sourceMapJson === undefined ? undefined : parseSourceMapJson(options.sourceMapJson)
  )
}

/**
 * Fail-closed probe (issue #68): runs FIRST, before any plan, read, or
 * Payload boot. Findings come back as unmappable rows — the caller's
 * exit-1 path — so nothing is silently read as empty.
 */
async function probeOrFail(
  options: ImportCommandOptions,
  log: (message: string) => void
): Promise<readonly SourceLayoutIssue[]> {
  const client = await openSource(options.databaseUrl)
  try {
    const issues = await probeSourceLayout(client, sourceTablesOf(options))
    for (const issue of issues) {
      log(`  X ${issue.model}: ${issue.reason}`)
    }
    return issues
  } finally {
    await client.end()
  }
}

/** Plan-only pass: counts, orphans, unverified users, warnings. */
async function buildPlan(
  options: ImportCommandOptions,
  sourceTables: ResolvedSourceTables
): Promise<{
  plan: ImportPlan
  sourceCounts: Record<string, number>
}> {
  const client = await openSource(options.databaseUrl)
  try {
    const sourceCounts = await countTables(client, presentTables(sourceTables))
    const { orphans, skipped } = await findOrphans(client, sourceTables)
    return {
      sourceCounts,
      plan: {
        rows: [],
        unmappable: orphans,
        sessions: options.sessions,
        warnings: skipped.map((reason) => `orphan check ${reason}`),
      },
    }
  } finally {
    await client.end()
  }
}

/** The `from-payload-auth` command: dry-run plan, or `--apply` + manifest. */
export async function runFromPayloadAuth(options: ImportCommandOptions): Promise<{
  exitCode: number
  result?: ImportResult
  plan: ImportPlan
  unverified: readonly string[]
}> {
  const log = log_(options)
  const slugs = slugsOf(options)
  const sourceTables = sourceTablesOf(options)

  // The config pre-flight runs before ANYTHING (issue #75): an
  // untouched payload-auth config has no ba-* targets — refuse here,
  // before the source probe or any Payload boot. Then the source
  // probe (issue #68): a missing mapped table or column aborts here —
  // exit 1, nothing planned or written.
  await preFlightTargets(options)
  const probeIssues = await probeOrFail(options, log)
  if (probeIssues.length > 0) {
    return {
      exitCode: 1,
      plan: {
        rows: [],
        unmappable: probeIssues.map((issue) => ({
          model: issue.model,
          key: issue.key,
          reason: issue.reason,
        })),
        sessions: options.sessions,
        warnings: [],
      },
      unverified: [],
    }
  }

  const { plan: basePlan, sourceCounts } = await buildPlan(options, sourceTables)

  const unverified = await (async () => {
    const client = await openSource(options.databaseUrl)
    try {
      return unverifiedEmails(await readSourceUsers(client, sourceTables))
    } finally {
      await client.end()
    }
  })()

  if (basePlan.unmappable.length > 0) {
    // Unmappable data aborts the run — nothing is silently skipped.
    const plan: ImportPlan = {
      ...basePlan,
      warnings: [
        ...basePlan.warnings,
        `${unverified.length} unverified user(s) will NOT be granted the linkable proof`,
      ],
    }
    if (options.apply) {
      log('ABORT: unmappable rows present; nothing was written')
      return { exitCode: 1, plan, unverified }
    }
    return { exitCode: 1, plan, unverified }
  }

  const manifestPath = options.manifestPath ?? defaultManifestPath
  const existingManifest = readManifest(manifestPath)

  const result = await withTargetPayload(options, (payload) =>
    applyImport({
      payload,
      sourceConnectionString: options.databaseUrl,
      apply: options.apply,
      sessions: options.sessions,
      manifest: existingManifest,
      manifestPath,
      sourceCounts,
      sourceDatabase: options.databaseUrl.replace(/\/\/[^@]*@/, '//***@'),
      slugs,
      sourceTables,
      log,
    })
  )
  const plan: ImportPlan = {
    ...result.plan,
    warnings: [
      ...result.plan.warnings,
      `${unverified.length} unverified user(s) will NOT be granted the linkable proof`,
    ],
  }

  if (!options.json) {
    for (const row of summarizePlanRows(result.plan.rows)) {
      log(
        `  ${row.model.padEnd(14)} ${String(row.rows).padStart(5)} row(s) -> ${row.targetCollection}${row.skipped > 0 ? ` (${row.skipped} already present)` : ''}`
      )
    }
    for (const warning of plan.warnings) {
      log(`  ! ${warning}`)
    }
    for (const row of plan.unmappable) {
      log(`  X ${row.model} #${row.key}: ${row.reason}`)
    }
    if (options.apply && plan.unmappable.length === 0) {
      log(
        `applied: manifest at ${manifestPath} (mode 0600; ids and sealed values only). Next: verify, then finalize after your soak window.`
      )
    } else if (!options.apply) {
      log('dry run: nothing was written. Re-run with --apply to copy.')
    }
  }
  return {
    exitCode: result.plan.unmappable.length > 0 ? 1 : 0,
    result,
    plan,
    unverified,
  }
}

/** The `verify` command. */
export async function runVerify(options: ImportCommandOptions): Promise<VerifyResult> {
  const log = log_(options)

  // The config pre-flight runs first (issue #75), then the probe
  // (issue #68): a missing mapped table fails the check with a
  // blocker — before any Payload boot or read.
  await preFlightTargets(options)
  const probeIssues = await probeOrFail(options, log)
  if (probeIssues.length > 0) {
    const result: VerifyResult = {
      ok: false,
      issues: probeIssues.map((issue) => ({
        code: 'source-table-missing',
        detail: issue.reason,
      })),
      checks: [],
    }
    if (!options.json) {
      for (const issue of result.issues) {
        log(`  [${issue.code}] ${issue.detail}`)
      }
    }
    return result
  }

  const result = await withTargetPayload(options, (payload) =>
    verifyImport({
      payload,
      sourceConnectionString: options.databaseUrl,
      slugs: slugsOf(options),
      sourceTables: sourceTablesOf(options),
      sessions: options.sessions,
    })
  )
  if (!options.json) {
    for (const check of result.checks) {
      log(`  ${check.passed ? 'ok ' : 'FAIL'} ${check.name}`)
    }
    for (const issue of result.issues) {
      log(`  [${issue.code}] ${issue.detail}`)
    }
    log(result.ok ? 'verify: ok' : `verify: ${result.issues.length} mismatch(es)`)
  }
  return result
}

/** The `rollback` command. */
export async function runRollback(
  options: ImportCommandOptions
): Promise<{ deleted: number; restored: number }> {
  const log = log_(options)
  const manifestPath = options.manifestPath ?? defaultManifestPath
  const manifest = readManifest(manifestPath)
  if (manifest === null) {
    throw new Error(`no manifest at ${manifestPath}; nothing to roll back`)
  }
  if (manifest.finalized) {
    throw new Error('the migration is finalized; rollback is no longer possible')
  }
  // A prelink manifest touches only host fields; its rollback needs no
  // ba-* target collections in the config.
  const requireTargets = manifest.kind !== 'adopt-prelink'
  return withTargetPayload(
    options,
    (payload) => rollbackImport({ payload, manifest, log, manifestPath }),
    requireTargets
  )
}

/** The `finalize` command — manifest-only; no Payload instance is loaded. */
export function runFinalize(
  options: Pick<ImportCommandOptions, 'manifestPath' | 'log'>
): Promise<ImportManifest> {
  const log = log_(options)
  const manifestPath = options.manifestPath ?? defaultManifestPath
  const manifest = readManifest(manifestPath)
  if (manifest === null) {
    return Promise.reject(new Error(`no manifest at ${manifestPath}; run --apply first`))
  }
  const finalized = finalizeManifest(manifest, manifestPath)
  log(
    `finalized: the manifest at ${manifestPath} is now read-only. Legacy tables may be dropped in a separate, later migration — nothing is dropped for you.`
  )
  return Promise.resolve(finalized)
}

/** Options for `adopt-prelink` (issue #88). */
export type PrelinkCommandOptions = Pick<
  ImportCommandOptions,
  'configPath' | 'apply' | 'manifestPath' | 'json' | 'log' | 'loadPayload'
> & {
  readonly usersSlug?: string | undefined
  readonly verifiedField?: string | undefined
}

/**
 * The `adopt-prelink` command (issues #49, #88): pre-link every adopted
 * user (one better-auth identity; the linking proof for verified
 * emails). Dry run by default; `--apply` writes and records the
 * manifest that `rollback --manifest` undoes exactly.
 */
export async function runAdoptPrelink(options: PrelinkCommandOptions): Promise<PrelinkResult> {
  const log = log_(options)
  const manifestPath = options.manifestPath ?? defaultPrelinkManifestPath
  const existing = readManifest(manifestPath)
  if (existing !== null && existing.kind !== 'adopt-prelink') {
    throw new Error(
      `the manifest at ${manifestPath} belongs to an import run, not adopt-prelink — pass a different --manifest`
    )
  }
  if (existing?.finalized === true) {
    throw new Error(`the manifest at ${manifestPath} is finalized; nothing to pre-link`)
  }
  const importOptions: ImportCommandOptions = {
    configPath: options.configPath,
    databaseUrl: '',
    apply: options.apply,
    sessions: 'carry',
    ...(options.loadPayload === undefined ? {} : { loadPayload: options.loadPayload }),
  }
  const result = await withTargetPayload(
    importOptions,
    (payload) =>
      prelinkUsers({
        payload,
        apply: options.apply,
        manifest: existing,
        manifestPath,
        usersSlug: options.usersSlug,
        verifiedField: options.verifiedField,
        log,
      }),
    false
  )
  if (options.json !== true) {
    log(
      `  users ${result.users}: ${result.linked} to link, ${result.alreadyLinked} already linked, ${result.proofGranted} verified-email proof grant(s), ${result.unverified} unverified (identity only)`
    )
    for (const row of result.unmappable) {
      log(`  X ${row.model} #${row.key}: ${row.reason}`)
    }
    if (result.unmappable.length === 0) {
      log(
        options.apply
          ? `applied: manifest at ${manifestPath} (mode 0600). Undo with: rollback --config <config> --manifest ${manifestPath}`
          : 'dry run: nothing was written. Re-run with --apply to pre-link.'
      )
    }
  }
  return result
}
