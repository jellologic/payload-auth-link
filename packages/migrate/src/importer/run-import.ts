import { isRecord } from '@payload-auth-link/core'
import { pathToFileURL } from 'node:url'
import { applyImport, summarizePlanRows } from './apply.js'
import {
  defaultManifestPath,
  finalizeManifest,
  readManifest,
  rollbackImport,
  verifyImport,
  type VerifyResult,
} from './lifecycle.js'
import { countTables, findOrphans, openSource, unverifiedEmails } from './source.js'
import {
  defaultTargetSlugs,
  type ImportManifest,
  type ImportPlan,
  type ImportResult,
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
  readonly json?: boolean
  readonly log?: (message: string) => void
  readonly loadPayload?: (configPath: string) => Promise<import('payload').Payload>
}

const log_ = (options: Pick<ImportCommandOptions, 'log'>): ((message: string) => void) =>
  options.log ?? (() => {})

async function loadPayloadInstance(configPath: string): Promise<import('payload').Payload> {
  // Lazy: `doctor` never needs Payload, and a cold CLI should not pay
  // for the module graph the import commands use.
  const { getPayload } = await import('payload')
  const mod = (await import(pathToFileURL(configPath).href)) as { default: unknown }
  let config: unknown = isRecord(mod) && 'default' in mod ? mod.default : mod
  if (typeof (config as Partial<Promise<unknown>> | undefined)?.then === 'function') {
    config = await config
  }
  return getPayload({ config: config as Parameters<typeof getPayload>[0]['config'] })
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

/** Plan-only pass: counts, orphans, unverified users, warnings. */
async function buildPlan(options: ImportCommandOptions): Promise<{
  plan: ImportPlan
  sourceCounts: Record<string, number>
}> {
  const client = await openSource(options.databaseUrl)
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
      'users_role',
    ])
    const orphans = await findOrphans(client)
    return {
      sourceCounts,
      plan: {
        rows: [],
        unmappable: orphans,
        sessions: options.sessions,
        warnings: [],
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
  const { plan: basePlan, sourceCounts } = await buildPlan(options)

  const unverified = await (async () => {
    const client = await openSource(options.databaseUrl)
    try {
      const { readSourceUsers } = await import('./source.js')
      return unverifiedEmails(await readSourceUsers(client))
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

  const payload = await (options.loadPayload ?? loadPayloadInstance)(options.configPath)
  const result = await applyImport({
    payload,
    sourceConnectionString: options.databaseUrl,
    apply: options.apply,
    sessions: options.sessions,
    manifest: existingManifest,
    manifestPath,
    sourceCounts,
    sourceDatabase: options.databaseUrl.replace(/\/\/[^@]*@/, '//***@'),
    slugs,
    log,
  })
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
  const payload = await (options.loadPayload ?? loadPayloadInstance)(options.configPath)
  const result = await verifyImport({
    payload,
    sourceConnectionString: options.databaseUrl,
    slugs: slugsOf(options),
  })
  if (!options.json) {
    for (const check of result.checks) {
      log(`  ${check.passed ? 'ok ' : 'FAIL'} ${check.name}`)
    }
    for (const issue of result.issues) {
      log(`  [${issue.code}] ${issue.detail}`)
    }
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
  const payload = await (options.loadPayload ?? loadPayloadInstance)(options.configPath)
  const result = await rollbackImport({ payload, manifest, log })
  return result
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
