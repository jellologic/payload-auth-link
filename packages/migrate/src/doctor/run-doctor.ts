import { isRecord } from '@payload-auth-link/core'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { checkVersions } from './bands.js'
import { introspectDatabase } from './database.js'
import { classifyPlugins, pluginsFromCollectionSlugs, pluginsFromConfigSource } from './plugins.js'
import { scanSource } from './source-scan.js'
import { analyzeUsersCollection, findUsersCollection } from './users.js'
import type { BehaviourChange, DoctorIssue, DoctorReport } from './types.js'

/**
 * The read-only doctor (issue #52): point it at a payload-auth app and
 * get the exact list of what breaks before touching anything. It loads
 * the app's config module, inspects the users collection and Better
 * Auth plugins, scans the source tree for call sites that must
 * migrate, and (with a database URL) reports row counts, unverified
 * users, and orphans. It never writes.
 */

export type DoctorOptions = {
  /** Absolute or cwd-relative path to the app's payload config. */
  readonly configPath: string
  /** Source directory to scan. Defaults to the config's directory. */
  readonly srcDir?: string | undefined
  /** Postgres connection string. Defaults to `DATABASE_URL`. */
  readonly databaseUrl?: string | undefined
  /** Config loader, injectable for tests. Defaults to dynamic import. */
  readonly loadModule?: ((path: string) => Promise<unknown>) | undefined
}

/**
 * Behaviour changes in payload-auth-link 0.7.0 that a payload-auth app
 * feels on day one. Static by nature; kept next to the doctor so the
 * report is one artifact.
 */
export const behaviourChanges: readonly BehaviourChange[] = [
  {
    title: 'Provider-linked documents lose local sign-in and forgot/reset',
    detail:
      '0.7.0 makes documents with linked identities provider-owned: Payload local login and the self-service forgot/reset flow are refused for them (GHSA-f4hj). Break-glass operator accounts (no linked identities) keep everything. Set allowLocalCredentialsForLinkedDocs: true only for a migration window.',
  },
  {
    title: 'Suspension is enforced on every strategy',
    detail:
      'suspendedUntil now refuses provider sessions, local sign-ins, existing local JWTs and API keys on the next request — including refresh-token and GraphQL.',
  },
  {
    title: 'Collection access defaults tighten',
    detail:
      'Engine collections default to deny-all API access, and the users collection ships governed defaults for update/delete/unlock. Hosts opening access do so explicitly.',
  },
  {
    title: 'req.user is a projection by default',
    detail:
      "req.user carries { id, collection, email, roles } plus assurance/actor fields, not the full document. Access functions reading other fields see undefined — audit them or opt into reqUser: 'document' (#57).",
  },
]

/**
 * Detect payload-auth in the built config. The plugin stamps
 * `config.custom.hasBetterAuthPlugin = true` when it runs; older or
 * future builds that instead expose `pluginOptions` on the plugin
 * function are honored too.
 */
export function findPayloadAuthPlugin(config: unknown): {
  pluginOptions: Record<string, unknown>
} | null {
  if (!isRecord(config)) {
    return null
  }
  if (isRecord(config.custom) && config.custom.hasBetterAuthPlugin === true) {
    return { pluginOptions: {} }
  }
  if (!Array.isArray(config.plugins)) {
    return null
  }
  for (const plugin of config.plugins) {
    if (typeof plugin === 'function' && 'pluginOptions' in plugin) {
      const options: unknown = (plugin as { pluginOptions: unknown }).pluginOptions
      if (isRecord(options)) {
        return { pluginOptions: options }
      }
    }
  }
  return null
}

/**
 * The Better Auth plugin ids the app declared. Reads them off
 * `betterAuthOptions.plugins` when a pluginOptions object is visible;
 * callers otherwise derive them from the built collections and the
 * config source (see {@link pluginsFromCollectionSlugs} and
 * {@link pluginsFromConfigSource}).
 */
export function betterAuthPluginIds(pluginOptions: Record<string, unknown>): string[] {
  const baOptions: unknown = pluginOptions.betterAuthOptions
  if (!isRecord(baOptions) || !Array.isArray(baOptions.plugins)) {
    return []
  }
  const ids: string[] = []
  for (const plugin of baOptions.plugins) {
    if (isRecord(plugin) && typeof plugin.id === 'string' && plugin.id !== '') {
      ids.push(plugin.id)
    }
  }
  return ids
}

/** The users collection slug the payload-auth app configured. */
export function usersSlugOf(pluginOptions: Record<string, unknown>): string {
  const users: unknown = pluginOptions.users
  return isRecord(users) && typeof users.slug === 'string' && users.slug !== ''
    ? users.slug
    : 'users'
}

/** Collection slugs of the built config. */
export function collectionSlugs(config: unknown): string[] {
  if (!isRecord(config) || !Array.isArray(config.collections)) {
    return []
  }
  return config.collections
    .filter(isRecord)
    .map((collection) => collection.slug)
    .filter((slug): slug is string => typeof slug === 'string')
}

/** Default config loader: a dynamic import of the TS/JS config module. */
async function defaultLoadModule(path: string): Promise<unknown> {
  const mod: unknown = await import(pathToFileURL(path).href)
  let config: unknown = isRecord(mod) && 'default' in mod ? mod.default : mod
  // Payload configs may be async (buildConfig returns a Promise when the
  // config awaits) — the doctor reads the resolved object either way.
  if (typeof (config as Partial<Promise<unknown>> | undefined)?.then === 'function') {
    config = await config
  }
  return config
}

export async function runDoctor(options: DoctorOptions): Promise<DoctorReport> {
  const configPath = resolve(options.configPath)
  const loadModule = options.loadModule ?? defaultLoadModule
  const config = await loadModule(configPath)
  const configDir = dirname(configPath)
  const srcDir = options.srcDir === undefined ? configDir : resolve(options.srcDir)

  const versions = checkVersions(pathToFileURL(configPath).href)
  const blockers: DoctorIssue[] = []
  const warnings: DoctorIssue[] = []
  for (const finding of versions) {
    if (finding.status === 'blocker') {
      blockers.push({
        code: `${finding.name}-out-of-band`,
        detail: `${finding.name}: ${finding.detail}`,
      })
    } else if (finding.status === 'unknown') {
      warnings.push({
        code: `${finding.name}-version-unknown`,
        detail: `${finding.name}: ${finding.detail}`,
      })
    }
  }

  const plugin = findPayloadAuthPlugin(config)
  if (plugin === null) {
    warnings.push({
      code: 'payload-auth-not-detected',
      detail:
        'no payload-auth plugin found in the config; if this app runs payload-auth elsewhere, point --config at that config',
    })
  }
  if (plugin !== null) {
    blockers.push({
      code: 'payload-auth-installed',
      detail:
        'payload-auth is installed and configured: migrate with adopt (#49, zero row moves) or the importer (#50, reversible copy). Its admin views, payload.betterAuth accessor, and user-table layout all change.',
    })
  }

  // payload-auth keeps the builder's options in its closure, so the
  // plugin set comes from what the built config proves: the collections
  // payload-auth created and the plugin calls in the config source.
  let configSource: string
  try {
    configSource = readFileSync(configPath, 'utf8')
  } catch {
    configSource = ''
  }
  const pluginIds = [
    ...new Set([
      ...betterAuthPluginIds(plugin?.pluginOptions ?? {}),
      ...pluginsFromCollectionSlugs(collectionSlugs(config)),
      ...pluginsFromConfigSource(configSource),
    ]),
  ]
  const pluginFindings = classifyPlugins(pluginIds)
  for (const finding of pluginFindings) {
    if (finding.status === 'removed-upstream') {
      blockers.push({
        code: 'ba-plugin-removed-upstream',
        detail: `${finding.id}: ${finding.detail}`,
      })
    } else if (finding.status === 'unsupported' || finding.status === 'unprobed') {
      warnings.push({ code: 'ba-plugin-unvalidated', detail: `${finding.id}: ${finding.detail}` })
    }
  }

  const usersSlug = usersSlugOf(plugin?.pluginOptions ?? {})
  const { finding: users, issues: userIssues } = analyzeUsersCollection(
    findUsersCollection(config, usersSlug),
    'roles'
  )
  for (const issue of userIssues) {
    if (
      issue.code === 'injected-field-collision' ||
      issue.code === 'roles-field-not-select' ||
      issue.code === 'users-collection-missing'
    ) {
      blockers.push(issue)
    } else {
      warnings.push(issue)
    }
  }

  const source = scanSource(srcDir)
  for (const finding of source) {
    if (finding.kind === 'ba-internals') {
      blockers.push({
        code: 'ba-internals-usage',
        detail: `${finding.files.length} file(s) use Better Auth internals (${finding.files.join(', ')}): these break across Better Auth minors and hand-roll session cookies — rewrite on the supported server API (#54) before migrating`,
      })
    }
  }

  const databaseUrl = options.databaseUrl ?? process.env.DATABASE_URL
  let database: DoctorReport['database'] = null
  if (databaseUrl !== undefined && databaseUrl !== '') {
    try {
      const found = await introspectDatabase(databaseUrl)
      database = found
      if (found.unverifiedUsers !== null && found.unverifiedUsers > 0) {
        warnings.push({
          code: 'unverified-users',
          detail: `${found.unverifiedUsers} user(s) have emailVerified = false: they will not JIT-link on a provider sign-in; they need a verified email (or a role manager's manual link) after migration`,
        })
      }
      for (const orphan of found.orphans) {
        blockers.push({
          code: 'orphan-rows',
          detail: `${orphan.count} orphaned row(s) of kind '${orphan.kind}': the importer refuses unmappable references rather than silently skipping them`,
        })
      }
    } catch (error) {
      warnings.push({
        code: 'database-unreachable',
        detail: `could not inspect the database: ${error instanceof Error ? error.message : String(error)}`,
      })
    }
  } else {
    warnings.push({
      code: 'database-not-inspected',
      detail:
        'no database URL (pass --database-url or set DATABASE_URL); row counts, unverified users, and orphans were not checked',
    })
  }

  return {
    versions,
    plugins: pluginFindings,
    users,
    source,
    database,
    behaviourChanges,
    blockers,
    warnings,
  }
}
