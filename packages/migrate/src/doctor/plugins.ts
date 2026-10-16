import { readFileSync } from 'node:fs'
import { relative } from 'node:path'
import type { PluginFinding } from './types.js'
import { listSourceFiles } from './source-scan.js'

/**
 * Better Auth plugin classification (issue #52): for each plugin the
 * app's `betterAuthOptions.plugins` declares, the doctor says whether
 * payload-auth-link's engine supports it out of the box
 * (`autoDeclare` derives its models from Better Auth's own
 * `getAuthTables`), whether it is a probed satellite, or whether it
 * blocks migration.
 */

/**
 * Core + first-party plugins the engine derives confidently. Mirrors
 * what the derive-schema snapshot tests pin in
 * packages/provider-better-auth; new entries land together with a
 * derived-schema probe.
 */
const autoDeclared: ReadonlySet<string> = new Set([
  'magic-link',
  'email-otp',
  'anonymous',
  'two-factor',
  'admin',
  'organization',
  'jwt',
  'username',
  'phone-number',
  'generic-oauth',
  'one-time-token',
  'multi-session',
  'bearer',
  'expo',
  'siwe',
  'next-cookies',
  'tanstack-start-cookies',
  'svelte-kit-cookies',
  'solid-start-cookies',
])

/** Satellites with a committed schema probe in this repo (compat matrix). */
const probedSatellites: ReadonlySet<string> = new Set([
  '@better-auth/passkey',
  '@better-auth/api-key',
])

/** Satellites explicitly unsupported until probed (see compatibility.md). */
const unsupportedSatellites: ReadonlyMap<string, string> = new Map([
  [
    '@better-auth/sso',
    'not probed by payload-auth-link; adding it meets UnsupportedSchemaError at wiring time',
  ],
])

/**
 * Payload-auth's own plugin additions the engine has no equivalent
 * for. `oidcProvider` is the headline: Better Auth 1.7 removed it, and
 * the replacement (@better-auth/oauth-provider) uses different tables,
 * so the data move is the app's phase-1 prerequisite.
 */
const removedUpstream: ReadonlyMap<string, string> = new Map([
  [
    'oidc-provider',
    'Better Auth 1.7 removed `oidcProvider`; moving to @better-auth/oauth-provider is a schema migration (oauthApplication → oauthClient, token splits, jwks gains alg/crv) — plan it before the auth migration',
  ],
  [
    'mcp',
    'Better Auth 1.7 removed the `mcp` plugin; move its surface to @better-auth/oauth-provider',
  ],
])

/** The satellite's own id convention: package name or its short id. */
function satelliteId(id: string): string {
  return id.startsWith('@better-auth/') ? id : `@better-auth/${id}`
}

export function classifyPlugins(ids: readonly string[]): PluginFinding[] {
  const findings: PluginFinding[] = []
  for (const raw of ids) {
    const id = raw.trim()
    if (id === '') {
      continue
    }
    const satellite = satelliteId(id)
    if (removedUpstream.has(id) || removedUpstream.has(satellite)) {
      findings.push({
        id,
        status: 'removed-upstream',
        detail: removedUpstream.get(id) ?? removedUpstream.get(satellite) ?? '',
      })
      continue
    }
    if (id === 'oidcProvider') {
      const detail = removedUpstream.get('oidc-provider') ?? ''
      findings.push({ id, status: 'removed-upstream', detail })
      continue
    }
    if (unsupportedSatellites.has(satellite)) {
      findings.push({
        id,
        status: 'unsupported',
        detail: unsupportedSatellites.get(satellite) ?? '',
      })
      continue
    }
    if (probedSatellites.has(satellite)) {
      findings.push({
        id,
        status: 'supported',
        detail: 'probed satellite — schema covered by the committed probe and the compat matrix',
      })
      continue
    }
    if (autoDeclared.has(id)) {
      findings.push({
        id,
        status: 'auto-declarable',
        detail: 'derived from Better Auth’s own getAuthTables via autoDeclare',
      })
      continue
    }
    if (satellite !== id) {
      findings.push({
        id,
        status: 'unprobed',
        detail:
          'Better Auth satellite without a committed probe; the engine will derive its models but nothing here has validated them',
      })
      continue
    }
    findings.push({
      id,
      status: 'unprobed',
      detail:
        'unknown plugin id; the engine derives what Better Auth’s schema reports, but treat it as unvalidated until probed',
    })
  }
  return findings
}

/**
 * payload-auth does not keep the builder's Better Auth options on the
 * built config (the plugin closure holds them), so the doctor derives
 * the plugin set from what IS visible: the collections payload-auth
 * built (each plugin model gets a slug) and the config source's plugin
 * calls (for plugins without dedicated tables — magic link, cookies).
 * Both probes feed the same classifier.
 */

/** payload-auth slug (baPluginSlugs) → Better Auth plugin id. */
const slugToPlugin: Readonly<Record<string, string>> = {
  apiKeys: 'api-key',
  jwks: 'jwt',
  twoFactors: 'two-factor',
  passkeys: 'passkey',
  oauthApplications: 'oidcProvider',
  oauthAccessTokens: 'oidcProvider',
  oauthConsents: 'oidcProvider',
  ssoProviders: 'sso',
  organizations: 'organization',
  members: 'organization',
  invitations: 'organization',
  organizationRoles: 'organization',
  teams: 'organization',
  teamMembers: 'organization',
  deviceCode: 'device-authorization',
  subscriptions: 'subscriptions',
}

/** Plugin ids proven live by the collections payload-auth built. */
export function pluginsFromCollectionSlugs(slugs: readonly string[]): string[] {
  const ids = new Set<string>()
  for (const slug of slugs) {
    const id: string | undefined = slugToPlugin[slug]
    if (id !== undefined) {
      ids.add(id)
    }
  }
  return [...ids].sort()
}

/**
 * True when a source file actually imports Better Auth — any subpath
 * depth (`better-auth/plugins/generic-oauth`, issue #110), static or
 * dynamic `import()`, or `require()`.
 */
const betterAuthImport =
  /(?:from\s*|require\(\s*|import\(\s*)['"](?:better-auth(?:\/[\w.-]+)*|@better-auth\/[\w.-]+(?:\/[\w.-]+)*)['"]/

/** Plugin call names a config source can name, mapped to plugin ids. */

const callNameToPlugin: Readonly<Record<string, string>> = {
  magicLink: 'magic-link',
  emailOTP: 'email-otp',
  anonymous: 'anonymous',
  twoFactor: 'two-factor',
  admin: 'admin',
  organization: 'organization',
  jwt: 'jwt',
  username: 'username',
  phoneNumber: 'phone-number',
  genericOAuth: 'generic-oauth',
  nextCookies: 'next-cookies',
  tanstackStartCookies: 'tanstack-start-cookies',
  oidcProvider: 'oidcProvider',
  mcp: 'mcp',
  passkey: 'passkey',
  apiKey: 'api-key',
  sso: 'sso',
  multiSession: 'multi-session',
  bearer: 'bearer',
  oneTimeToken: 'one-time-token',
  siwe: 'siwe',
  expo: 'expo',
  deviceAuthorization: 'device-authorization',
  subscriptions: 'subscriptions',
}

/**
 * Plugin ids found by scanning the config source for plugin factory
 * calls. Regex on purpose: the loaded config cannot reveal these
 * (closure-held options), and the doctor must not execute app code
 * beyond loading its config module. A file must IMPORT Better Auth for
 * its `call(` shapes to count — `admin(` in prose, a route handler, or
 * an unrelated package's API reads as noise otherwise (issue #75).
 */
export function pluginsFromConfigSource(configSource: string): string[] {
  if (!betterAuthImport.test(configSource)) {
    return []
  }
  const ids = new Set<string>()
  for (const [call, id] of Object.entries(callNameToPlugin)) {
    const pattern = new RegExp(`\\b${call}\\s*\\(`)
    if (pattern.test(configSource)) {
      ids.add(id)
    }
  }
  return [...ids].sort()
}

/** One plugin factory call found in a source file. */
export type PluginSourceHit = {
  /** The Better Auth plugin id (or payload-auth-era name). */
  readonly id: string
  /** The file it was found in, relative to the scanned root. */
  readonly file: string
}

/**
 * Plugin factory calls across the WHOLE source tree (issue #71), not
 * just the config file: a mid-upgrade app calls `admin(...)` or
 * `oidcProvider(...)` in helpers too, and a schema-adding plugin that
 * hides in a non-config file changes what the migration must carry.
 * Same walk/skip rules as the source scan.
 */
export function pluginsFromSourceTree(srcDir: string): readonly PluginSourceHit[] {
  const hits: PluginSourceHit[] = []
  const seen = new Set<string>()
  for (const file of listSourceFiles(srcDir)) {
    // Test files are app-internal evidence, never the app's Better
    // Auth posture (issue #75: a security-tail test mentioning `mcp(`
    // blocked the whole doctor).
    const rel0 = relative(srcDir, file)
    if (/(^|\/)(__tests__|__fixtures__)(\/|$)/.test(rel0) || /\.(test|spec)\.[jt]sx?$/.test(rel0)) {
      continue
    }
    let content: string
    try {
      content = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    // Only files that actually import Better Auth can carry plugin
    // factory calls; everything else (`admin(` in prose or another
    // package's API) is noise.
    if (!betterAuthImport.test(content)) {
      continue
    }
    for (const [call, id] of Object.entries(callNameToPlugin)) {
      const pattern = new RegExp(`\\b${call}\\s*\\(`)
      if (pattern.test(content)) {
        const key = `${id}\n${rel0}`
        if (!seen.has(key)) {
          seen.add(key)
          hits.push({ id, file: rel0 })
        }
      }
    }
  }
  return hits
}
