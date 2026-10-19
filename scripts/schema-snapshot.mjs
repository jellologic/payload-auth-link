/**
 * Collection-config snapshot gate (PLAN-UPGRADE-RESILIENCE Phase 2).
 * Snapshots the DB-facing collection shapes every package ships —
 * the provider `ba-*` / `aj-*` collections and the plugin's injected
 * users-collection fields — as JSON in `snapshots/schema/`. These
 * shapes are exactly what a Payload push or migration acts on, so a
 * silent change here is a broken user database (B1/B2/B6/B7).
 *
 * `--check` (wired into `bun run check`) fails when a shape differs
 * from the committed snapshot UNLESS the same tree carries a changeset
 * with an `Upgrade impact:` section AND a `docs/upgrading.md` change —
 * the two artifacts every schema change owes its users.
 *
 * When this fails on purpose: write the upgrading.md entry and a
 * changeset whose `Upgrade impact:` section names the affected
 * collections, per-adapter behavior (SQLite/Postgres/Mongo, push and
 * migrations mode), and the required operator steps. Then regenerate
 * with `bun run schema:snapshot` and commit.
 *
 * Run after `bun run build` (reads built dist, so the snapshot is of
 * exactly what ships).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const snapshotDir = join(root, 'snapshots', 'schema')
const mode = process.argv[2]

// The repo uses bun's isolated linker: resolve through a package that
// declares these deps rather than the (empty) root node_modules.
function resolveFrom(packageName) {
  return require(require.resolve(packageName, { paths: [join(root, 'packages', 'plugin')] }))
}
const { okAsync } = resolveFrom('neverthrow')
const { defineProviderId } = resolveFrom('@payload-auth-link/core')

if (mode !== '--check' && mode !== '--write') {
  console.error('usage: schema-snapshot.mjs --check|--write')
  process.exit(2)
}

/** Key-sorted, deterministic JSON so regeneration is diff-stable. */
function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function sanitize(configs) {
  // Functions (hooks, access, validate) are not DB shape; JSON
  // drops them, which keeps the snapshot to fields, types, and
  // constraints — the part Payload push/migrations act on.
  return JSON.parse(JSON.stringify(configs))
}

function minimalStubProvider() {
  return {
    id: defineProviderId('stub'),
    capabilities: new Set(),
    sessionCookieNames: ['al_stub_session'],
    getSession: () => okAsync(null),
    revokeSession: () => okAsync(undefined),
  }
}

const { createAuthJsCollections } = await import('../packages/provider-authjs/dist/collections.js')
const { createBetterAuthCollections } =
  await import('../packages/provider-better-auth/dist/collections.js')
const { wireOptions } = await import('../packages/plugin/dist/options.js')
const { createAuthLinkStrategy } = await import('../packages/plugin/dist/strategy.js')
const { applyUsersCollection } = await import('../packages/plugin/dist/collections.js')
const { migrationRecordsCollection } = await import('../packages/plugin/dist/migration-records.js')

const wired = wireOptions({
  baseUrl: 'http://schema-snapshot.test',
  roles: ['admin', 'user'],
  defaultRole: 'user',
  providers: [minimalStubProvider()],
})
const strategy = createAuthLinkStrategy(wired)
const usersCollection = applyUsersCollection(
  [{ slug: 'users', auth: true, fields: [] }],
  wired,
  strategy
)

const snapshots = {
  'provider-authjs.json': sanitize(createAuthJsCollections()),
  'provider-better-auth.json': sanitize(createBetterAuthCollections()),
  // The merge path is the common one: an existing users collection
  // gains the plugin's injected fields.
  'plugin-users.json': sanitize(usersCollection),
  // The kit's own record store (issue #139): declared by the plugin so
  // the app's migrations create it.
  'plugin-migration-records.json': sanitize(migrationRecordsCollection()),
}

function pendingChangesets() {
  try {
    const files = execFileSync('git', ['status', '--porcelain', '.changeset'], {
      cwd: root,
      encoding: 'utf8',
    })
      .split('\n')
      .map((line) => line.slice(3).trim())
      .filter((name) => name.endsWith('.md'))
    return files.map((name) => readFileSync(join(root, name), 'utf8'))
  } catch {
    return []
  }
}

function upgradingMdTouched() {
  try {
    const status = execFileSync('git', ['status', '--porcelain', 'docs/upgrading.md'], {
      cwd: root,
      encoding: 'utf8',
    })
    return status.trim() !== ''
  } catch {
    return false
  }
}

mkdirSync(snapshotDir, { recursive: true })
let failed = false

for (const [name, configs] of Object.entries(snapshots)) {
  const snapshot = `${stableStringify(configs)}\n`
  const target = join(snapshotDir, name)
  if (mode === '--write') {
    writeFileSync(target, snapshot)
    console.log(`schema-snapshot: wrote snapshots/schema/${name}`)
  } else if (!existsSync(target) || readFileSync(target, 'utf8') !== snapshot) {
    failed = true
    const hasImpactChangeset = pendingChangesets().some((text) => text.includes('Upgrade impact:'))
    const hasUpgradeNotes = upgradingMdTouched()
    console.error(
      `schema-snapshot: collection shapes of ${name.replace('.json', '')} differ from ` +
        `snapshots/schema/${name}.\n` +
        `  changeset with 'Upgrade impact:' section: ${hasImpactChangeset ? 'found' : 'MISSING'}\n` +
        `  docs/upgrading.md entry: ${hasUpgradeNotes ? 'found' : 'MISSING'}\n` +
        (hasImpactChangeset && hasUpgradeNotes
          ? '  Both present — run: bun run schema:snapshot'
          : '  Every schema change ships an `Upgrade impact:` changeset section (per-adapter\n' +
            '  push/migrations behavior + operator steps) and a docs/upgrading.md entry.\n' +
            '  Add both, then run: bun run schema:snapshot')
    )
  }
}

if (failed) {
  process.exit(1)
}
if (mode === '--check') {
  console.log('schema-snapshot: all collection shapes match their snapshots')
}
