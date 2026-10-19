/**
 * Public API of `@payload-auth-link/migrate` (issues #49–#59). The
 * CLI is the primary surface; these exports let tools and tests run
 * the doctor in-process and consume its typed report.
 */
export {
  runDoctor,
  behaviourChanges,
  findPayloadAuthPlugin,
  betterAuthPluginIds,
  usersSlugOf,
} from './doctor/run-doctor.js'
export type { DoctorOptions } from './doctor/run-doctor.js'
export { checkVersions, payloadBand, betterAuthBand, nextBand } from './doctor/bands.js'
export { classifyPlugins, pluginsFromSourceTree } from './doctor/plugins.js'
export { scanSource, projectedUserFields, listSourceFiles } from './doctor/source-scan.js'
export { analyzeUsersCollection, findUsersCollection, localStrategyOn } from './doctor/users.js'
export { introspectDatabase } from './doctor/database.js'
export {
  runFromPayloadAuth,
  runVerify,
  runRollback,
  runFinalize,
  runAdoptPrelink,
  type FinalizeCommandOptions,
  type ImportCommandOptions,
  type PrelinkCommandOptions,
} from './importer/run-import.js'
export { prelinkUsers, type PrelinkOptions, type PrelinkResult } from './importer/prelink.js'
export { applyImport, summarizePlanRows } from './importer/apply.js'
/**
 * The `req.context` key the migration kit marks every host write with
 * (issue #123). The kit's host writes run through YOUR app's Local API
 * (`from-payload-auth --apply`, `adopt-prelink --apply`, and every
 * `rollback` restore), so the users collection's `beforeChange` /
 * `afterChange` hooks fire once per user. A hook that triggers outward
 * side effects skips them for migration writes by checking this key:
 *
 * ```ts
 * import { MIGRATION_CONTEXT } from '@payload-auth-link/migrate'
 *
 * // in a users-collection hook:
 * if (req.context?.[MIGRATION_CONTEXT] !== undefined) return
 * ```
 *
 * The value under the key is a {@link MigrationContextMarker} whose
 * `op` names the command the write belongs to.
 */
export {
  MIGRATION_CONTEXT,
  type MigrationContextMarker,
  type MigrationContextOp,
} from './importer/host-writes.js'
export {
  countTables,
  findOrphans,
  openSource,
  probeSourceLayout,
  readFlatRows,
  readSourceUsers,
  unverifiedEmails,
  type OrphanScan,
  type SourceClient,
  type SourceLayoutIssue,
  type SourceAccount,
  type SourceRow,
  type SourceUser,
} from './importer/source.js'
export {
  readManifest,
  writeManifest,
  verifyImport,
  rollbackImport,
  finalizeManifest,
  defaultManifestPath,
  defaultPrelinkManifestPath,
  type FinalizeOptions,
  type RollbackOptions,
  type VerifyIssue,
  type VerifyResult,
} from './importer/lifecycle.js'
export {
  defaultSourceTables,
  defaultTargetSlugs,
  parseSourceMapJson,
  presentTables,
  resolveSourceTables,
  sourceModelNames,
  type CreatedRow,
  type ResolvedSourceTables,
  type SourceModel,
  type SourceTableMap,
  type TargetModel,
  type TargetSlugMap,
  type FieldWrite,
  type ImportManifest,
  type ManifestKind,
  type ImportPlan,
  type ImportResult,
  type PlanRow,
  type Unmappable,
} from './importer/types.js'
export {
  exportToJsonl,
  parseExportTables,
  exportTables,
  optionalAuthTables,
  resolveAuthTables,
} from './exporters.js'
export { kvAdapterOf } from './kv-adapter.js'
export type { KvAdapterKind } from './kv-adapter.js'
export { cliMain } from './cli.js'
export type {
  BehaviourChange,
  DatabaseFinding,
  DoctorIssue,
  DoctorReport,
  PluginFinding,
  SourceFinding,
  UsersFinding,
  VersionFinding,
} from './doctor/types.js'
