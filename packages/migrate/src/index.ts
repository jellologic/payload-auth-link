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
  type ImportCommandOptions,
  type PrelinkCommandOptions,
} from './importer/run-import.js'
export { prelinkUsers, type PrelinkOptions, type PrelinkResult } from './importer/prelink.js'
export { applyImport, summarizePlanRows } from './importer/apply.js'
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
export { exportToJsonl, parseExportTables, exportTables } from './exporters.js'
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
