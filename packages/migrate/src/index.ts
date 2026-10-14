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
export { classifyPlugins } from './doctor/plugins.js'
export { scanSource, projectedUserFields } from './doctor/source-scan.js'
export { analyzeUsersCollection, findUsersCollection, localStrategyOn } from './doctor/users.js'
export { introspectDatabase } from './doctor/database.js'
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
