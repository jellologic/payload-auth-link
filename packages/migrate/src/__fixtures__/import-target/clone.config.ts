import { targetConfig } from './shared.js'

/**
 * The SAME app (same PAYLOAD_SECRET) against a CLONE of the lifecycle
 * database taken after its first `--apply` (GHSA-xw9m-ph95-84rx). A
 * separate module, because the CLI's config import is cached per
 * module: `PAL_MIGRATE_CLONE_URL`.
 */
export default targetConfig({ withAdminPlugins: true, urlEnv: 'PAL_MIGRATE_CLONE_URL' })
