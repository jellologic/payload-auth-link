import { targetConfig } from './shared.js'

/**
 * The SAME app (same PAYLOAD_SECRET) against a second database — a
 * rehearsal clone (GHSA-crrr-3cg7-f6jw). A separate module, because the
 * CLI's config import is cached per module: `PAL_MIGRATE_REHEARSAL_URL`.
 */
export default targetConfig({ withAdminPlugins: true, urlEnv: 'PAL_MIGRATE_REHEARSAL_URL' })
