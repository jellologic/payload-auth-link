import { targetConfig } from './shared.js'

/** The target WITHOUT Better Auth's admin()/anonymous(): it cannot hold bans. */
export default targetConfig({ withAdminPlugins: false })
