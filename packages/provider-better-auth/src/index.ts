/**
 * Better Auth identity-provider adapter: Payload-backed database adapter,
 * `IdentityProviderPort`, session cookie names, and the composition engine.
 */
export { createPayloadDatabaseAdapter } from './adapter.js'
export type { PayloadDatabaseAdapterDeps } from './adapter.js'
export {
  betterAuthCoreFields,
  createBetterAuthCollections,
  customModelSlug,
  defaultBetterAuthSlugs,
  defaultCustomSlug,
} from './collections.js'
export type {
  BetterAuthCollectionsAccess,
  BetterAuthCollectionSlugs,
  BetterAuthCollectionsOptions,
  BetterAuthCustomField,
  BetterAuthCustomFieldType,
  BetterAuthCustomModel,
  BetterAuthModelKey,
} from './collections.js'
export {
  getBetterAuthSessionCookieClearOptions,
  getBetterAuthSessionCookieNames,
} from './cookies.js'
export type { BetterAuthCookieOptions } from './cookies.js'
export { createBetterAuthEngine } from './engine.js'
export type { BetterAuthEngine, BetterAuthEngineInput } from './engine.js'
export {
  AdapterOperationError,
  UnknownModelError,
  UnsupportedOperatorError,
  UnsupportedSchemaError,
} from './errors.js'
export { createBetterAuthProvider } from './port.js'
export type { BetterAuthProviderDeps, BetterAuthServerApi, BetterAuthSessionQuery } from './port.js'
export { baFieldToPayload, translateWhereClause } from './where.js'
