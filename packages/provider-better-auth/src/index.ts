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
  BetterAuthAdoptedModel,
  BetterAuthCollectionsOptions,
  BetterAuthCustomField,
  BetterAuthCustomFieldType,
  BetterAuthCustomModel,
  BetterAuthModelKey,
  BetterAuthSchemaMap,
} from './collections.js'
export {
  declarationsFromTables,
  deriveBetterAuthSchema,
  isCoreModel,
  payloadOwnedFields,
} from './derive-schema.js'
export { mergeDeclarations } from './engine.js'
export {
  getBetterAuthLogoutCookieNames,
  getBetterAuthSessionCookieClearOptions,
  getBetterAuthSessionCookieNames,
} from './cookies.js'
export type { BetterAuthCookieOptions } from './cookies.js'
export {
  assertBetterAuthVersion,
  createBetterAuthEngine,
  supportedBetterAuthBand,
} from './engine.js'
export { createIdentityEventBus } from './events.js'
export type { IdentityEventBus } from './events.js'
export type { BetterAuthEngine, BetterAuthEngineInput } from './engine.js'
export {
  AdapterOperationError,
  UnknownModelError,
  UnsupportedApiKeyOwnerError,
  UnsupportedOperatorError,
  UnsupportedSchemaError,
} from './errors.js'
export {
  betterAuthCapabilities,
  betterAuthPluginCapabilities,
  createBetterAuthProvider,
  isPlaceholderEmail,
} from './port.js'
export type { BetterAuthProviderDeps, BetterAuthServerApi, BetterAuthSessionQuery } from './port.js'
export { baFieldToPayload, translateWhereClause } from './where.js'
