/**
 * Framework-free auth domain and port interfaces.
 *
 * This barrel is the entire public API: exporting something new is a
 * decision, not a side effect. Adapters implement the ports; the domain
 * never imports a framework.
 */
export { assertNever } from './assert.js'
export { assertUniqueSlugs, denyAllAccess, resolveSlugs } from './collections.js'
export type { DenyAllAccess } from './collections.js'
export {
  expiringCookieOptions,
  hostCookiePrefix,
  isCookieName,
  parseCookieHeader,
  resolveSecureCookies,
  secureCookiePrefix,
  serializeCookie,
} from './cookies.js'
export type { SecureCookieEnvironment, SecureCookieRuleInput } from './cookies.js'
export { nullLogger, nullTracer, randomIds, systemClock } from './defaults.js'
export { emailSchema, parseEmail } from './email.js'
export type { Email } from './email.js'
export { isNonEmptyString, isRecord, toDate } from './guards.js'
export {
  csrfHeaderName,
  defaultSessionEndpointPath,
  normalizeBaseUrl,
  parseSessionResponse,
  parseSessionUser,
  resolveOrigin,
} from './http.js'
export type { HttpFetch, OriginResolutionInput, SessionUser } from './http.js'
export {
  AuthLinkError,
  DuplicateProviderError,
  ForbiddenError,
  InvalidCollectionMapError,
  InvalidConfigError,
  InvalidEmailError,
  InvalidProviderIdError,
  InvalidRoleError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnknownProviderError,
  UnverifiedEmailError,
  UserExistsError,
} from './errors.js'
export {
  defineProviderId,
  defineSessionId,
  defineUserId,
  providerIdSchema,
  runProviderOperation,
  wellKnownProviderIds,
} from './ports.js'
export type {
  CookieOptions,
  CookiePort,
  ClockPort,
  IdentityProviderPort,
  IdPort,
  LinkedIdentity,
  LogFields,
  LoggerPort,
  NewUser,
  ProviderIdentityRef,
  ProviderId,
  ProviderProfile,
  ProviderSession,
  SameSite,
  Session,
  SessionId,
  SessionPort,
  TracerPort,
  TransactionPort,
  UserId,
  UserRecord,
  UserRepository,
} from './ports.js'
export { safeRedirectPath } from './redirect.js'
export type { SafeRedirectOptions } from './redirect.js'
export { createProviderRegistry } from './registry.js'
export type { ProviderRegistry } from './registry.js'
export { parseRole, roleSchema } from './roles.js'
export type { Role } from './roles.js'
export { registerUser, registerWithStore } from './use-cases/register-user.js'
export type {
  RegisterUserDeps,
  RegisterUserInput,
  RegisterWithStoreDeps,
  RegisterWithStoreInput,
  RegisteredWithStore,
  RegistrationStore,
} from './use-cases/register-user.js'
export { ensureLinkedUser } from './use-cases/ensure-linked-user.js'
export type { EnsureLinkedUserDeps, EnsureLinkedUserInput } from './use-cases/ensure-linked-user.js'
export {
  collectionMapSchema,
  parseCollectionMap,
  startupConfigSchema,
  validateStartupConfig,
} from './validation.js'
export type { CollectionMap, StartupConfig } from './validation.js'
