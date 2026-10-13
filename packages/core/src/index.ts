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
export {
  consoleLogger,
  isSilentLogger,
  nullLogger,
  nullTracer,
  randomIds,
  systemClock,
} from './defaults.js'
export { emailSchema, parseEmail } from './email.js'
export type { Email } from './email.js'
export { parsePhoneNumber, phoneNumberSchema } from './phone.js'
export type { PhoneNumber } from './phone.js'
export { isNonEmptyString, isRecord, toDate } from './guards.js'
export {
  csrfHeaderName,
  defaultSessionEndpointPath,
  normalizeBaseUrl,
  parseGuestResponse,
  parseSessionGuest,
  parseSessionResponse,
  parseSessionUser,
  resolveOrigin,
} from './http.js'
export type {
  HttpFetch,
  OriginResolutionInput,
  ParseSessionUserOptions,
  SessionGuest,
  SessionUser,
  SessionUserDegradeReason,
} from './http.js'
export { defaultLinkingPolicy, linkingPolicySchema, parseLinkingPolicy } from './linking.js'
export type { LinkingPolicy } from './linking.js'
export {
  AuthLinkError,
  ChannelNotAdmittedError,
  DuplicateProviderError,
  ForbiddenError,
  InvalidCollectionMapError,
  InvalidConfigError,
  InvalidEmailError,
  InvalidPhoneNumberError,
  InvalidProviderIdError,
  InvalidRoleError,
  MfaRequiredError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnknownProviderError,
  UnsupportedCapabilityError,
  UnsupportedVersionError,
  UnverifiedEmailError,
  UnverifiedIdentityError,
  UserExistsError,
  UserSuspendedError,
} from './errors.js'
export {
  effectiveRoles,
  emailDomainAllowed,
  emailDomainOf,
  isSuspendedAt,
  mfaSatisfied,
  withheldRoles,
} from './policies.js'
export {
  assertCapabilities,
  authMethods,
  defineProviderId,
  defineSessionId,
  defineUserId,
  providerIdSchema,
  runProviderOperation,
  sessionChannels,
  wellKnownProviderIds,
} from './ports.js'
export type {
  AuthMethod,
  Capability,
  CookieOptions,
  CookiePort,
  ClockPort,
  GuestPrincipal,
  IdentityProviderPort,
  IdPort,
  LinkedIdentity,
  LogFields,
  LoggerPort,
  NewUser,
  ProviderIdentityClaims,
  ProviderIdentityRef,
  ProviderId,
  ProviderProfile,
  ProviderSession,
  ResolvedSessionActor,
  SameSite,
  Session,
  SessionActor,
  SessionAssurance,
  SessionChannel,
  SessionId,
  SessionPort,
  TracerPort,
  TransactionPort,
  UserId,
  UserRecord,
  UserRepository,
  VerifiedClaim,
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
export { applyIdentityEvent } from './use-cases/apply-identity-event.js'
export { createIdentityEventEmitter } from './events.js'
export type { IdentityEvent, IdentityEventEmitter, IdentityEventHandler } from './events.js'
export { ensureLinkedUser } from './use-cases/ensure-linked-user.js'
export type { EnsureLinkedUserDeps, EnsureLinkedUserInput } from './use-cases/ensure-linked-user.js'
export {
  collectionMapSchema,
  parseCollectionMap,
  startupConfigSchema,
  validateStartupConfig,
} from './validation.js'
export type { CollectionMap, StartupConfig } from './validation.js'
export {
  assertSupportedVersion,
  describeBand,
  isSupportedVersion,
  parseVersion,
  readInstalledVersion,
} from './version.js'
export type { ParsedVersion, VersionRange } from './version.js'
