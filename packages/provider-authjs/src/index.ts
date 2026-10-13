/**
 * Auth.js identity-provider adapter: Payload-backed database adapter,
 * credentials service, `IdentityProviderPort`, session cookie names, and
 * the composition engine.
 */
export { createAuthJsAdapter } from './adapter.js'
export type { AuthJsAdapterDeps } from './adapter.js'
export { createAuthLinkCallbacks, createAuthLinkEvents, emailVerifiedClaim } from './callbacks.js'
export type { AuthLinkCallbacks, AuthLinkEvents, AuthLinkTrustOptions } from './callbacks.js'
export { createAuthJsCollections, defaultAuthJsSlugs } from './collections.js'
export type {
  AuthJsCollectionsAccess,
  AuthJsCollectionSlugs,
  AuthJsCollectionsOptions,
  AuthJsModelKey,
} from './collections.js'
export { getAuthJsSessionCookieClearOptions, getAuthJsSessionCookieNames } from './cookies.js'
export type { AuthJsCookieOptions } from './cookies.js'
export {
  createAuthJsCredentials,
  hashCredentialsPassword,
  minCredentialsPasswordLength,
  verifyCredentialsPassword,
} from './credentials.js'
export type {
  AuthJsCredentials,
  AuthJsCredentialsDeps,
  RegisteredCredentialsUser,
  RegisterCredentialsUserInput,
} from './credentials.js'
export { createAuthJsEngine } from './engine.js'
export type { AuthJsEngine, AuthJsEngineInput } from './engine.js'
export { AdapterMappingError, AdapterOperationError, WeakPasswordError } from './errors.js'
export { authJsCapabilities, createAuthJsProvider } from './port.js'
export {
  buildEmailOtpCallbackUrl,
  createGoogleOneTapAuthorize,
  emailOtpMaxAgeSeconds,
  emailOtpVerificationToken,
  generateEmailOtpCode,
  verifyGoogleIdToken,
} from './recipes.js'
export type {
  GoogleIdTokenProfile,
  GoogleOneTapAuthorizeDeps,
  GoogleOneTapVerifyDeps,
} from './recipes.js'
export type { AuthJsProviderDeps, AuthJsSessionApi } from './port.js'
/** Package name for diagnostics. */
export const packageName = '@payload-auth-link/provider-authjs'
