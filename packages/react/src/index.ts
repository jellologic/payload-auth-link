/**
 * Provider-agnostic React UI: session context, sign-in components, user
 * menu, role gates. No Next, no Payload imports — framework work lives in
 * `@payload-auth-link/next`, server work in `@payload-auth-link/plugin`.
 */
export const packageName = '@payload-auth-link/react'

export { RequireRoles, SignInButton, SignOutButton, UserMenu } from './components.js'
export type {
  RequireRolesProps,
  SignInButtonProps,
  SignOutButtonProps,
  UserMenuProps,
} from './components.js'
export { AuthLinkProvider, useAuthLink, useHasRoles } from './provider.js'
export type { AuthLinkContextValue, AuthLinkProviderProps, AuthLinkStatus } from './provider.js'
export { fetchSessionUser, revokeSession } from './session.js'
