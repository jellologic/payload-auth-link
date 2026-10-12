'use client'

import { safeRedirectPath } from '@payload-auth-link/core'
import type { ReactNode } from 'react'
import { useAuthLink, useHasRoles } from './provider.js'

/** {@link SignInButton} wiring; unstyled by design. */
export type SignInButtonProps = {
  /** Where the sign-in page lives. Defaults to `/sign-in`. */
  readonly href?: string | undefined
  readonly className?: string | undefined
  readonly children?: ReactNode | undefined
}

/** Unstyled link to the builder's sign-in page. */
export function SignInButton({
  href = '/sign-in',
  className,
  children = 'Sign in',
}: SignInButtonProps): ReactNode {
  return (
    <a href={href} className={className} data-auth-link="sign-in">
      {children}
    </a>
  )
}

/** {@link SignOutButton} wiring; navigation is injectable. */
export type SignOutButtonProps = {
  readonly className?: string | undefined
  readonly children?: ReactNode | undefined
  /**
   * Where to go after a successful sign-out. Stays put by default.
   * Narrowed by `safeRedirectPath` (an off-origin or API destination
   * falls back to `/`), so a prop fed from a query param cannot turn
   * sign-out into an open redirect.
   */
  readonly redirectTo?: string | undefined
  /** Navigation injection for tests; defaults to a full page load. */
  readonly navigate?: ((url: string) => void) | undefined
  /** Called after a successful sign-out, before navigation. */
  readonly onSignedOut?: (() => void) | undefined
}

/**
 * Unstyled sign-out button. Revokes through the provider; on failure it
 * does nothing (the session is still live, so navigating away would lie).
 */
export function SignOutButton({
  className,
  children = 'Sign out',
  redirectTo,
  navigate = (url: string): void => {
    window.location.assign(url)
  },
  onSignedOut,
}: SignOutButtonProps): ReactNode {
  const { signOut } = useAuthLink()
  return (
    <button
      type="button"
      className={className}
      data-auth-link="sign-out"
      onClick={() => {
        void (async () => {
          if (await signOut()) {
            onSignedOut?.()
            if (redirectTo !== undefined) {
              // Sign-in is a fine post-sign-out destination: disable
              // that rule, keep the off-origin and API ones.
              navigate(safeRedirectPath(redirectTo, '/', { signInPath: null }))
            }
          }
        })()
      }}
    >
      {children}
    </button>
  )
}

/** {@link UserMenu} wiring; renders nothing while loading. */
export type UserMenuProps = {
  readonly className?: string | undefined
  /** Sign-in page for the anonymous state. Defaults to `/sign-in`. */
  readonly signInHref?: string | undefined
  /** Where to go after sign-out. Stays put by default. */
  readonly signOutRedirectTo?: string | undefined
}

/**
 * Minimal session menu: nothing while loading, a sign-in link when
 * anonymous, the email plus a sign-out button when authenticated.
 */
export function UserMenu({
  className,
  signInHref = '/sign-in',
  signOutRedirectTo,
}: UserMenuProps): ReactNode {
  const { user, status } = useAuthLink()
  if (status === 'loading') {
    return null
  }
  if (!user) {
    return <SignInButton href={signInHref} />
  }
  return (
    <div className={className} data-auth-link="user-menu" data-auth-status={status}>
      <span data-auth-link="user-email">{user.email}</span>{' '}
      <SignOutButton redirectTo={signOutRedirectTo} />
    </div>
  )
}

/** {@link RequireRoles} wiring: all roles required, fail closed. */
export type RequireRolesProps = {
  /** Every listed role is required (fail closed while loading). */
  readonly roles: readonly string[]
  readonly children: ReactNode
  readonly fallback?: ReactNode | undefined
}

/** Render-gate for role-restricted UI. Hides — it never authorizes. */
export function RequireRoles({ roles, children, fallback = null }: RequireRolesProps): ReactNode {
  const allowed = useHasRoles(...roles)
  return allowed ? children : fallback
}
