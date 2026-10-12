'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import {
  defaultSessionEndpointPath,
  type HttpFetch,
  type SessionUser,
} from '@payload-auth-link/core'
import { fetchSessionUser, revokeSession } from './session.js'

/** Session state: unknown until the first load settles. */
export type AuthLinkStatus = 'loading' | 'authenticated' | 'anonymous'

/** What `useAuthLink` returns: user, status, refresh, honest sign-out. */
export type AuthLinkContextValue = {
  readonly user: SessionUser | null
  readonly status: AuthLinkStatus
  /** Re-read the session endpoint (call after sign-in or role changes). */
  readonly refresh: () => Promise<void>
  /**
   * Revoke the session and drop local state. Resolves `false` when the
   * revocation failed — local state is kept so the UI stays honest.
   */
  readonly signOut: () => Promise<boolean>
}

const AuthLinkContext = createContext<AuthLinkContextValue | null>(null)

/** Client provider wiring; `initialUser` is the hydration contract. */
export type AuthLinkProviderProps = {
  readonly children: ReactNode
  /** Session endpoint path. Defaults to the plugin's endpoint. */
  readonly sessionEndpoint?: string | undefined
  /** Injectible fetch. Defaults to the global `fetch`. */
  readonly fetchImpl?: HttpFetch | undefined
  /**
   * Hydration contract: `undefined` (default) fetches on mount;
   * `SessionUser` starts authenticated without a fetch; `null` starts
   * anonymous without a fetch. The Next adapter's server provider
   * supplies this from full server-side validation.
   */
  readonly initialUser?: SessionUser | null | undefined
}

/** Value identity for hydration snapshots (fresh objects, same user). */
function snapshotKey(user: SessionUser | null | undefined): string {
  if (user === undefined) {
    return 'undefined'
  }
  if (user === null) {
    return 'null'
  }
  return JSON.stringify([user.id, user.collection, user.email, [...user.roles].sort()])
}

function statusFor(user: SessionUser | null): AuthLinkStatus {
  return user === null ? 'anonymous' : 'authenticated'
}

/**
 * Client session provider: loads once on mount (unless hydrated),
 * exposes refresh/sign-out. Fail-closed — fetch errors mean anonymous.
 *
 * A later `initialUser` (a re-run server loader, a new RSC payload) is
 * synced into context when its value changes; re-renders passing the
 * same user as a fresh object change nothing, so a client-side sign-out
 * is never undone by a stale snapshot. Refresh stays explicit.
 */
export function AuthLinkProvider({
  children,
  sessionEndpoint = defaultSessionEndpointPath,
  fetchImpl = fetch,
  initialUser = undefined,
}: AuthLinkProviderProps): ReactNode {
  const [user, setUser] = useState<SessionUser | null>(initialUser ?? null)
  const [status, setStatus] = useState<AuthLinkStatus>(
    initialUser === undefined ? 'loading' : statusFor(initialUser)
  )
  // React's "adjust state when a prop changes" pattern (during render,
  // not in an effect): no stale frame, no set-state-in-effect.
  const [syncedKey, setSyncedKey] = useState(() => snapshotKey(initialUser))
  const incomingKey = snapshotKey(initialUser)
  if (incomingKey !== syncedKey) {
    setSyncedKey(incomingKey)
    if (initialUser !== undefined) {
      setUser(initialUser)
      setStatus(statusFor(initialUser))
    }
  }

  const loadSession = useCallback(
    () => fetchSessionUser(sessionEndpoint, fetchImpl),
    [sessionEndpoint, fetchImpl]
  )

  const refresh = useCallback(async () => {
    const current = await loadSession()
    setUser(current)
    setStatus(current === null ? 'anonymous' : 'authenticated')
  }, [loadSession])

  const signOut = useCallback(async () => {
    const revoked = await revokeSession(sessionEndpoint, fetchImpl)
    if (revoked) {
      setUser(null)
      setStatus('anonymous')
    }
    return revoked
  }, [sessionEndpoint, fetchImpl])

  useEffect(() => {
    if (initialUser !== undefined) {
      return
    }
    let cancelled = false
    // Mount-only initial load (the async boundary keeps this out of the
    // sync-setState-in-effect rule); `refresh` stays the public re-read.
    void (async () => {
      const current = await loadSession()
      if (!cancelled) {
        setUser(current)
        setStatus(current === null ? 'anonymous' : 'authenticated')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [initialUser, loadSession])

  const value = useMemo<AuthLinkContextValue>(
    () => ({ user, status, refresh, signOut }),
    [user, status, refresh, signOut]
  )
  return <AuthLinkContext.Provider value={value}>{children}</AuthLinkContext.Provider>
}

/** Read the auth context. Throws outside `AuthLinkProvider` — fail loud. */
export function useAuthLink(): AuthLinkContextValue {
  const value = useContext(AuthLinkContext)
  if (!value) {
    throw new Error('useAuthLink must be used within AuthLinkProvider')
  }
  return value
}

/** `true` when the current user holds every listed role. Fails closed. */
export function useHasRoles(...roles: readonly string[]): boolean {
  const { user } = useAuthLink()
  if (!user) {
    return false
  }
  return roles.every((role) => user.roles.includes(role))
}
