'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  defaultSessionEndpointPath,
  type HttpFetch,
  type SessionGuest,
  type SessionUser,
} from '@payload-auth-link/core'
import { fetchSession, revokeSession } from './session.js'

/** Session state: unknown until the first load settles. */
export type AuthLinkStatus = 'loading' | 'authenticated' | 'anonymous'

/** What `useAuthLink` returns: user, status, refresh, honest sign-out. */
export type AuthLinkContextValue = {
  readonly user: SessionUser | null
  /**
   * The anonymous guest principal (CAP-10), present instead of a
   * user while the provider session is anonymous. Never carries
   * roles or access — a stable key for anonymous app state only.
   */
  readonly guest: SessionGuest | null
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
  // PORT-4 facts are part of the value: a re-run loader reporting a
  // new actor/assurance/tenant for the same user must still sync.
  return JSON.stringify([
    user.id,
    user.collection,
    user.email,
    [...user.roles].sort(),
    user.assurance ?? null,
    user.actor ?? null,
    user.organizationId ?? null,
  ])
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
 *
 * Loads are sequenced: only the newest read writes state (late,
 * out-of-order results are dropped), and `signOut` cancels in-flight
 * reads so none can flip the UI back to authenticated afterwards.
 */
export function AuthLinkProvider({
  children,
  sessionEndpoint = defaultSessionEndpointPath,
  fetchImpl = fetch,
  initialUser = undefined,
}: AuthLinkProviderProps): ReactNode {
  const [user, setUser] = useState<SessionUser | null>(initialUser ?? null)
  const [guest, setGuest] = useState<SessionGuest | null>(null)
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

  // Request sequencing. Every load (mount, refresh) takes a ticket;
  // only the newest ticket may write state, so an older read that
  // resolves late (out-of-order refreshes) is dropped. Sign-out bumps
  // the generation and aborts in-flight loads, so a read that started
  // before sign-out can never resurrect the signed-out session.
  const generation = useRef(0)
  const inFlight = useRef(new Set<AbortController>())

  const abortInFlight = useCallback((): boolean => {
    const aborted = inFlight.current.size > 0
    for (const controller of inFlight.current) {
      controller.abort()
    }
    inFlight.current.clear()
    return aborted
  }, [])

  const load = useCallback(async (): Promise<void> => {
    generation.current += 1
    const ticket = generation.current
    const controller = new AbortController()
    inFlight.current.add(controller)
    try {
      const current = await fetchSession(sessionEndpoint, fetchImpl, controller.signal)
      if (ticket !== generation.current || controller.signal.aborted) {
        return
      }
      setUser(current.user)
      setGuest(current.guest)
      setStatus(statusFor(current.user))
    } finally {
      inFlight.current.delete(controller)
    }
  }, [sessionEndpoint, fetchImpl])

  const refresh = useCallback(() => load(), [load])

  const signOut = useCallback(async () => {
    // Cancel reads that started before sign-out.
    generation.current += 1
    const cancelledLoad = abortInFlight()
    const revoked = await revokeSession(sessionEndpoint, fetchImpl)
    if (revoked) {
      // Also cancel reads started while the revocation was in flight.
      generation.current += 1
      abortInFlight()
      setUser(null)
      setGuest(null)
      setStatus('anonymous')
    } else if (cancelledLoad) {
      // Revocation failed but a cancelled read left the state unknown:
      // re-read so the UI reflects the (still live) session honestly.
      await load()
    }
    return revoked
  }, [sessionEndpoint, fetchImpl, abortInFlight, load])

  useEffect(() => {
    if (initialUser !== undefined) {
      return
    }
    // Mount-only initial load (the async boundary keeps this out of the
    // sync-setState-in-effect rule); `refresh` stays the public re-read.
    void load()
    return () => {
      generation.current += 1
      abortInFlight()
    }
  }, [initialUser, load, abortInFlight])

  const value = useMemo<AuthLinkContextValue>(
    () => ({ user, guest, status, refresh, signOut }),
    [user, guest, status, refresh, signOut]
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
