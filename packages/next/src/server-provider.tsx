import { headers } from 'next/headers'
import type { JSX, ReactNode } from 'react'
import { AuthLinkProvider } from '@payload-auth-link/react'
import type { SessionVerifier } from '@payload-auth-link/web'

/** Server provider wiring: live validation plus hydration. */
export type AuthLinkServerProviderProps = {
  readonly children: ReactNode
  /**
   * Full server-side validation, e.g. `createSessionVerifier(...)`.
   * Receives the live request headers; `null` hydrates anonymous.
   */
  readonly verify: SessionVerifier
  /** Session endpoint path for client-side refresh/sign-out. */
  readonly sessionEndpoint?: string | undefined
}

/**
 * Async server component: fully validates the session on Node and
 * hydrates the client provider, so the first paint already knows the
 * user (no loading flash, no client-side fetch waterfall).
 */
export async function AuthLinkServerProvider({
  children,
  verify,
  sessionEndpoint,
}: AuthLinkServerProviderProps): Promise<JSX.Element> {
  const user = await verify(await headers())
  return (
    <AuthLinkProvider initialUser={user} sessionEndpoint={sessionEndpoint}>
      {children}
    </AuthLinkProvider>
  )
}
