import type { SessionUser } from '@payload-auth-link/core'

/**
 * Root-route loader data: the session user (or null) for hydrating
 * `AuthLinkProvider initialUser`, so the client never fetches on mount
 * unless unhydrated.
 */
export type SessionLoaderData = {
  readonly initialUser: SessionUser | null
}

/**
 * Build a route `loader` returning {@link SessionLoaderData} from a
 * session server function. Use on the root (or a layout) route and pass
 * `Route.useLoaderData()` into `AuthLinkProvider`.
 *
 * ```tsx
 * // routes/__root.tsx
 * export const Route = createRootRoute({
 *   loader: createSessionLoader(getSessionUser),
 *   component: () => (
 *     <AuthLinkProvider initialUser={Route.useLoaderData().initialUser}>
 *       <Outlet />
 *     </AuthLinkProvider>
 *   ),
 * })
 * ```
 */
export function createSessionLoader(
  getSessionUser: () => Promise<SessionUser | null>
): () => Promise<SessionLoaderData> {
  return async (): Promise<SessionLoaderData> => ({ initialUser: await getSessionUser() })
}
