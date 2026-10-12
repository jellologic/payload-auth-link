'use client'

import { useAuthLink } from '@payload-auth-link/react'
import { useRouter } from '@tanstack/react-router'
import { useCallback } from 'react'

/**
 * Refresh both layers after a client-side auth change (sign-in, sign-out,
 * role update): re-reads the session endpoint into context, then
 * invalidates TanStack Router loaders (`router.invalidate()` — the
 * Start parallel of Next's `router.refresh()`).
 */
export function useAuthLinkRefreshStart(): () => Promise<void> {
  const router = useRouter()
  const { refresh } = useAuthLink()
  return useCallback(async () => {
    await refresh()
    await router.invalidate()
  }, [refresh, router])
}
