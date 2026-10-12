'use client'

import { useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthLink } from '@payload-auth-link/react'

/**
 * Refresh both layers after a client-side auth change (sign-in, sign-out,
 * role update): re-reads the session endpoint into context, then
 * revalidates Next.js server-component state.
 */
export function useAuthLinkRefresh(): () => Promise<void> {
  const router = useRouter()
  const { refresh } = useAuthLink()
  return useCallback(async () => {
    await refresh()
    router.refresh()
  }, [refresh, router])
}
