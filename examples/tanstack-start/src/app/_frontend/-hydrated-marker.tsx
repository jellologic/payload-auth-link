'use client'

import { useEffect } from 'react'

/**
 * Test hook: marks first hydration so the shared e2e suite can wait
 * for interactivity (`gotoOwn`) instead of racing it. SSR HTML
 * accepts clicks before React hydrates; a click in that window is
 * silently lost. Invisible and inert in production.
 */
export function HydratedMarker() {
  useEffect(() => {
    document.documentElement.dataset.hydrated = 'true'
  }, [])
  return null
}
