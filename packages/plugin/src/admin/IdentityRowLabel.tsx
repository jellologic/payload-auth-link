'use client'

import { isRecord } from '@payload-auth-link/core'
import { useRowLabel } from '@payloadcms/ui'
import type { JSX } from 'react'

/** Pure label formatting, unit-tested; the component only reads the row. */
export function formatIdentityLabel(data: unknown): string {
  const row = isRecord(data) ? data : {}
  const provider = typeof row.providerId === 'string' ? row.providerId : 'identity'
  const email = typeof row.email === 'string' ? row.email : ''
  return email === '' ? provider : `${provider} · ${email}`
}

/**
 * Row label for linked-identity rows: `provider · email`.
 * Reads the row through `useRowLabel` and narrows defensively.
 */
export function IdentityRowLabel(): JSX.Element {
  const { data } = useRowLabel<unknown>()
  return <span>{formatIdentityLabel(data)}</span>
}
