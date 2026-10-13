/**
 * Consumer fixture (B19): uses the shipped `dist` types of the two
 * framework-free packages exactly as an external strict consumer
 * would. Never executed; `tsc --noEmit` with `skipLibCheck: false`
 * is the whole test. Keep the surface broad: ports a custom adapter
 * implements, the wire parser, and the web verifier entry points.
 */
import {
  authMethods,
  emailSchema,
  parseSessionUser,
  sessionChannels,
  type IdentityProviderPort,
  type SessionChannel,
  type UserRepository,
} from '@payload-auth-link/core'
import type { SessionVerifier } from '@payload-auth-link/web'
import type { StandardSchemaV1 } from '@standard-schema/spec'

// A custom adapter author must be able to name these ports.
export type Ports = readonly [IdentityProviderPort, UserRepository, SessionVerifier]

// Exported schemas must remain valid Standard Schemas for consumers
// (Effect, Valibot-era tooling, form libraries) — assignment proves it.
export const asStandard: StandardSchemaV1<unknown, string> = emailSchema

export const methods: readonly string[] = authMethods
export const channel: SessionChannel = sessionChannels[0] ?? 'cookie'

export function readSession(value: unknown): string | null {
  const user = parseSessionUser(value, { onDegrade: () => undefined })
  return user?.email ?? null
}
