// Scan target (never executed): the API-key → session bridge the
// production app hand-rolls on Better Auth internals — exactly what
// the supported server API (#54) replaces.
import type { getPayloadAuth } from 'payload-auth'

type Payload = ReturnType<typeof getPayloadAuth>

export async function apiKeySession(payload: Payload, key: string): Promise<string | null> {
  const ctx = await payload.betterAuth.$context
  const row = await ctx.adapter.findOne({
    model: 'apikey',
    where: [{ field: 'key', value: key }],
  })
  if (row === null || row.userId === null) {
    return null
  }
  const session = await ctx.internalAdapter.createSession(String(row.userId))
  return session.token
}
