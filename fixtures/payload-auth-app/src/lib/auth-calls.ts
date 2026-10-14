// Scan target (never executed): representative payload-auth call
// sites the doctor's source scan must find (#52). Shapes mirror the
// production app's ~15 getSession sites, 3 getPayloadAuth sites and 3
// internal-bridge sites (journey issue #60).
import { getPayloadAuth } from 'payload-auth'

export async function currentSession(headers: Headers): Promise<unknown> {
  const payload = getPayloadAuth()
  return payload.betterAuth.api.getSession({ headers })
}

export async function signOut(headers: Headers): Promise<void> {
  const payload = getPayloadAuth()
  await payload.betterAuth.api.signOut({ headers })
}
