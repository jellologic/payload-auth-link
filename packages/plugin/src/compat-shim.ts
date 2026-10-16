import type { Payload } from 'payload'
import { authLinkServer, ServerSessionsDisabledError } from './server.js'

/**
 * The temporary `payload.betterAuth` compatibility shim (issue #53):
 * an opt-in, `payload.betterAuth`-shaped accessor backed ENTIRELY by
 * the supported server API — same suspension gate, same MFA
 * projection, same audit sink, no back door. One deprecation warning
 * per accessor construction (the call sites migrate file by file
 * behind it; the doctor counts what remains).
 *
 * Not installed by the plugin. Apps opt in explicitly:
 *
 *   payload.betterAuth = createBetterAuthCompatShim(payload)
 */

let warned = false

function warnOnce(): void {
  if (warned) {
    return
  }
  warned = true
  // The deprecation warning IS the shim's contract — it must reach
  // the operator. `console.warn` here is the one sanctioned use: the
  // shim is temporary by definition and accepts no logger argument.
  // eslint-disable-next-line no-console -- sanctioned, see above
  console.warn(
    '[payload-auth-link] payload.betterAuth compatibility shim is DEPRECATED: migrate call ' +
      'sites to authLinkServer(payload) (issue #54) and remove the shim (issue #53).'
  )
}

/** The subset of the payload-auth `payload.betterAuth` surface the shim supports. */
export type BetterAuthCompatShim = {
  readonly api: {
    readonly getSession: (input: { headers: Headers }) => Promise<unknown>
  }
}

export function createBetterAuthCompatShim(payload: Payload): BetterAuthCompatShim {
  warnOnce()
  const server = authLinkServer(payload)
  return {
    api: {
      getSession: async ({ headers }) => {
        try {
          return await server.getSession(headers)
        } catch (error) {
          if (error instanceof ServerSessionsDisabledError) {
            throw error
          }
          // The old getSession returned null on every failure mode;
          // the shim preserves that contract.
          return null
        }
      },
    },
  }
}
