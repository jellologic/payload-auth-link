import type { BetterAuthPlugin } from 'better-auth'
import type { AuthMethod } from '@payload-auth-link/core'

/**
 * The engine's internal session-provenance plugin. Adds ONE nullable,
 * input-excluded field to Better Auth's session model:
 * `authenticationMethod` — a short token recording HOW the session
 * came into being (`server-mint` for server-side mints,
 * `server-step-up` when the server vouches a second factor it
 * verified itself, `two-factor` for flows that record one). The
 * server session API reads this per-session fact for its assurance
 * projection; enrollment flags are never consulted.
 *
 * Internal: appended to the builder's plugin list by the engine; the
 * field is engine-owned (never a client input) and null on rows that
 * predate it — a null reads as "no recorded method", which the
 * assurance projection treats as proving nothing.
 */
export const sessionProvenancePlugin: BetterAuthPlugin = {
  id: 'payload-auth-link-session-provenance',
  init: () => ({ context: {} }),
  schema: {
    session: {
      fields: {
        authenticationMethod: { type: 'string', required: false, input: false },
      },
    },
  },
}

/** The method value recorded on server-side mints (no 2FA challenge ran). */
export const MINT_METHOD: AuthMethod = 'server-mint'
/** The method recorded when the server vouches a second factor it verified itself. */
export const STEP_UP_METHOD: AuthMethod = 'server-step-up'
/** Session methods whose recorded value counts as an MFA proof. */
export const MFA_METHODS: readonly AuthMethod[] = [STEP_UP_METHOD, 'two-factor']
