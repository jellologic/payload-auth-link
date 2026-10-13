import {
  createIdentityEventEmitter,
  isRecord,
  parseEmail,
  wellKnownProviderIds,
  type IdentityEventHandler,
  type LoggerPort,
} from '@payload-auth-link/core'

/**
 * Better Auth identity lifecycle translation (CAP-14): the engine
 * feeds BA `databaseHooks` observations into this bus, which narrows
 * BA's user/account rows (arriving as `unknown` at this boundary)
 * into core `IdentityEvent`s for subscribers. Rows that cannot be
 * narrowed are skipped and logged — a hook observation must never
 * throw into the provider operation that already committed.
 */
export type IdentityEventBus = {
  readonly subscribe: (handler: IdentityEventHandler) => () => void
  readonly userUpdated: (user: unknown) => Promise<void>
  readonly userDeleted: (user: unknown) => Promise<void>
  readonly accountDeleted: (account: unknown) => Promise<void>
}

function userShape(value: unknown): { id: string; email: string; emailVerified: boolean } | null {
  if (!isRecord(value)) {
    return null
  }
  const { id, email, emailVerified } = value
  if (typeof id !== 'string' || id === '' || typeof email !== 'string' || email === '') {
    return null
  }
  return { id, email, emailVerified: emailVerified === true }
}

/** Create the event bus the BA engine composes its hooks over. */
export function createIdentityEventBus(logger: LoggerPort): IdentityEventBus {
  const emitter = createIdentityEventEmitter()
  const emit = emitter.emit
  const providerId = wellKnownProviderIds.betterAuth
  return {
    subscribe: (handler: IdentityEventHandler) => emitter.subscribe(handler),
    async userUpdated(user) {
      const shape = userShape(user)
      if (shape === null) {
        logger.warn('better-auth user.update hook: unusable user row, event skipped')
        return
      }
      const email = parseEmail(shape.email)
      if (email.isErr()) {
        logger.warn('better-auth user.update hook: unparseable email, event skipped', {
          providerUserId: shape.id,
        })
        return
      }
      // BA's update hook carries the post-update row, not a diff, so
      // every user update reports the current email + verification
      // state. Application is idempotent (setEmail no-ops when the
      // address already matches) and D9-gated on `verified`.
      await emit({
        type: 'email-changed',
        providerId,
        providerUserId: shape.id,
        email: email.value,
        verified: shape.emailVerified,
      })
    },
    async userDeleted(user) {
      const shape = userShape(user)
      if (shape === null) {
        logger.warn('better-auth user.delete hook: unusable user row, event skipped')
        return
      }
      await emit({ type: 'user-deleted', providerId, providerUserId: shape.id })
    },
    async accountDeleted(account) {
      if (!isRecord(account) || typeof account.userId !== 'string' || account.userId === '') {
        logger.warn('better-auth account.delete hook: unusable account row, event skipped')
        return
      }
      await emit({
        type: 'identity-unlinked',
        providerId,
        providerUserId: account.userId,
      })
    },
  }
}
