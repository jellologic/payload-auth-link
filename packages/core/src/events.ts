import type { Email } from './email.js'
import type { ProviderId } from './ports.js'

/**
 * Provider-side identity lifecycle facts (CAP-14), translated by each
 * adapter from its native hooks (Better Auth `databaseHooks`, Auth.js
 * `events`) into this one core vocabulary. The plugin applies them
 * through `UserRepository`, so Payload stays the single user store
 * (invariant 1): an event can sync a verified email or unlink an
 * identity row, but it can never create or delete a Payload user.
 *
 * These are provider HOOKS observed in-process, not webhooks: nothing
 * here is delivered over the network, and the read-time sync in
 * `ensureLinkedUser` remains the backstop when an event is missed
 * (for example while the process was down).
 */
export type IdentityEvent =
  | {
      /**
       * The provider changed the user's email. Applied to Payload
       * only when `verified` is true (D9: the provider owns the
       * email for verified changes only); an unverified change is
       * ignored and logged.
       */
      readonly type: 'email-changed'
      readonly providerId: ProviderId
      readonly providerUserId: string
      readonly email: Email
      readonly verified: boolean
    }
  | {
      /**
       * The provider verified this email for the user. Payload users
       * carry no verification flag (verification gates linking, which
       * already happened), so applying means: sync the address if it
       * differs, otherwise a no-op.
       */
      readonly type: 'email-verified'
      readonly providerId: ProviderId
      readonly providerUserId: string
      readonly email: Email
    }
  | {
      /**
       * The provider account was unlinked from the provider user.
       * Applying removes the identity row from the Payload user; the
       * Payload user itself always remains (D9).
       */
      readonly type: 'identity-unlinked'
      readonly providerId: ProviderId
      readonly providerUserId: string
    }
  | {
      /**
       * The provider user was deleted. Applying unlinks the identity
       * row; the Payload user remains, because Payload owns it (D9).
       */
      readonly type: 'user-deleted'
      readonly providerId: ProviderId
      readonly providerUserId: string
    }

/**
 * Consumes one {@link IdentityEvent}. Adapters call every registered
 * handler from their provider hooks; handlers must not throw into the
 * provider operation (the plugin's applier logs failures instead, so
 * a Payload-side sync failure never aborts the provider-side change
 * that already committed — read-time sync is the backstop).
 */
export type IdentityEventHandler = (event: IdentityEvent) => Promise<void>

/**
 * The fan-out behind an adapter's `onIdentityEvent`: adapters `emit`
 * narrowed events from their provider hooks; the plugin subscribes
 * once. Emission awaits every handler in subscription order.
 */
export type IdentityEventEmitter = {
  readonly emit: (event: IdentityEvent) => Promise<void>
  readonly subscribe: (handler: IdentityEventHandler) => () => void
}

/** Create an {@link IdentityEventEmitter} for an adapter. */
export function createIdentityEventEmitter(): IdentityEventEmitter {
  const handlers = new Set<IdentityEventHandler>()
  return {
    async emit(event) {
      for (const handler of handlers) {
        await handler(event)
      }
    },
    subscribe(handler) {
      handlers.add(handler)
      return () => {
        handlers.delete(handler)
      }
    },
  }
}
