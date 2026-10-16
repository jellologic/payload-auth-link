import { applyIdentityEvent, type IdentityEvent } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import type { WiredOptions } from './options.js'
import { createServices } from './services.js'
import { syncVerifiedEmail } from './verified-email.js'

/**
 * CAP-14 lifecycle subscription, wired once at Payload `onInit` (the
 * composition root): every registered provider that can emit
 * identity events gets the plugin's applier, which syncs them
 * through `UserRepository`. Builders never wire this by hand.
 *
 * Application failures are logged, never thrown into the provider
 * hook: the provider-side change already committed, and read-time
 * sync in the session service is the backstop.
 */
export function subscribeIdentityEvents(wired: WiredOptions, payload: Payload): void {
  const handle = async (event: IdentityEvent): Promise<void> => {
    const { users } = createServices(wired, payload)
    const applied = await applyIdentityEvent(users, event, wired.logger)
    if (applied.isErr()) {
      wired.logger.error('identity event application failed; read-time sync remains the backstop', {
        type: event.type,
        providerId: event.providerId,
        providerUserId: event.providerUserId,
        error: applied.error.message,
      })
      return
    }
    // Issue #88: a verified event for the address the linked document
    // ALREADY carries (setEmail no-ops on it) still proves ownership —
    // grant the bound linking proof and set the host's verified mirror.
    const verifiedEmail =
      event.type === 'email-verified' || (event.type === 'email-changed' && event.verified)
        ? event.email
        : null
    if (verifiedEmail === null) {
      return
    }
    const linked = await users.findByProviderIdentity({
      providerId: event.providerId,
      providerUserId: event.providerUserId,
    })
    if (linked.isErr()) {
      wired.logger.error('verified-email sync lookup failed', {
        providerId: event.providerId,
        error: linked.error.message,
      })
      return
    }
    if (linked.value === null) {
      return
    }
    const outcome = await syncVerifiedEmail(wired, payload, linked.value.id, verifiedEmail)
    if (outcome === 'updated') {
      wired.logger.info('verified email synced onto the linked user', {
        userId: linked.value.id,
        providerId: event.providerId,
      })
    }
  }
  for (const id of wired.registry.ids()) {
    const provider = wired.registry.require(id)
    if (provider.isErr()) {
      continue
    }
    provider.value.onIdentityEvent?.((event) => {
      // The handler contract forbids throwing into the provider op;
      // belt-and-braces: a synchronous throw is logged, not raised.
      return handle(event).catch((cause: unknown) => {
        wired.logger.error('identity event handler threw', {
          type: event.type,
          providerId: event.providerId,
          error: cause instanceof Error ? cause.message : 'non-Error cause',
        })
      })
    })
  }
}
