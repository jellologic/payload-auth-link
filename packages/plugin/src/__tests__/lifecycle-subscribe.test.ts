/**
 * `subscribeIdentityEvents` (CAP-14) against a registry whose `ids()`
 * names a provider `require()` cannot resolve (issue #116 item 11: the
 * last uncovered arm of `lifecycle.ts`). The real registry never does
 * this — its ids come from the same map — but the subscription must
 * skip such an id and still wire every resolvable provider, rather
 * than throw at `onInit`.
 */
import {
  createProviderRegistry,
  defineProviderId,
  UnknownProviderError,
  type IdentityEventHandler,
  type IdentityProviderPort,
  type ProviderRegistry,
} from '@payload-auth-link/core'
import { err } from 'neverthrow'
import type { Payload } from 'payload'
import { describe, expect, it } from 'vitest'
import { subscribeIdentityEvents } from '../lifecycle.js'
import type { WiredOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

describe('subscribeIdentityEvents', () => {
  it('skips an id the registry cannot resolve and wires the rest', () => {
    const stub = createStubProvider()
    const subscribed: IdentityEventHandler[] = []
    const provider: IdentityProviderPort = {
      ...stub.provider,
      onIdentityEvent: (handler) => {
        subscribed.push(handler)
        return () => undefined
      },
    }
    const real = createProviderRegistry()
    real.register(provider)
    const ghost = defineProviderId('ghost')
    const registry: ProviderRegistry = {
      register: (entry) => real.register(entry),
      require: (id) => (id === ghost ? err(new UnknownProviderError(id)) : real.require(id)),
      ids: () => [ghost, ...real.ids()],
    }
    const wired = { registry } as unknown as WiredOptions
    expect(() => {
      subscribeIdentityEvents(wired, {} as Payload)
    }).not.toThrow()
    expect(subscribed).toHaveLength(1)
  })
})
