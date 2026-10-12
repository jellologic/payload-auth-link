import { err, ok, type Result } from 'neverthrow'
import { DuplicateProviderError, UnknownProviderError } from './errors.js'
import type { IdentityProviderPort, ProviderId } from './ports.js'

/**
 * Explicit adapter registry: providers are registered at the composition
 * root, never discovered by magic. Duplicate registration is an error.
 */
export interface ProviderRegistry {
  register(provider: IdentityProviderPort): Result<void, DuplicateProviderError>
  require(id: ProviderId): Result<IdentityProviderPort, UnknownProviderError>
  ids(): readonly ProviderId[]
}

/** Create an empty provider registry for the composition root. */
export function createProviderRegistry(): ProviderRegistry {
  const providers = new Map<ProviderId, IdentityProviderPort>()
  return {
    register(provider) {
      if (providers.has(provider.id)) {
        return err(new DuplicateProviderError(provider.id))
      }
      providers.set(provider.id, provider)
      return ok(undefined)
    },
    require(id) {
      const provider = providers.get(id)
      if (!provider) {
        return err(new UnknownProviderError(id))
      }
      return ok(provider)
    },
    ids() {
      return [...providers.keys()]
    },
  }
}
