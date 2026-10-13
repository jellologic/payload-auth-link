import { err, ok, type Result } from 'neverthrow'
import { isCookieName } from './cookies.js'
import { DuplicateProviderError, InvalidConfigError, UnknownProviderError } from './errors.js'
import type { IdentityProviderPort, ProviderId } from './ports.js'

/**
 * Explicit adapter registry: providers are registered at the composition
 * root, never discovered by magic. Duplicate registration is an error;
 * an illegal session cookie name is a wiring bug and throws
 * `InvalidConfigError` at registration, instead of surfacing later as a
 * per-request serialization throw on logout.
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
      const illegal = [
        ...provider.sessionCookieNames,
        ...(provider.logoutCookieNames ?? []),
      ].filter((name) => !isCookieName(name))
      if (illegal.length > 0) {
        throw new InvalidConfigError(
          `provider ${provider.id} has illegal cookie names: ${illegal
            .map((name) => JSON.stringify(name))
            .join(', ')}`
        )
      }
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
