import type { CollectionBeforeValidateHook } from 'payload'
import type { CollectionMap } from '@payload-auth-link/core'

/**
 * Normalize the user email to lowercase before validation, matching the
 * `Email` smart constructor. Payload then validates/stores the canonical
 * form, so lookups never miss on case.
 */
export function normalizeUserEmailHook(map: CollectionMap): CollectionBeforeValidateHook {
  return ({ data }) => {
    const email: unknown = data?.[map.emailField]
    if (data && typeof email === 'string') {
      const lowercased = email.toLowerCase()
      if (lowercased !== email) {
        data[map.emailField] = lowercased
      }
    }
    return data
  }
}
