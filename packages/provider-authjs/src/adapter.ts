import type {
  Adapter,
  AdapterAccount,
  AdapterAuthenticator,
  AdapterSession,
  AdapterUser,
  VerificationToken,
} from '@auth/core/adapters'
import { isRecord, resolveSlugs } from '@payload-auth-link/core'
import { randomUUID } from 'node:crypto'
import type { Payload, Where } from 'payload'
import { defaultAuthJsSlugs, type AuthJsCollectionSlugs } from './collections.js'
import { AdapterMappingError, AdapterOperationError } from './errors.js'

/** Database adapter wiring: Payload access, slugs, read depth. */
export type AuthJsAdapterDeps = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Override any default Auth.js collection slug. */
  readonly slugs?: Partial<AuthJsCollectionSlugs> | undefined
  /** Payload query depth for adapter reads. Defaults to 0. */
  readonly depth?: number | undefined
}

function requiredString(doc: Record<string, unknown>, field: string, what: string): string {
  const value = doc[field]
  if (typeof value !== 'string' || value === '') {
    throw new AdapterMappingError(`${what}: field ${field} is missing or empty`)
  }
  return value
}

function optionalString(doc: Record<string, unknown>, field: string): string | undefined {
  const value = doc[field]
  return typeof value === 'string' ? value : undefined
}

function optionalDate(doc: Record<string, unknown>, field: string, what: string): Date | null {
  const value = doc[field]
  if (value === null || value === undefined) {
    return null
  }
  if (typeof value !== 'string') {
    throw new AdapterMappingError(`${what}: field ${field} is not a date string`)
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    throw new AdapterMappingError(`${what}: field ${field} is not a valid date`)
  }
  return parsed
}

function requiredDate(doc: Record<string, unknown>, field: string, what: string): Date {
  const parsed = optionalDate(doc, field, what)
  if (!parsed) {
    throw new AdapterMappingError(`${what}: field ${field} is missing`)
  }
  return parsed
}

function toUser(doc: Record<string, unknown>): AdapterUser {
  const name = optionalString(doc, 'name')
  const image = optionalString(doc, 'image')
  return {
    id: requiredString(doc, 'auId', 'user'),
    email: requiredString(doc, 'email', 'user'),
    emailVerified: optionalDate(doc, 'emailVerified', 'user'),
    ...(name === undefined ? {} : { name }),
    ...(image === undefined ? {} : { image }),
  }
}

const accountTypes: readonly AdapterAccount['type'][] = ['oauth', 'oidc', 'email', 'webauthn']

function isAccountType(value: string): value is AdapterAccount['type'] {
  return (accountTypes as readonly string[]).includes(value)
}

/**
 * Narrow the stored account type against the Auth.js allowlist. A corrupt
 * `type` must fail loud (`AdapterMappingError`), never cast through: the
 * value steers provider dispatch downstream.
 */
function toAccountType(doc: Record<string, unknown>): AdapterAccount['type'] {
  const value = requiredString(doc, 'type', 'account')
  if (!isAccountType(value)) {
    throw new AdapterMappingError(`account: field type has unknown value ${JSON.stringify(value)}`)
  }
  return value
}

function toAccount(doc: Record<string, unknown>): AdapterAccount {
  const expiresAt = doc.expires_at
  const accessToken = optionalString(doc, 'access_token')
  const refreshToken = optionalString(doc, 'refresh_token')
  const idToken = optionalString(doc, 'id_token')
  const tokenType = optionalString(doc, 'token_type')
  const scope = optionalString(doc, 'scope')
  const sessionState = optionalString(doc, 'session_state')
  return {
    provider: requiredString(doc, 'provider', 'account'),
    providerAccountId: requiredString(doc, 'providerAccountId', 'account'),
    userId: requiredString(doc, 'userId', 'account'),
    type: toAccountType(doc),
    ...(accessToken === undefined ? {} : { access_token: accessToken }),
    ...(refreshToken === undefined ? {} : { refresh_token: refreshToken }),
    ...(idToken === undefined ? {} : { id_token: idToken }),
    // Written from typed upstream input (`Lowercase<string>`), so the
    // read-back cast restores the type rather than guessing it.
    ...(tokenType === undefined ? {} : { token_type: tokenType as Lowercase<string> }),
    ...(scope === undefined ? {} : { scope }),
    ...(sessionState === undefined ? {} : { session_state: sessionState }),
    ...(typeof expiresAt === 'number' ? { expires_at: expiresAt } : {}),
  }
}

function toSession(doc: Record<string, unknown>): AdapterSession {
  return {
    sessionToken: requiredString(doc, 'sessionToken', 'session'),
    userId: requiredString(doc, 'userId', 'session'),
    expires: requiredDate(doc, 'expires', 'session'),
  }
}

/**
 * Composite `(identifier, token)` uniqueness key for verification tokens
 * (Payload has no compound unique indexes; see `collections.ts`). JSON
 * encoding keeps the pair unambiguous for any identifier/token strings,
 * unlike a delimiter join. Lookups still query `identifier` + `token`
 * directly, so rows written before this field existed remain consumable.
 */
function verificationTokenKey(identifier: string, token: string): string {
  return JSON.stringify([identifier, token])
}

function toVerificationToken(doc: Record<string, unknown>): VerificationToken {
  return {
    identifier: requiredString(doc, 'identifier', 'verification token'),
    token: requiredString(doc, 'token', 'verification token'),
    expires: requiredDate(doc, 'expires', 'verification token'),
  }
}

function toAuthenticator(doc: Record<string, unknown>): AdapterAuthenticator {
  const counter = doc.counter
  const backedUp = doc.credentialBackedUp
  const transports = optionalString(doc, 'transports')
  if (typeof counter !== 'number' || typeof backedUp !== 'boolean') {
    throw new AdapterMappingError('authenticator: counter/credentialBackedUp have wrong types')
  }
  return {
    credentialID: requiredString(doc, 'credentialID', 'authenticator'),
    userId: requiredString(doc, 'userId', 'authenticator'),
    providerAccountId: requiredString(doc, 'providerAccountId', 'authenticator'),
    credentialPublicKey: requiredString(doc, 'credentialPublicKey', 'authenticator'),
    counter,
    credentialBackedUp: backedUp,
    credentialDeviceType: requiredString(doc, 'credentialDeviceType', 'authenticator'),
    ...(transports === undefined ? {} : { transports }),
  }
}

/**
 * Auth.js database adapter over Payload collections. Every lookup is a
 * single-field (or dual-field) equality query through the Local API —
 * no query language to translate, unlike the Better Auth adapter. Auth.js
 * user ids live in `auId` (Payload owns the document `id`); cross-model
 * `userId` references hold `auId` values.
 */
export function createAuthJsAdapter(deps: AuthJsAdapterDeps): Adapter {
  const slugs: AuthJsCollectionSlugs = resolveSlugs(defaultAuthJsSlugs, deps.slugs)
  const depth = deps.depth ?? 0

  const findOne = async (
    collection: string,
    where: Where,
    operation: string
  ): Promise<Record<string, unknown> | null> => {
    try {
      const payload = await deps.getPayload()
      const found = await payload.find({ collection, where, limit: 1, depth, overrideAccess: true })
      const doc: unknown = found.docs[0]
      if (doc === undefined) {
        return null
      }
      if (!isRecord(doc)) {
        throw new AdapterMappingError(`${operation}: document is not an object`)
      }
      return doc
    } catch (error) {
      if (error instanceof AdapterMappingError) {
        throw error
      }
      throw new AdapterOperationError(operation, { cause: error })
    }
  }

  const findMany = async (
    collection: string,
    where: Where,
    operation: string
  ): Promise<Record<string, unknown>[]> => {
    try {
      const payload = await deps.getPayload()
      const found = await payload.find({
        collection,
        where,
        depth,
        overrideAccess: true,
        pagination: false,
      })
      const docs: unknown[] = found.docs
      for (const doc of docs) {
        if (!isRecord(doc)) {
          throw new AdapterMappingError(`${operation}: document is not an object`)
        }
      }
      return docs.filter(isRecord)
    } catch (error) {
      if (error instanceof AdapterMappingError) {
        throw error
      }
      throw new AdapterOperationError(operation, { cause: error })
    }
  }

  const deleteDoc = async (
    collection: string,
    doc: Record<string, unknown>,
    operation: string
  ): Promise<void> => {
    const id = doc.id
    if (typeof id !== 'string' && typeof id !== 'number') {
      throw new AdapterMappingError(`${operation}: document has no id`)
    }
    try {
      const payload = await deps.getPayload()
      await payload.delete({ collection, id, overrideAccess: true })
    } catch (error) {
      throw new AdapterOperationError(operation, { cause: error })
    }
  }

  const updateDoc = async (
    collection: string,
    doc: Record<string, unknown>,
    data: Record<string, unknown>,
    operation: string
  ): Promise<Record<string, unknown>> => {
    const id = doc.id
    if (typeof id !== 'string' && typeof id !== 'number') {
      throw new AdapterMappingError(`${operation}: document has no id`)
    }
    try {
      const payload = await deps.getPayload()
      const updated = await payload.update({ collection, id, data, overrideAccess: true })
      if (!isRecord(updated)) {
        throw new AdapterMappingError(`${operation}: update returned no document`)
      }
      return updated
    } catch (error) {
      if (error instanceof AdapterMappingError) {
        throw error
      }
      throw new AdapterOperationError(operation, { cause: error })
    }
  }

  return {
    async createUser(user) {
      try {
        const payload = await deps.getPayload()
        const created = await payload.create({
          collection: slugs.user,
          data: {
            auId: user.id || randomUUID(),
            email: user.email,
            ...(user.name === undefined || user.name === null ? {} : { name: user.name }),
            ...(user.image === undefined || user.image === null ? {} : { image: user.image }),
            ...(user.emailVerified === null || user.emailVerified === undefined
              ? {}
              : { emailVerified: user.emailVerified.toISOString() }),
          },
          overrideAccess: true,
        })
        if (!isRecord(created)) {
          throw new AdapterMappingError('createUser: create returned no document')
        }
        return toUser(created)
      } catch (error) {
        if (error instanceof AdapterMappingError) {
          throw error
        }
        throw new AdapterOperationError('createUser', { cause: error })
      }
    },

    async getUser(id) {
      const doc = await findOne(slugs.user, { auId: { equals: id } }, 'getUser')
      return doc === null ? null : toUser(doc)
    },

    async getUserByEmail(email) {
      const doc = await findOne(slugs.user, { email: { equals: email } }, 'getUserByEmail')
      return doc === null ? null : toUser(doc)
    },

    async getUserByAccount({ provider, providerAccountId }) {
      const account = await findOne(
        slugs.account,
        {
          and: [
            { provider: { equals: provider } },
            { providerAccountId: { equals: providerAccountId } },
          ],
        },
        'getUserByAccount'
      )
      if (account === null) {
        return null
      }
      const userId = account.userId
      if (typeof userId !== 'string') {
        throw new AdapterMappingError('getUserByAccount: account has no userId')
      }
      const doc = await findOne(slugs.user, { auId: { equals: userId } }, 'getUserByAccount')
      return doc === null ? null : toUser(doc)
    },

    async updateUser({ id, ...patch }) {
      const doc = await findOne(slugs.user, { auId: { equals: id } }, 'updateUser')
      if (doc === null) {
        throw new AdapterOperationError('updateUser on a missing user')
      }
      const data: Record<string, unknown> = {}
      if (patch.email !== undefined) {
        data.email = patch.email
      }
      if (patch.name !== undefined) {
        data.name = patch.name
      }
      if (patch.image !== undefined) {
        data.image = patch.image
      }
      if (patch.emailVerified !== undefined) {
        data.emailVerified = patch.emailVerified === null ? null : patch.emailVerified.toISOString()
      }
      return toUser(await updateDoc(slugs.user, doc, data, 'updateUser'))
    },

    async deleteUser(userId) {
      const doc = await findOne(slugs.user, { auId: { equals: userId } }, 'deleteUser')
      if (doc === null) {
        return
      }
      // Payload has no cascades: remove the user's accounts, sessions,
      // and authenticators explicitly so none are orphaned.
      for (const collection of [slugs.account, slugs.session, slugs.authenticator]) {
        const related = await findMany(collection, { userId: { equals: userId } }, 'deleteUser')
        for (const entry of related) {
          await deleteDoc(collection, entry, 'deleteUser')
        }
      }
      await deleteDoc(slugs.user, doc, 'deleteUser')
    },

    async linkAccount(account) {
      try {
        const payload = await deps.getPayload()
        const created = await payload.create({
          collection: slugs.account,
          data: {
            key: `${account.provider}:${account.providerAccountId}`,
            provider: account.provider,
            providerAccountId: account.providerAccountId,
            userId: account.userId,
            type: account.type,
            ...(account.access_token === undefined ? {} : { access_token: account.access_token }),
            ...(account.refresh_token === undefined
              ? {}
              : { refresh_token: account.refresh_token }),
            ...(account.id_token === undefined ? {} : { id_token: account.id_token }),
            ...(account.token_type === undefined ? {} : { token_type: account.token_type }),
            ...(account.scope === undefined ? {} : { scope: account.scope }),
            ...(account.session_state === undefined
              ? {}
              : { session_state: account.session_state }),
            ...(account.expires_at === undefined ? {} : { expires_at: account.expires_at }),
          },
          overrideAccess: true,
        })
        if (!isRecord(created)) {
          throw new AdapterMappingError('linkAccount: create returned no document')
        }
        return toAccount(created)
      } catch (error) {
        if (error instanceof AdapterMappingError) {
          throw error
        }
        throw new AdapterOperationError('linkAccount', { cause: error })
      }
    },

    async unlinkAccount({ provider, providerAccountId }) {
      const doc = await findOne(
        slugs.account,
        {
          and: [
            { provider: { equals: provider } },
            { providerAccountId: { equals: providerAccountId } },
          ],
        },
        'unlinkAccount'
      )
      if (doc !== null) {
        await deleteDoc(slugs.account, doc, 'unlinkAccount')
      }
    },

    async getAccount(providerAccountId, provider) {
      const doc = await findOne(
        slugs.account,
        {
          and: [
            { provider: { equals: provider } },
            { providerAccountId: { equals: providerAccountId } },
          ],
        },
        'getAccount'
      )
      return doc === null ? null : toAccount(doc)
    },

    async createSession({ sessionToken, userId, expires }) {
      try {
        const payload = await deps.getPayload()
        const created = await payload.create({
          collection: slugs.session,
          data: { sessionToken, userId, expires: expires.toISOString() },
          overrideAccess: true,
        })
        if (!isRecord(created)) {
          throw new AdapterMappingError('createSession: create returned no document')
        }
        return toSession(created)
      } catch (error) {
        if (error instanceof AdapterMappingError) {
          throw error
        }
        throw new AdapterOperationError('createSession', { cause: error })
      }
    },

    async getSessionAndUser(sessionToken) {
      const sessionDoc = await findOne(
        slugs.session,
        { sessionToken: { equals: sessionToken } },
        'getSessionAndUser'
      )
      if (sessionDoc === null) {
        return null
      }
      const session = toSession(sessionDoc)
      const userDoc = await findOne(
        slugs.user,
        { auId: { equals: session.userId } },
        'getSessionAndUser'
      )
      return userDoc === null ? null : { session, user: toUser(userDoc) }
    },

    async updateSession({ sessionToken, ...patch }) {
      const doc = await findOne(
        slugs.session,
        { sessionToken: { equals: sessionToken } },
        'updateSession'
      )
      if (doc === null) {
        return null
      }
      const data: Record<string, unknown> = {}
      if (patch.userId !== undefined) {
        data.userId = patch.userId
      }
      if (patch.expires !== undefined) {
        data.expires = patch.expires.toISOString()
      }
      return toSession(await updateDoc(slugs.session, doc, data, 'updateSession'))
    },

    async deleteSession(sessionToken) {
      const doc = await findOne(
        slugs.session,
        { sessionToken: { equals: sessionToken } },
        'deleteSession'
      )
      if (doc !== null) {
        await deleteDoc(slugs.session, doc, 'deleteSession')
      }
    },

    async createVerificationToken({ identifier, token, expires }) {
      try {
        const payload = await deps.getPayload()
        const created = await payload.create({
          collection: slugs.verificationToken,
          data: {
            key: verificationTokenKey(identifier, token),
            identifier,
            token,
            expires: expires.toISOString(),
          },
          overrideAccess: true,
        })
        if (!isRecord(created)) {
          throw new AdapterMappingError('createVerificationToken: create returned no document')
        }
        return toVerificationToken(created)
      } catch (error) {
        if (error instanceof AdapterMappingError) {
          throw error
        }
        throw new AdapterOperationError('createVerificationToken', { cause: error })
      }
    },

    async useVerificationToken({ identifier, token }) {
      const doc = await findOne(
        slugs.verificationToken,
        { and: [{ identifier: { equals: identifier } }, { token: { equals: token } }] },
        'useVerificationToken'
      )
      if (doc === null) {
        return null
      }
      const claimed = toVerificationToken(doc)
      await deleteDoc(slugs.verificationToken, doc, 'useVerificationToken')
      return claimed
    },

    async getAuthenticator(credentialID) {
      const doc = await findOne(
        slugs.authenticator,
        { credentialID: { equals: credentialID } },
        'getAuthenticator'
      )
      return doc === null ? null : toAuthenticator(doc)
    },

    async createAuthenticator(authenticator) {
      try {
        const payload = await deps.getPayload()
        const created = await payload.create({
          collection: slugs.authenticator,
          data: {
            credentialID: authenticator.credentialID,
            userId: authenticator.userId,
            providerAccountId: authenticator.providerAccountId,
            credentialPublicKey: authenticator.credentialPublicKey,
            counter: authenticator.counter,
            credentialBackedUp: authenticator.credentialBackedUp,
            credentialDeviceType: authenticator.credentialDeviceType,
            ...(authenticator.transports === undefined || authenticator.transports === null
              ? {}
              : { transports: authenticator.transports }),
          },
          overrideAccess: true,
        })
        if (!isRecord(created)) {
          throw new AdapterMappingError('createAuthenticator: create returned no document')
        }
        return toAuthenticator(created)
      } catch (error) {
        if (error instanceof AdapterMappingError) {
          throw error
        }
        throw new AdapterOperationError('createAuthenticator', { cause: error })
      }
    },

    async listAuthenticatorsByUserId(userId) {
      const docs = await findMany(
        slugs.authenticator,
        { userId: { equals: userId } },
        'listAuthenticatorsByUserId'
      )
      return docs.map(toAuthenticator)
    },

    async updateAuthenticatorCounter(credentialID, newCounter) {
      const doc = await findOne(
        slugs.authenticator,
        { credentialID: { equals: credentialID } },
        'updateAuthenticatorCounter'
      )
      if (doc === null) {
        throw new AdapterOperationError('updateAuthenticatorCounter on a missing authenticator')
      }
      return toAuthenticator(
        await updateDoc(
          slugs.authenticator,
          doc,
          { counter: newCounter },
          'updateAuthenticatorCounter'
        )
      )
    },
  }
}
