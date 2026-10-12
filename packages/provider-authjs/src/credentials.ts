import {
  InvalidConfigError,
  isRecord,
  nullLogger,
  registerWithStore,
  RepositoryError,
  resolveSlugs,
  type Email,
  type InvalidEmailError,
  type LoggerPort,
  type RegistrationStore,
  type UserExistsError,
} from '@payload-auth-link/core'
import type { User } from '@auth/core/types'
import { errAsync, ResultAsync } from 'neverthrow'
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import type { Payload } from 'payload'
import { defaultAuthJsSlugs, type AuthJsCollectionSlugs } from './collections.js'
import { AdapterMappingError, AdapterOperationError, WeakPasswordError } from './errors.js'

/** Minimum credentials password length. Builders may raise it, never lower it. */
export const minCredentialsPasswordLength = 8

/**
 * Well-formed dummy hash for unknown users and hashless rows: `authorize`
 * runs the same scrypt verification against it, so those paths cost the
 * same as a wrong password and response timing reveals no account
 * existence. Constant salt, all-zero key — it verifies nothing and only
 * ever returns false; it just burns equal time.
 */
const dummyPasswordHash = `dummy:${'00'.repeat(32)}`

/**
 * Hash a credentials password (scrypt, random salt, `salt:derived`
 * format). Auth.js never sees passwords — hashing and verification live
 * here, beside the `passwordHash` column only this service reads.
 */
export function hashCredentialsPassword(password: string): string {
  const salt = randomBytes(16).toString('hex')
  return `${salt}:${scryptSync(password, salt, 32).toString('hex')}`
}

/** Constant-time verification. Malformed hashes fail closed (false). */
export function verifyCredentialsPassword(password: string, stored: string): boolean {
  const [salt, expected] = stored.split(':')
  if (salt === undefined || expected === undefined) {
    return false
  }
  const derived = Buffer.from(scryptSync(password, salt, 32).toString('hex'), 'hex')
  const wanted = Buffer.from(expected, 'hex')
  return derived.length === wanted.length && timingSafeEqual(derived, wanted)
}

/** Credentials service wiring: Payload access, slugs, password floor. */
export type AuthJsCredentialsDeps = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Override any default Auth.js collection slug. */
  readonly slugs?: Partial<AuthJsCollectionSlugs> | undefined
  /** Minimum password length. Defaults to 8; lower values are rejected. */
  readonly minPasswordLength?: number | undefined
  /** Logger for registration outcomes. Defaults to silent. */
  readonly logger?: LoggerPort | undefined
}

/** Builder-owned signup input; verification is builder policy. */
export type RegisterCredentialsUserInput = {
  readonly email: string
  readonly password: string
  readonly name?: string | undefined
  /**
   * Verification timestamp. Defaults to null (unverified): the plugin
   * refuses to link unverified identities, so credentials users stay
   * locked out until the builder verifies them — Auth.js has no email
   * flow for credentials, so verification is the builder's signup
   * policy, stamped here.
   */
  readonly emailVerified?: Date | null | undefined
}

/** What registration returns: stable id plus normalized email. */
export type RegisteredCredentialsUser = {
  readonly id: string
  readonly email: Email
}

/** Credentials service: `authorize` for the provider, `register` for signup. */
export type AuthJsCredentials = {
  /**
   * `authorize` for the Credentials provider: validates the credentials
   * against the users collection. Returns null for unknown users and
   * wrong passwords (normal login failure); throws `AdapterMappingError`
   * on corrupt stored rows (loud, not a silent login failure).
   */
  readonly authorize: (credentials: Record<string, unknown> | undefined) => Promise<User | null>
  /**
   * Register a credentials user (builder signup endpoints call this).
   * Flows through the core `registerWithStore` use-case over an
   * `aj-users` store: never throws, errors arrive as values —
   * `InvalidEmailError` / `WeakPasswordError` (400s), `UserExistsError`
   * (409), `AdapterOperationError` (500, storage failure with cause).
   */
  readonly register: (
    input: RegisterCredentialsUserInput
  ) => ResultAsync<
    RegisteredCredentialsUser,
    InvalidEmailError | WeakPasswordError | UserExistsError | AdapterOperationError
  >
}

/**
 * Credentials service over the Auth.js users collection. Auth.js's
 * Credentials provider stores nothing itself — `register` writes the
 * user row (scrypt hash, verification stamp) and `authorize` reads it
 * back. Works with any session strategy; the engine fail-fasts the
 * credentials+database combination Auth.js itself rejects.
 */
export function createAuthJsCredentials(deps: AuthJsCredentialsDeps): AuthJsCredentials {
  const slugs: AuthJsCollectionSlugs = resolveSlugs(defaultAuthJsSlugs, deps.slugs)
  const minPasswordLength = deps.minPasswordLength ?? minCredentialsPasswordLength
  if (minPasswordLength < minCredentialsPasswordLength) {
    throw new InvalidConfigError(
      `minPasswordLength must be at least ${minCredentialsPasswordLength}`
    )
  }

  const authorize: AuthJsCredentials['authorize'] = async (credentials) => {
    const email = credentials?.email
    const password = credentials?.password
    if (typeof email !== 'string' || typeof password !== 'string' || email === '') {
      return null
    }
    let payload: Payload
    try {
      payload = await deps.getPayload()
    } catch (error) {
      throw new AdapterOperationError('credentials authorize: getPayload', { cause: error })
    }
    let found
    try {
      found = await payload.find({
        collection: slugs.user,
        where: { email: { equals: email } },
        limit: 1,
        overrideAccess: true,
      })
    } catch (error) {
      throw new AdapterOperationError('credentials authorize: find', { cause: error })
    }
    const doc: unknown = found.docs[0]
    if (doc === undefined) {
      // Unknown email: run the dummy verification so this path costs the
      // same as a wrong password (no user-enumeration timing oracle).
      verifyCredentialsPassword(password, dummyPasswordHash)
      return null
    }
    if (!isRecord(doc)) {
      throw new AdapterMappingError('credentials authorize: user document is not an object')
    }
    if (typeof doc.auId !== 'string' || doc.auId === '') {
      throw new AdapterMappingError('credentials authorize: user has no auId')
    }
    // A hashless row verifies against the dummy (false, equal time) rather
    // than short-circuiting: same oracle, same fix.
    const stored = typeof doc.passwordHash === 'string' ? doc.passwordHash : dummyPasswordHash
    if (!verifyCredentialsPassword(password, stored)) {
      return null
    }
    if (typeof doc.email !== 'string' || doc.email === '') {
      throw new AdapterMappingError('credentials authorize: user has no email')
    }
    // Built as a variable: `User` carries no verification field, and the
    // jwt callback picks the smuggled claim up for the session body.
    const user = {
      id: doc.auId,
      email: doc.email,
      ...(typeof doc.name === 'string' ? { name: doc.name } : {}),
      emailVerified: typeof doc.emailVerified === 'string' ? new Date(doc.emailVerified) : null,
    }
    return user
  }

  type CredentialsCandidate = {
    readonly email: Email
    readonly name: string | null
    readonly passwordHash: string
    readonly emailVerified: Date | null
  }

  const store: RegistrationStore<CredentialsCandidate, { id: string }> = {
    findByEmail: (email) =>
      ResultAsync.fromPromise(
        (async () => {
          const payload = await deps.getPayload()
          const found = await payload.find({
            collection: slugs.user,
            where: { email: { equals: email } },
            limit: 1,
            overrideAccess: true,
          })
          const doc: unknown = found.docs[0]
          // Existence is what matters: even a malformed row blocks
          // re-registration (fail closed — the id is never used).
          return doc === undefined ? null : { id: 'exists' }
        })(),
        (cause) => new RepositoryError('credentials register: find', { cause })
      ),
    create: (candidate) =>
      ResultAsync.fromPromise(
        (async () => {
          const payload = await deps.getPayload()
          const created: unknown = await payload.create({
            collection: slugs.user,
            data: {
              auId: randomUUID(),
              email: candidate.email,
              ...(candidate.name === null ? {} : { name: candidate.name }),
              passwordHash: candidate.passwordHash,
              ...(candidate.emailVerified === null
                ? {}
                : { emailVerified: candidate.emailVerified.toISOString() }),
            },
            overrideAccess: true,
          })
          if (!isRecord(created) || typeof created.auId !== 'string') {
            throw new RepositoryError('credentials register: create returned no user')
          }
          return { id: created.auId }
        })(),
        (cause) =>
          cause instanceof RepositoryError
            ? cause
            : new RepositoryError('credentials register: create', { cause })
      ),
  }

  const register: AuthJsCredentials['register'] = (input) => {
    if (input.password.length < minPasswordLength) {
      return errAsync(new WeakPasswordError(minPasswordLength))
    }
    return registerWithStore(
      { store, logger: deps.logger ?? nullLogger() },
      {
        email: input.email,
        // Built only when no existing row is found, so duplicates skip
        // the scrypt hash — same as before, now enforced by the use-case.
        candidate: (email) => ({
          email,
          name: input.name ?? null,
          passwordHash: hashCredentialsPassword(input.password),
          emailVerified: input.emailVerified ?? null,
        }),
      }
    )
      .map(({ created, email }) => ({ id: created.id, email }))
      .mapErr((error) =>
        error instanceof RepositoryError
          ? new AdapterOperationError('credentials register', { cause: error })
          : error
      )
  }

  return { authorize, register }
}
