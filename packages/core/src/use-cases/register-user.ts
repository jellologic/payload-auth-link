import { errAsync, type ResultAsync } from 'neverthrow'
import { parseEmail, type Email } from '../email.js'
import { InvalidEmailError, RepositoryError, UserExistsError } from '../errors.js'
import type {
  LoggerPort,
  NewUser,
  ProviderIdentityRef,
  UserRecord,
  UserRepository,
} from '../ports.js'
import type { Role } from '../roles.js'

export type RegisterUserDeps = {
  readonly users: UserRepository
  readonly logger: LoggerPort
}

export type RegisterUserInput = {
  readonly email: Email
  readonly roles: readonly Role[]
  readonly identity?: ProviderIdentityRef | undefined
}

/**
 * Register a new user. Pure domain flow over injected ports: rejects
 * duplicates with {@link UserExistsError}, persists via the repository,
 * and logs the outcome. Linking extra identities is a separate operation.
 */
export function registerUser(
  deps: RegisterUserDeps,
  input: RegisterUserInput
): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
  const candidate: NewUser = {
    email: input.email,
    roles: input.roles,
    identity: input.identity,
  }
  return deps.users.findByEmail(input.email).andThen((existing) => {
    if (existing) {
      deps.logger.warn('registration rejected: user exists', { email: input.email })
      return errAsync(new UserExistsError(input.email))
    }
    return deps.users.create(candidate).map((user) => {
      deps.logger.info('user registered', { userId: user.id, email: user.email })
      return user
    })
  })
}

/**
 * Registration-relevant subset of {@link UserRepository}: the two
 * operations registration needs. Plugin flows pass their repository
 * (which satisfies this structurally); provider flows implement it over
 * their own collections, whose row shapes (`auId`, `passwordHash`, …)
 * are not `NewUser`/`UserRecord` and must stay provider-owned.
 */
export type RegistrationStore<TCandidate, TCreated> = {
  findByEmail(email: Email): ResultAsync<TCreated | null, RepositoryError>
  create(candidate: TCandidate): ResultAsync<TCreated, RepositoryError | UserExistsError>
}

export type RegisterWithStoreDeps<TCandidate, TCreated> = {
  readonly store: RegistrationStore<TCandidate, TCreated>
  readonly logger: LoggerPort
}

export type RegisterWithStoreInput<TCandidate> = {
  /** Raw email; parsed (and normalized) here so stores see `Email` only. */
  readonly email: string
  /** Build the store candidate from the parsed email. Runs only when no existing row is found, so expensive construction (password hashing) is skipped for duplicates. */
  readonly candidate: (email: Email) => TCandidate
}

export type RegisteredWithStore<TCreated> = {
  readonly created: TCreated
  readonly email: Email
}

/**
 * Register through an injected store: the provider-registration flow.
 * Parses the email, rejects duplicates with {@link UserExistsError} (a
 * lost create race surfaces the same error — the caller learns the email
 * is taken, no retry needed), persists via the store, and logs the
 * outcome. Never throws; storage failures arrive as
 * {@link RepositoryError} for the caller to map to its own taxonomy.
 */
export function registerWithStore<TCandidate, TCreated>(
  deps: RegisterWithStoreDeps<TCandidate, TCreated>,
  input: RegisterWithStoreInput<TCandidate>
): ResultAsync<
  RegisteredWithStore<TCreated>,
  InvalidEmailError | UserExistsError | RepositoryError
> {
  const email = parseEmail(input.email)
  if (email.isErr()) {
    return errAsync(email.error)
  }
  const parsed = email.value
  return deps.store.findByEmail(parsed).andThen((existing) => {
    if (existing) {
      deps.logger.warn('registration rejected: user exists', { email: parsed })
      return errAsync(new UserExistsError(parsed))
    }
    return deps.store.create(input.candidate(parsed)).map((created) => {
      deps.logger.info('user registered', { email: parsed })
      return { created, email: parsed }
    })
  })
}
