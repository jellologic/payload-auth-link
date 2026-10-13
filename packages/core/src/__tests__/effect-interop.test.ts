/**
 * Effect interoperability proof (PLAN-UPGRADE-RESILIENCE Phase 3b,
 * B21). `effect` is a devDependency of this package only: shipped
 * core source never imports it (lint boundaries + the size budget
 * prove that). This file pins the documented recipe so an upstream
 * Effect or Zod change that breaks interop fails here, in CI,
 * instead of in an Effect user's build.
 *
 * The bridge is Standard Schema in both directions:
 * - core's Zod schemas are consumed through `~standard.validate`
 *   inside an `Effect` (works identically for Valibot/ArkType), and
 * - an Effect `Schema` converted with `Schema.standardSchemaV1`
 *   passes through the exact same boundary helper.
 * neverthrow `ResultAsync` port calls lift into `Effect` via
 * `Effect.tryPromise` + `Result.match`, keeping the typed error.
 */
import type { StandardSchemaV1 } from '@standard-schema/spec'
import { Effect, Either, Schema } from 'effect'
import { errAsync, okAsync, type Result } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { emailSchema, type Email } from '../email.js'
import { InvalidEmailError } from '../errors.js'
import { startupConfigSchema, type StartupConfig } from '../validation.js'

/** Decode unknown input with any Standard Schema inside an Effect. */
function decodeStandard<A>(
  schema: StandardSchemaV1<unknown, A>,
  value: unknown
): Effect.Effect<A, string> {
  return Effect.tryPromise({
    try: () => Promise.resolve(schema['~standard'].validate(value)),
    catch: () => 'validate threw',
  }).pipe(
    Effect.flatMap((result) =>
      result.issues === undefined
        ? Effect.succeed(result.value)
        : Effect.fail(result.issues.map((issue) => issue.message).join('; '))
    )
  )
}

/**
 * Lift a neverthrow `ResultAsync` port call into an `Effect`.
 * `ResultAsync` values never reject by contract (failures are `Err`
 * values), so `Effect.promise` is sound here; a foreign thenable
 * that did reject would surface as a defect, not a typed error.
 */
function fromResultAsync<A, E>(result: PromiseLike<Result<A, E>>): Effect.Effect<A, E> {
  return Effect.promise(() => Promise.resolve(result)).pipe(
    Effect.flatMap((resolved) =>
      resolved.isOk() ? Effect.succeed(resolved.value) : Effect.fail(resolved.error)
    )
  )
}

const validConfig = {
  baseUrl: 'https://example.com',
  roles: ['user', 'admin'],
  defaultRole: 'user',
  providers: ['better-auth'],
  map: {
    usersCollection: 'users',
    emailField: 'email',
    rolesField: 'roles',
    identitiesField: 'identities',
  },
}

describe('Effect interop via Standard Schema', () => {
  it('decodes a core Zod schema inside an Effect, typed end to end', async () => {
    const program = Effect.gen(function* () {
      const email: Email = yield* decodeStandard(emailSchema, 'a@b.co')
      const config: StartupConfig = yield* decodeStandard(startupConfigSchema, validConfig)
      return `${email} @ ${config.baseUrl}`
    })
    await expect(Effect.runPromise(program)).resolves.toBe('a@b.co @ https://example.com')
  })

  it('fails in the Effect error channel (never throws) on invalid input', async () => {
    const result = await Effect.runPromise(Effect.either(decodeStandard(emailSchema, 'nope')))
    expect(Either.isLeft(result)).toBe(true)
    if (Either.isLeft(result)) {
      expect(result.left).toContain('email')
    }
  })

  it('accepts an Effect Schema through the same boundary helper', async () => {
    const Port = Schema.standardSchemaV1(Schema.Struct({ port: Schema.Number }))
    await expect(Effect.runPromise(decodeStandard(Port, { port: 3100 }))).resolves.toEqual({
      port: 3100,
    })
    const rejected = await Effect.runPromise(Effect.either(decodeStandard(Port, { port: '3100' })))
    expect(Either.isLeft(rejected)).toBe(true)
  })

  it('lifts ResultAsync port calls into Effect, preserving typed errors', async () => {
    await expect(Effect.runPromise(fromResultAsync(okAsync(42)))).resolves.toBe(42)

    const failure = await Effect.runPromise(
      Effect.either(fromResultAsync(errAsync(new InvalidEmailError('bad'))))
    )
    expect(Either.isLeft(failure)).toBe(true)
    if (Either.isLeft(failure)) {
      expect(failure.left).toBeInstanceOf(InvalidEmailError)
      expect(failure.left.code).toBe('INVALID_EMAIL')
    }
  })
})
