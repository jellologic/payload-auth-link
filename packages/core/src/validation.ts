import { err, ok, type Result } from 'neverthrow'
import { z } from 'zod'
import { InvalidCollectionMapError, InvalidConfigError } from './errors.js'
import { providerIdSchema, type ProviderId } from './ports.js'
import { roleSchema, type Role } from './roles.js'

function issueDetail(error: z.ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
    .join('; ')
}

const slugSchema = z.string().min(1, 'must not be empty').max(100)

/**
 * Typed map from the domain to Payload collection/field slugs.
 * Explicit and strict: unknown keys are rejected, never silently ignored.
 */
export const collectionMapSchema = z
  .object({
    usersCollection: slugSchema,
    emailField: slugSchema,
    rolesField: slugSchema,
    identitiesField: slugSchema,
  })
  .strict()

/** Validated slug/field map from {@link collectionMapSchema}. */
export type CollectionMap = z.output<typeof collectionMapSchema>

/** Parse a collection map; strict — unknown keys fail, never ignored. */
export function parseCollectionMap(
  value: unknown
): Result<CollectionMap, InvalidCollectionMapError> {
  const parsed = collectionMapSchema.safeParse(value)
  if (!parsed.success) {
    return err(new InvalidCollectionMapError(issueDetail(parsed.error)))
  }
  return ok(parsed.data)
}

/**
 * Startup config, validated once at composition-root wiring time.
 * Invalid config fails fast here instead of misbehaving at runtime.
 */
export const startupConfigSchema = z
  .object({
    baseUrl: z.url('must be a valid URL'),
    roles: z.array(roleSchema).min(1, 'at least one role is required'),
    defaultRole: roleSchema,
    providers: z.array(providerIdSchema).min(1, 'at least one provider is required'),
    map: collectionMapSchema,
  })
  .strict()
  .refine((config) => config.roles.includes(config.defaultRole), {
    message: 'defaultRole must be one of roles',
    path: ['defaultRole'],
  })

/** Validated startup config from {@link startupConfigSchema}. */
export type StartupConfig = z.output<typeof startupConfigSchema>

/**
 * Validate startup config once at wiring time. Fails fast on bad
 * URLs, empty roles, default-role-not-in-roles, or zero providers.
 */
export function validateStartupConfig(value: unknown): Result<StartupConfig, InvalidConfigError> {
  const parsed = startupConfigSchema.safeParse(value)
  if (!parsed.success) {
    return err(new InvalidConfigError(issueDetail(parsed.error)))
  }
  return ok(parsed.data)
}

export type { ProviderId, Role }
