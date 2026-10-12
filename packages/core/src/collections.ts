import { InvalidConfigError } from './errors.js'

/**
 * System-collection building blocks shared by provider packages: slug
 * resolution and validation plus the deny-all access default. Structural
 * types only — core never imports Payload (see DNA §3).
 */

/**
 * Merge slug overrides over provider defaults. Rejects empty and
 * non-string slugs plus unknown model keys at wiring time: a typo'd
 * override otherwise points the adapter at a missing collection and fails
 * deep in a query instead of here.
 */
export function resolveSlugs<TSlugs extends Record<string, string>>(
  defaults: TSlugs,
  overrides?: Partial<TSlugs>
): TSlugs {
  if (overrides !== undefined) {
    for (const model of Object.keys(overrides)) {
      if (!(model in defaults)) {
        throw new InvalidConfigError(`unknown model "${model}" in slug overrides`)
      }
    }
  }
  const resolved: Record<string, string> = { ...defaults, ...overrides }
  for (const [model, slug] of Object.entries(resolved)) {
    if (typeof slug !== 'string' || slug === '') {
      throw new InvalidConfigError(`slug for model "${model}" must be a non-empty string`)
    }
  }
  return resolved as TSlugs
}

/**
 * Reject slug collisions: two models sharing one collection corrupt each
 * other's reads. Run over the final slug record (core plus custom models).
 */
export function assertUniqueSlugs(slugs: Readonly<Record<string, string>>, owner: string): void {
  const seen = new Map<string, string>()
  for (const [model, slug] of Object.entries(slugs)) {
    const first = seen.get(slug)
    if (first !== undefined) {
      throw new InvalidConfigError(
        `${owner}: models "${first}" and "${model}" share slug "${slug}"`
      )
    }
    seen.set(slug, model)
  }
}

/** Payload collection access shape, structurally: four deny decisions. */
export type DenyAllAccess = {
  readonly create: () => boolean
  readonly read: () => boolean
  readonly update: () => boolean
  readonly delete: () => boolean
}

/**
 * Fresh deny-all access for system collections (sessions, tokens,
 * hashes): only the adapter touches them, via `overrideAccess`. Fresh
 * object per call — never share one across collections.
 */
export function denyAllAccess(): DenyAllAccess {
  return {
    create: () => false,
    read: () => false,
    update: () => false,
    delete: () => false,
  }
}
