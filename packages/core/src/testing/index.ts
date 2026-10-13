/**
 * Test-only helpers for adapter authors. Import from
 * `@payload-auth-link/core/testing`; nothing here is runtime API and
 * nothing is re-exported from the core barrel.
 *
 * Packaging: this is a plain subpath export (`types` + `default`),
 * matching every other subpath in the workspace
 * (`@payload-auth-link/plugin/admin`, the providers' `./cookies`) —
 * no export condition, so the kit resolves identically under
 * bundler and NodeNext resolution. It is a separate entry, never
 * imported by `dist/index.js`, so it adds zero bytes to the core
 * runtime bundle; it carries its own `.size-limit.json` budget
 * (`core/testing`) so kit growth is still gated.
 */
export {
  assertProviderConformance,
  checkProviderConformance,
  ProviderConformanceError,
} from './provider-conformance.js'
export type {
  ConformanceCheckId,
  ConformanceViolation,
  ExpectedConformanceSession,
  ProviderConformanceFactory,
  ProviderConformanceScenarios,
  ProviderConformanceSubject,
} from './provider-conformance.js'
