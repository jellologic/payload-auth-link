/**
 * Adapter-contract exhaustiveness (Phase 3, the issue-#160 class).
 * Every method on BA's `CustomAdapter` except the last four is
 * required, but the optional tail (`consumeOne`, `incrementOne`,
 * `createSchema`, `options`) proves the real trap: an upstream BA
 * minor can add a method or flip an optional one to required, and
 * the `satisfies CustomAdapter` in `adapter.ts` typechecks silently
 * either way. A NEW upstream method also passes `satisfies` — it is
 * simply missing at runtime and BA calls it per request. This pin
 * fails `tsc` on any change to the method inventory so the gap is
 * found in CI, not in production.
 *
 * If this fails after a better-auth bump: implement the new method
 * (or consciously leave it unimplemented and document why), extend
 * the conformance coverage in `conformance.test.ts` / the probe,
 * then update this pin.
 */
import type { CustomAdapter } from 'better-auth/adapters'
import { describe, expectTypeOf, it } from 'vitest'

describe('CustomAdapter inventory alarm (Phase 3)', () => {
  it('pins keyof CustomAdapter: upstream method changes fail typecheck here', () => {
    expectTypeOf<keyof CustomAdapter>().toEqualTypeOf<
      | 'create'
      | 'findOne'
      | 'findMany'
      | 'update'
      | 'updateMany'
      | 'delete'
      | 'deleteMany'
      | 'count'
      | 'consumeOne'
      | 'incrementOne'
      | 'createSchema'
      | 'options'
    >()
  })

  it('implements the full required surface (optional tail consciously absent)', () => {
    // `consumeOne` and `incrementOne` stay optional in 1.7.x: BA falls
    // back to find-then-write when they are absent. If a bump makes
    // either required, the `satisfies CustomAdapter` in adapter.ts
    // breaks here first — implement it then, with an integration test
    // for the operation it serves.
    type RequiredMethods = {
      [K in keyof CustomAdapter]-?: undefined extends CustomAdapter[K] ? never : K
    }[keyof CustomAdapter]
    expectTypeOf<RequiredMethods>().toEqualTypeOf<
      | 'create'
      | 'findOne'
      | 'findMany'
      | 'update'
      | 'updateMany'
      | 'delete'
      | 'deleteMany'
      | 'count'
    >()
  })
})
