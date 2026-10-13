---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

Type-safe upgrade alarms and schema interoperability (upgrade-resilience Phase 3b):

- Core: `authMethods` exported as the single source for `AuthMethod` and the session wire enum; `sessionChannels` is now a const tuple with `SessionChannel` derived from it; `LinkingPolicy` derives from `linkingPolicySchema`. Union/schema drift now fails typecheck instead of degrading sessions at runtime.
- Core: `parseSessionUser` accepts `ParseSessionUserOptions.onDegrade` with a typed `SessionUserDegradeReason`, so producer/consumer version skew (e.g. an unknown auth method from a newer server) is observable instead of silent. Default behavior is unchanged.
- Core: every exported Zod schema is pinned as a Standard Schema v1 (`@standard-schema/spec` added); Zod and Effect Schema compose through `~standard`. Effect interop is covered by a CI test with `effect` as a devDependency only. The `zod: ^4.0.0` floor and a consumer TypeScript floor of 5.5 are now probe-proven and documented.
- Plugin: stored-row mapping warnings aggregate once per kind per logger instead of once per corrupt row.
- Better Auth provider: exhaustive `assertNever` guards on custom-field types and where operators, so new upstream variants fail CI typecheck.
- Repo gates: public-API `.d.ts` snapshots (`bun run api:check`) and a `skipLibCheck: false` consumer fixture (`bun run consumer:check`) now run in `bun run check`.
