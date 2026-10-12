# Compatibility

Pinned versions are the validated set; ranges are what the package
manifests allow. CI runs the full matrix (unit + e2e on SQLite,
Postgres service, and mongo memory replset).

## Runtimes and frameworks

| Dependency                               | Validated           | Range                       | Notes                                                                |
| ---------------------------------------- | ------------------- | --------------------------- | -------------------------------------------------------------------- |
| `payload`                                | 3.90.2              | `^3.0.0` (peer)             | v3 for Next; plugin also loads on v4 beta with zero changes          |
| `payload` (Start)                        | 4.0.0-beta.0        | narrow beta pin (example)   | `@payloadcms/tanstack-start` exists only on the v4 line              |
| `next`                                   | 16.4.0              | `>=15.0.0` (peer, next pkg) | App router; `middleware.ts` (proxy-safe)                             |
| `@tanstack/react-start` / `react-router` | 1.168.61 / 1.170.41 | peer (start pkg)            | File routes, server functions, request middleware                    |
| `vite` (Start)                           | 8.3.4               | dev (example)               | + `@vitejs/plugin-rsc`, `react-server-dom-webpack` for Payload admin |
| `react` / `react-dom`                    | 19.2.6              | `^19.0.0` (peer, UI pkgs)   |                                                                      |
| `better-auth`                            | 1.7.7               | provider dep                | Ships with the provider; install directly only to import it yourself |
| `@auth/core`                             | 0.41.3              | provider dep                | Raw core, not the `next-auth` wrapper                                |
| `neverthrow`                             | 8.2.0               | dep                         | `Result`/`ResultAsync` throughout                                    |
| `zod`                                    | 4.6.5               | dep                         | Boundary schemas + branded types                                     |
| `bun`                                    | 1.4.2               | `packageManager`            | CI pins the same                                                     |
| `node`                                   | 20.9+ / 22          | `engines`                   | All packages ESM-only (`type: module`)                               |

Module resolution: shipped code builds under `nodenext`, except
`@payload-auth-link/next`, which uses `esnext`/`bundler` because
Next.js ships no `exports` map for `next/*` subpaths. Tests run
under bundler resolution for the same reason.

## Databases

| Adapter                   | Validated how                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `@payloadcms/db-sqlite`   | Unit integration (in-memory) + `bun run e2e`                                          |
| `@payloadcms/db-postgres` | `bun run e2e:postgres` (per-run database, `push: true`), GH service in CI             |
| `@payloadcms/db-mongodb`  | `bun run e2e:mongo` (per-run wiredTiger memory replset, transactions off — see below) |

Product code issues only single-document Local API calls, so the
parity risk sits in Where translation, date serialization, and id
types — all six suites assert identical behavior (23 specs each:
`e2e`, `e2e:postgres`, `e2e:mongo` on Next; `e2e:tanstack`,
`e2e:tanstack-postgres`, `e2e:tanstack-mongo` on Start). Each
example's mongo branch disables Payload transactions: several
Payload instances (plugin + provider loaders) lock-fight on a
single-node memory server. Production mongo deployments keep
transactions on; nothing we ship depends on their absence.

## Browsers

The SQLite suites (`e2e`, `e2e:tanstack`) run in Chromium, Firefox,
and WebKit (Playwright Desktop Chrome / Firefox / Safari profiles),
one engine after another against the same server. Postgres and Mongo
suites run Chromium only. Traces are kept on failure; CI retries
exist as a backstop, but specs pass with retries off. The shipped UI
is unstyled primitives with no browser-specific APIs beyond `fetch`
and `location`.

## Type surface

`attw --profile esm-only` + `publint` gate every package
(`bun run release:check`). Legacy node10/CJS resolution is the
documented non-goal: ESM-only by decision.
