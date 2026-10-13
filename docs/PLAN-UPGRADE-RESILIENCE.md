# Upgrade Resilience Plan (completed 2026-10-13, shipped in 0.3.0)

Every checklist item from the 2026-10-13 deep dive landed and was
validated (unit + golden-DB on SQLite/Postgres/Mongo, compat matrix
{floor, latest} green, e2e on both examples in Chromium and WebKit,
consumer-install smoke, then released). The durable guidance lives in
the docs; this file remains only as the index of what moved where.

| Plan area (B-refs)                                                       | Now lives in                                                                                                          |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Upgrade-safe shapes; golden-DB suites; per-adapter steps (B1, B2, B6-B9) | `docs/upgrading.md` (0.1.1 → 0.2.0, rolling deploys), `packages/*/src/__tests__/upgrade-golden*`, `snapshots/schema/` |
| Version-range honesty, floors, assertions (B3, B4, B10, B13)             | `docs/compatibility.md` (bands = matrix), `supported*Band` constants, `.github/workflows/compat.yml`                  |
| BA satellite lockstep (B12)                                              | `docs/compatibility.md`, provider READMEs                                                                             |
| Schema-change policy + snapshot gate (Phase 2)                           | `AGENTS.md` § Schema changes, `bun run schema:check`                                                                  |
| Type-safe alarms, Standard Schema/Effect interop (B15-B22)               | `docs/compatibility.md` § Type surface + § Schema interoperability                                                    |
| Role-config safety (B11)                                                 | `docs/upgrading.md` § Changing or removing roles, plugin `role-audit.ts`                                              |
| Production migrations, consumer smoke, deploy skew (Phase 2)             | `docs/upgrading.md` § migrations recipe, `bun run release:smoke`                                                      |
| Support policy + release checklist (Phase 4)                             | `docs/compatibility.md` (intro), `docs/releasing.md`                                                                  |
