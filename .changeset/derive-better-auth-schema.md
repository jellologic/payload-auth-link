---
'@payload-auth-link/provider-better-auth': minor
---

Derive `customFields`/`customModels` from Better Auth's own schema
(issue #17). New `deriveBetterAuthSchema(options)` (built on
`getAuthTables` from `better-auth/db` — the same source the adapter
validates against, so a derived declaration cannot disagree with
what BA asks for), `declarationsFromTables(tables)` for the pure
step, and `createBetterAuthEngine({ autoDeclare: true })`, which
derives and merges **under** the builder's explicit declarations —
a hand-pinned field always wins, the derived remainder fills the
gaps. Semantics: arrays/unknown BA types map to JSON; enum-valued
attributes stay text (BA owns value validation); a BA `defaultValue`
keeps the column nullable; renames (`modelName`/`fieldName`) throw
with a declare-by-hand pointer. Strict hand-declared mode is
unchanged. `examples/basic` switches to `autoDeclare: true`; the
capabilities guide documents the recipe and the snapshot-test drift
alarm.

Upgrade impact: none — `autoDeclare` is opt-in and hand declarations
are unchanged.
