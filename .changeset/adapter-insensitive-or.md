---
'@payload-auth-link/provider-better-auth': minor
---

The Better Auth adapter now refuses (`UnsupportedOperatorError`) a
case-insensitive `eq` combined with an `OR` connector instead of
silently returning too few rows: the exactness post-filter ran over the
whole result, dropping rows the other `OR` branch admitted. Found by a
new differential suite that runs the adapter against Better Auth's
`memoryAdapter`. Better Auth core issues no such query; plugin or app
code that did now gets a loud error. String sort collation is now
documented: ordering follows the database (binary on SQLite/MongoDB),
not the memory adapter's `localeCompare`.
