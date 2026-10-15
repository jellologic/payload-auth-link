---
'@payload-auth-link/migrate': minor
---

Off-ramp (issue #58): `bunx @payload-auth-link/migrate export
--database-url URL [--out file.jsonl]` exports every auth table
losslessly as JSONL — every column (plugin-injected fields,
credential hashes, role child rows) typed as stored, re-importable
without transformation. The uninstall path is a supported operation
with a CI-validated test (plugin removed → users/content intact on
the same database) and documentation of every plugin-injected field.
