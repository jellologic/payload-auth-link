---
'@payload-auth-link/migrate': patch
---

The migrate CLI's `codemod --write` now writes the rewritten content to disk — it previously wrote the original file back, so `--write` reported the files as rewritten while changing nothing. `codemod`, `export` and `finalize` also no longer require `--config`, matching their documented usage (`codemod` needs `--src`, `export` needs `--database-url`, `finalize` is manifest-only).

Upgrade impact: none — schema, options, and the programmatic `applyCodemods` result gain an additive `after` field only. CLI users running `codemod --write` get the rewrite they were promised; no stored data is touched.
