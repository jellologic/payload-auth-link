---
'@payload-auth-link/plugin': minor
---

Docs-drift sweep (issue #19) plus one developer-experience widening:

- `requireOrgRole` accepts **plain role slugs and plain wiring**:
  roles are parsed fail-closed (`InvalidRoleError` on a bad entry,
  like `requireRoles`), and the wiring parameter is a structural
  subset (`organizationsCollection` + `membershipsCollection`, extra
  fields accepted) — the capabilities guide's snippet now
  type-checks as written, and the validated wiring from
  `authLink({ organizations })` still satisfies it.
- README peer ranges are generated from the manifests and
  `check-docs` now fails when a README states a peer range the
  manifest does not (the drift that started this issue).
- getting-started says `better-auth` is a peer (since 0.3.0), not a
  bundled dependency; MISSION.md no longer promises admin session
  views or webhook sync (none exist, by design); SECURITY.md and
  PLAN.md drop webhook wording; PLAN.md marks sessions views/admin
  revoke as deferred so PLAN and MISSION agree.

Upgrade impact: none — the `requireOrgRole` signature is widened, so
existing call sites (including branded-role callers) compile
unchanged.
