---
'@payload-auth-link/plugin': minor
---

Role-config safety (B11): removing a role from `authLink({ roles })`
now stops granting it at the next session instead of the next time a
user doc happens to be rewritten. Reads drop stored roles outside
the configured set (one `LoggerPort` warning per removed role,
naming it); a user whose only role was removed is denied a record
entirely — never silently upgraded to the default role. The first
boot after the change logs one aggregate startup audit warning
(`N user doc(s) carry roles outside the configured set: 'editor'
(2)`), so drift is visible without touching the data. Runbook for
removals and renames (drain first, then remove, then read the
audit) in docs/upgrading.md.

Upgrade impact: none for the database. Behavior change for anyone
relying on stored-but-unconfigured roles still granting: they stop
granting on upgrade. Re-add the role to the config to restore the
old behavior while you drain assignments.
