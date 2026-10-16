---
'@payload-auth-link/plugin': patch
---

`req.user.id` for provider sessions now carries the database's id type (a number on SQLite/Postgres) instead of always a string. Payload v4 fills `createdBy`/`updatedBy` relationships from `req.user`, so on number-id adapters every create by a provider-signed-in user, the organization endpoint included, failed validation (400). The session endpoint's JSON is unchanged.

The MFA role gate reads and writes `req.user.roles` through a record, so the plugin type-checks against Payload v4's `AuthenticatedUser` as well as v3.
