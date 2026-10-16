---
'@payload-auth-link/plugin': minor
---

`reset-password` (REST, GraphQL `resetPasswordUser`, Local API) for a
SUSPENDED account is now refused (401) in `beforeOperation`, before
Payload writes anything. Payload's reset operation stores the new
password and clears the account's sessions before it runs
`beforeLogin`, so on adapters where that write is not rolled back the
previous `beforeLogin` refusal came too late: the "refused" reset had
already rotated the credential, which then worked as soon as the
suspension lapsed. The check applies whatever
`allowLocalCredentialsForLinkedDocs` says, and the guard's lookup now
runs inside the operation's transaction (`req`).
