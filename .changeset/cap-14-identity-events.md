---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/provider-authjs': minor
---

CAP-14 identity lifecycle foundation: core `IdentityEvent` union and
`applyIdentityEvent` use-case. Verified provider email changes sync to
Payload (D9); unverified changes are ignored. Provider unlink/delete
removes only the identity row via the new required
`UserRepository.unlinkIdentity` — the Payload user always remains.
Adapters may expose `IdentityProviderPort.onIdentityEvent`; the plugin
subscribes at `onInit`. Custom `UserRepository` implementations must
add `unlinkIdentity` (pre-1.0 minor break for port implementers).

Both provider adapters now translate lifecycle hooks: Better Auth
`databaseHooks` (user update/delete, account delete; builder hooks
preserved, plus `revokeSessionsOnPasswordReset` defaults on) and
Auth.js `events` (`updateUser`, `linkAccount` — upstream never fires
unlink/delete events, so Auth.js emits no unlink/delete facts).
