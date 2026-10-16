---
'@payload-auth-link/plugin': patch
---

An email collision during just-in-time provisioning is recognised structurally, not with `instanceof`, so it is still handled when the host app and the plugin load different copies of `payload` (e.g. a Payload v4 app). Before, the collision surfaced as a raw storage error there and the lost-create-race retry never ran: when two first requests after sign-up raced, one came back signed out.
