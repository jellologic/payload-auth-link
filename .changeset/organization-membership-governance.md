---
'@payload-auth-link/plugin': minor
---

Organization membership governance is enforced on every write path.

- A membership's `organization` and `user` are immutable after create: field access drops REST/GraphQL/admin writes, and a `beforeChange` guard throws for any other writer, trusted Local-API calls with `overrideAccess` included. The only sanctioned `user` write is the plugin's own invite acceptance binding the verified user to their pending invitation. Previously a manager of one organization could move their own membership into another organization (as owner) or re-point a membership at any user.
- Membership create/update/delete and invites require a manager of the row's organization and never grant a role above the caller's own (`orgRoles` order is the rank): an `admin` can no longer promote anyone (themselves included) to owner, nor edit or remove an owner's membership.
- An organization always keeps an active owner: demoting or removing the last one answers a typed `409`.
- `DELETE /api/organizations/:id` cascades the organization's memberships and pending invitations in the same request instead of failing with a 500.
- While an operator impersonates a user, organization updates/deletes, every membership write, and the invite / accept / create endpoints are refused (`403`); endpoint attempts are audited through the logger and `onAudit` with `denied: true` and the endpoint path (collection operations keep their existing per-operation audit).

Upgrade impact: no schema change — no column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Behavioural: Local-API scripts that re-pointed memberships must delete and re-create the row; a sole owner must promote a second owner before stepping down. See docs/upgrading.md.
