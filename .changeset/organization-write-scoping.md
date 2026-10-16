---
'@payload-auth-link/plugin': minor
---

Organization writes are scoped more tightly, and the last-owner guard holds under concurrency.

- Bulk `PATCH`/`DELETE /api/organizations?where=…` (no document id) is scoped to the organizations the caller manages (owns, for delete). Before this change, organization update access read the organization id from the request body when no id was present, so a manager of one organization could rewrite other organizations through a bulk update.
- Deleting an organization is owner-only. It removes every membership, the owners' included, which an `admin` must not be able to do.
- `verifiedDomains` can be written only by Payload role managers (`roleManagerRoles`), and never while impersonating. A listed domain admits SSO sign-ins (CAP-15) for every address on it, for every registered SSO provider, so organization owners can no longer list one themselves.
- Two owners removing or demoting each other at the same moment can no longer leave an organization without an owner. Each removal writes (locks) the organization row before counting owners, and re-counts after its write. If no owner is left, it restores the row and answers `409`.
- Accepting an invitation after joining the organization another way answers `409` (`user is already a member`) instead of a storage validation error.

Upgrade impact: no schema change. No column is added, removed or retyped on any adapter, so push and migrations have nothing to do. Behavioural: org admins get `403` on organization delete; `verifiedDomains` writes from non-role-managers are ignored, so review existing entries once after upgrading; owner removals bump the organization's `updatedAt`. See docs/upgrading.md.
