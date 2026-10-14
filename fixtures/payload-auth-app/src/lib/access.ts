// Scan target (never executed): access functions reading fields off
// req.user that are NOT in the auth-link session projection — the
// silent-drift list the doctor reports (#57 opts into the full
// document).
import type { PayloadRequest } from 'payload'

export function canEdit(request: PayloadRequest): boolean {
  if (request.user === null) {
    return false
  }
  const org = request.user.activeOrganization
  return typeof org === 'object' && org !== null && request.user.name !== ''
}
