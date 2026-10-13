import type { SessionAssurance } from './ports.js'
import type { Role } from './roles.js'

/**
 * Pure session-policy decisions (CAP-6/CAP-7), shared by the plugin's
 * role projection and the web authorization helpers so the two can
 * never drift. Every function here fails closed: absent or `'unknown'`
 * assurance never satisfies a policy requiring proof (risk R3).
 */

/** Whether an assurance fact proves multi-factor authentication. */
export function mfaSatisfied(assurance: SessionAssurance | undefined): boolean {
  return assurance !== undefined && assurance.mfa === true
}

/**
 * The roles a session may exercise under a `requireMfaForRoles`
 * policy: when MFA is not satisfied, the listed roles are withheld
 * (the stored roles are untouched — this is a per-session view, so a
 * later MFA-proven session sees the full set again). Returns the
 * input array unchanged when the policy is empty or satisfied.
 */
export function effectiveRoles(
  roles: readonly Role[],
  assurance: SessionAssurance | undefined,
  requireMfaForRoles: readonly Role[]
): readonly Role[] {
  if (requireMfaForRoles.length === 0 || mfaSatisfied(assurance)) {
    return roles
  }
  const gated = new Set<Role>(requireMfaForRoles)
  return roles.filter((role) => !gated.has(role))
}

/** The gated roles {@link effectiveRoles} withholds for this session. */
export function withheldRoles(
  roles: readonly Role[],
  assurance: SessionAssurance | undefined,
  requireMfaForRoles: readonly Role[]
): readonly Role[] {
  if (requireMfaForRoles.length === 0 || mfaSatisfied(assurance)) {
    return []
  }
  const gated = new Set<Role>(requireMfaForRoles)
  return roles.filter((role) => gated.has(role))
}

/**
 * Whether a suspension is in force at `now` (CAP-7). `null` /
 * `undefined` means not suspended; a past instant means the
 * suspension has lapsed and the user is admitted again without any
 * operator action.
 */
export function isSuspendedAt(suspendedUntil: Date | null | undefined, now: Date): boolean {
  return (
    suspendedUntil !== null &&
    suspendedUntil !== undefined &&
    suspendedUntil.getTime() > now.getTime()
  )
}

/** The lowercase domain part of an email address (after the last `@`). */
export function emailDomainOf(email: string): string {
  return email.slice(email.lastIndexOf('@') + 1).toLowerCase()
}

/**
 * Whether an email may link through enterprise SSO (CAP-15): its
 * domain must be one of the organization's VERIFIED domains. Exact
 * match only — subdomains do not inherit trust (`mail.example.com`
 * does not satisfy `example.com`), and an empty domain list admits
 * nothing (fail closed): a tenant-registered IdP can assert verified
 * emails for anyone, so the verified domain is the boundary.
 */
export function emailDomainAllowed(email: string, verifiedDomains: readonly string[]): boolean {
  const domain = emailDomainOf(email)
  return domain !== '' && verifiedDomains.some((candidate) => candidate.toLowerCase() === domain)
}
