# Security Policy

## Supported Versions

Pre-1.0: only the latest `0.x` release receives security fixes.

## Reporting a Vulnerability

**Do not file a public issue, pull request, or discussion.**

Report privately through GitHub's private vulnerability reporting:

**<https://github.com/jellologic/payload-auth-link/security/advisories/new>**

(Repository → **Security** tab → **Report a vulnerability**.) The
report stays visible only to you and the maintainers, and the fix is
coordinated in a private advisory with a CVE requested where
applicable.

Include the affected package(s) and version(s), reproduction steps or a
proof of concept, and the impact you see (what an attacker gains).

If you cannot use GitHub's form, contact the maintainer through the
[@jellologic GitHub profile](https://github.com/jellologic) to arrange
another private channel. There is no dedicated security email address.

### Response times

| Step                            | Target                                 |
| ------------------------------- | -------------------------------------- |
| Acknowledge the report          | within 3 business days                 |
| Triage + severity assessment    | within 7 days                          |
| Fix or mitigation for High/Crit | within 30 days (sooner when exploited) |
| Public advisory (credits you)   | when the fixed release is out          |

Please do not disclose publicly until a fixed release is available.
We will keep you updated at each step; if a deadline slips, we will
tell you why and the new date.

## Release integrity

Every published `@payload-auth-link/*` version is built and published
by this repository's `release` workflow after CI passes, through npm
trusted publishing with provenance. Verify a version with
`npm audit signatures`, or `bun run verify:published <version>
--expect-provenance` from a checkout. A version without provenance
was published through the documented emergency path and is called out
in its release notes.

## Scope Notes

This project handles authentication sessions, cookies, and identity
linking (there are no webhooks; identity sync is read-time). Out of
scope: vulnerabilities in Payload CMS itself, in
identity providers (Better Auth, Auth.js, WorkOS, Clerk), or in host
applications consuming this plugin — report those upstream.
