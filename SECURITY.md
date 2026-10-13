# Security Policy

## Supported Versions

Pre-1.0: only the latest `0.x` release receives security fixes.

## Reporting a Vulnerability

Report security issues privately: open a private security advisory on
the repository host (or email the maintainers) instead of filing a
public issue. Include the affected package and version, reproduction
steps, and impact.

We aim to acknowledge within 72 hours and to ship a fix or mitigation
before any public disclosure. Please do not disclose until a fix is
released.

## Scope Notes

This project handles authentication sessions, cookies, and identity
linking (there are no webhooks; identity sync is read-time). Out of
scope: vulnerabilities in Payload CMS itself, in
identity providers (Better Auth, Auth.js, WorkOS, Clerk), or in host
applications consuming this plugin — report those upstream.
