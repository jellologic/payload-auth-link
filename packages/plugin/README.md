# @payload-auth-link/plugin

The Payload CMS plugin. It keeps your users as first-class Payload documents, extends the users collection with `roles` and linked `identities`, registers an auth strategy that resolves sessions from your identity provider, and adds CSRF-guarded session endpoints. It works on Payload v3 and v4.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/plugin
```

Peer dependencies: `payload` ^3.83.0 || 4.0.0-beta.0, `react` ^19.0.0, `@payloadcms/ui` ^3.83.0 || 4.0.0-beta.0.

ESM-only, Node 20.9 or later.

## What it provides

- `authLink(options)`: the plugin itself — session endpoints,
  verified-claim linking, impersonation with audit, MFA role
  policies, suspension, multi-session logout, optional
  Payload-owned organizations with SSO domain enforcement
- `@payload-auth-link/plugin/admin`: admin UI components (identity row labels)

## Usage

```ts
import { authLink } from '@payload-auth-link/plugin'
import { buildConfig } from 'payload'
import { engine } from './lib/auth' // a provider engine, e.g. Better Auth

export default buildConfig({
  // ...
  collections: [/* users, ... */ ...engine.collections],
  plugins: [
    authLink({
      baseUrl: 'https://example.com',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [engine.provider],
    }),
  ],
})
```

## Docs

- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Capabilities guide](https://github.com/jellologic/payload-auth-link/blob/main/docs/guide-capabilities.md)
- [Concepts](https://github.com/jellologic/payload-auth-link/blob/main/docs/concepts.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
