# @payload-auth-link/react

Provider-agnostic React UI for payload-auth-link: a session context plus unstyled sign-in, sign-out, and user-menu components. It has no Next.js or Payload imports, so it works under any framework adapter.

Part of [payload-auth-link](https://github.com/jellologic/payload-auth-link): an auth plugin for Payload CMS with swappable identity providers (Better Auth, Auth.js) and first-class Next.js and TanStack Start adapters.

## Install

```bash
npm install @payload-auth-link/react
```

Peer dependencies: `react` ^19.0.0.

ESM-only, Node 20.9 or later.

## What it provides

- `AuthLinkProvider`, `useAuthLink`, `useHasRoles`: session context, hydrated from the server through `initialUser`
- `SignInButton`, `SignOutButton`, `UserMenu`: unstyled primitives
- `RequireRoles`: hides UI by role (never use it to gate content; enforce on the server)

## Usage

```tsx
import { AuthLinkProvider, UserMenu } from '@payload-auth-link/react'

export function Layout({ user, children }) {
  return (
    <AuthLinkProvider initialUser={user}>
      <UserMenu signOutRedirectTo="/" />
      {children}
    </AuthLinkProvider>
  )
}
```

## Docs

- [Getting started](https://github.com/jellologic/payload-auth-link/blob/main/docs/getting-started.md)
- [Compatibility](https://github.com/jellologic/payload-auth-link/blob/main/docs/compatibility.md) · [Troubleshooting](https://github.com/jellologic/payload-auth-link/blob/main/docs/troubleshooting.md) · [Changelog](./CHANGELOG.md)

## License

MIT
