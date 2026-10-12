import { withPayloadRoot } from '@payloadcms/tanstack-start/client'
import { createRootRoute, HeadContent, Scripts } from '@tanstack/react-router'

export const Route = createRootRoute({
  shellComponent: withPayloadRoot(StartHtml),
})

function StartHtml({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
        <title>payload-auth-link example</title>
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  )
}
