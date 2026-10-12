import { withPayload } from '@payloadcms/tanstack-start'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import viteReact from '@vitejs/plugin-react'
import rsc from '@vitejs/plugin-rsc'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig(
  withPayload(
    ({ pluginOptions }) => ({
      plugins: [
        rsc(pluginOptions.rsc),
        tanstackStart(pluginOptions.tanstackStart),
        viteReact(pluginOptions.react),
      ],
      resolve: {
        alias: [
          { find: /^@\//, replacement: `${path.resolve(__dirname, 'src')}/` },
          // Pin tslib to ESM; the UMD build breaks CJS interop at boot
          // (same pin as Payload's TanStack demo).
          {
            find: /^tslib$/,
            replacement: path.resolve(__dirname, 'node_modules', 'tslib', 'tslib.es6.mjs'),
          },
        ],
      },
      server: { port: 3200 },
    }),
    {
      payloadConfigPath: path.resolve(__dirname, 'src', 'payload.config.ts'),
      // ajv's CJS breaks under the RSC plugin's CJS-to-ESM rewrite
      // (frozen ESM namespace hits `uri.code = ...`); keep it external
      // in dev so Node requires it directly.
      devServerExternalPackages: ['ajv'],
    }
  )
)
