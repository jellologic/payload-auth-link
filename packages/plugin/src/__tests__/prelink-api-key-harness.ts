/**
 * Shared harness for the pre-link API-key suites
 * (`integration-prelink-api-key*.test.ts`, one Payload per file):
 * a users collection with Payload API keys behind a real authLink boot
 * on SQLite in memory, driven through `handleEndpoints`.
 */
import { createHmac } from 'node:crypto'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { expect } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://prelink-api-key.test'
const SECRET = 'prelink-api-key-secret-32-chars!!'

export type Instance = {
  readonly key: string
  readonly config: SanitizedConfig
  readonly payload: Payload
  readonly stub: ReturnType<typeof createStubProvider>
}

export type Reply = { status: number; body: unknown }

export async function boot(key: string, allowLocal: boolean): Promise<Instance> {
  const stub = createStubProvider()
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: { useAPIKey: true }, fields: [] }],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        ...(allowLocal ? { allowLocalCredentialsForLinkedDocs: true } : {}),
      }),
    ],
  })
  const payload = await getPayload({ config, key })
  return { key, config, payload, stub }
}

export async function rest(
  instance: Instance,
  method: string,
  path: string,
  opts: { authorization?: string; cookie?: string; body?: unknown } = {}
): Promise<Reply> {
  const headers: Record<string, string> = { origin: ORIGIN }
  if (opts.authorization !== undefined) {
    headers.authorization = opts.authorization
  }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config: instance.config,
    payloadInstanceCacheKey: instance.key,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body }
}

export const apiKeyHeader = (key: string) => `users API-Key ${key}`

/** A proven, unlinked document with a Payload API key enabled. */
export async function documentWithKey(
  instance: Instance,
  email: string,
  apiKey: string
): Promise<string> {
  const created = await instance.payload.create({
    collection: 'users',
    data: {
      email,
      password: 'pre-link-password-1',
      roles: ['user'],
      linkable: true,
      linkableEmail: email,
      enableAPIKey: true,
      apiKey,
    },
    overrideAccess: true,
  })
  return String(created.id)
}

/** Link a provider identity to the document through a real verification. */
export async function link(
  instance: Instance,
  email: string,
  providerUserId: string
): Promise<void> {
  const linked = await rest(instance, 'GET', '/auth-link/session', {
    cookie: instance.stub.issue({
      sessionId: `sess-${providerUserId}`,
      providerUserId,
      email,
      expiresAt: new Date(Date.now() + 3600_000),
    }),
  })
  expect(linked.status).toBe(200)
}

export function meUserId(reply: Reply): string | null {
  const user = (reply.body as { user?: { id?: unknown } | null } | null)?.user
  return user === null || user === undefined ? null : String(user.id)
}

export function usersGrants(reply: Reply): { read: unknown; update: unknown } {
  const users =
    (
      reply.body as {
        collections?: {
          users?: {
            read?: { permission?: boolean } | boolean
            update?: { permission?: boolean } | boolean
          }
        }
      }
    ).collections?.users ?? {}
  const flag = (value: { permission?: boolean } | boolean | undefined) =>
    typeof value === 'boolean' ? value : value?.permission
  return { read: flag(users.read), update: flag(users.update) }
}

/** Whether Payload's API-key lookup index still matches the key. */
export async function keyIndexed(instance: Instance, apiKey: string): Promise<boolean> {
  const index = createHmac('sha256', instance.payload.secret).update(apiKey).digest('hex')
  const found = await instance.payload.find({
    collection: 'users',
    where: { apiKeyIndex: { equals: index } },
    overrideAccess: true,
    pagination: false,
  })
  return found.docs.length > 0
}
