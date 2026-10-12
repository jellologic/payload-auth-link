import { describe, expect, it, vi } from 'vitest'
import { createServerRouteHandlers } from '../handlers.js'

describe('createServerRouteHandlers', () => {
  it('routes GET and POST contexts to the handler request', async () => {
    const seen: string[] = []
    const { GET, POST } = createServerRouteHandlers((request: Request): Promise<Response> => {
      seen.push(request.method)
      return Promise.resolve(Response.json({ ok: true }))
    })
    const get = await GET({
      request: new Request('http://localhost/api/auth/x', { method: 'GET' }),
    })
    const post = await POST({
      request: new Request('http://localhost/api/auth/x', { method: 'POST' }),
    })
    expect(get.status).toBe(200)
    expect(post.status).toBe(200)
    expect(seen).toEqual(['GET', 'POST'])
  })

  it('envelopes handler errors as 500 JSON', async () => {
    const onError = vi.fn()
    const { GET } = createServerRouteHandlers(
      (): Promise<Response> => Promise.reject(new Error('boom')),
      { onError }
    )
    const response = await GET({ request: new Request('http://localhost/api/auth/x') })
    expect(response.status).toBe(500)
    expect(await response.json()).toEqual({ error: 'auth handler failed' })
    expect(onError).toHaveBeenCalledTimes(1)
  })
})
