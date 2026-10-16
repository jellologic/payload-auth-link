/**
 * Property tests for the middleware path matcher (issue #86):
 * `decideAuthRedirect` backs both the Next and TanStack Start
 * middlewares. Public paths are EXACT strings (or host regexes), the
 * sign-in path is always public, and a session cookie lets anything
 * through. The properties pin that no path spelling aliases its way
 * onto a public path, that the decision depends only on the
 * URL-normalised pathname, and that the bounce never leaves the
 * request's origin.
 */
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { decideAuthRedirect } from '../redirect.js'

const runs = { numRuns: 200 } as const
const ORIGIN = 'http://localhost:3200'
const COOKIE = 'better-auth.session_token'

const segment = fc.stringMatching(/^[a-z0-9][a-z0-9_-]{0,8}$/)
const pathArb = fc
  .array(segment, { minLength: 1, maxLength: 4 })
  .map((parts) => `/${parts.join('/')}`)
/** Path-ish strings including the usual normalisation tricks. */
const trickyPathArb = fc
  .array(
    fc.oneof(
      segment,
      fc.constantFrom('', '.', '..', '%2e%2e', '%2F', '%2f', 'Admin', 'ADMIN', '%61dmin', ';x')
    ),
    { minLength: 1, maxLength: 5 }
  )
  .map((parts) => `/${parts.join('/')}`)

function request(path: string, cookie?: string): Request {
  return new Request(`${ORIGIN}${path}`, cookie === undefined ? undefined : { headers: { cookie } })
}

/** Aliases of a path that must NOT be treated as that exact path. */
function aliasesOf(path: string): string[] {
  return [
    `${path}/`,
    `${path}x`,
    `${path}/child`,
    `/${path}`,
    path.toUpperCase(),
    // Percent-encode the first letter: URL keeps it encoded.
    `/%${path.charCodeAt(1).toString(16)}${path.slice(2)}`,
    `${path}%2F`,
  ].filter((alias) => alias !== path)
}

describe('decideAuthRedirect matcher (property)', () => {
  it('anonymous requests to non-public paths always bounce to the same-origin sign-in page', () => {
    fc.assert(
      fc.property(
        trickyPathArb,
        fc.option(fc.stringMatching(/^[a-z]=[a-z0-9]{0,5}$/)),
        (path, query) => {
          const url = new URL(`${ORIGIN}${path}${query === null ? '' : `?${query}`}`)
          fc.pre(url.pathname !== '/sign-in')
          const target = decideAuthRedirect(
            request(`${path}${query === null ? '' : `?${query}`}`),
            {
              sessionCookieNames: [COOKIE],
            }
          )
          expect(target).not.toBeNull()
          if (target !== null) {
            expect(target.origin).toBe(ORIGIN)
            expect(target.pathname).toBe('/sign-in')
            // The intercepted destination is the normalised path + query.
            expect(target.searchParams.get('redirect')).toBe(`${url.pathname}${url.search}`)
            expect([...target.searchParams.keys()]).toEqual(['redirect'])
          }
        }
      ),
      runs
    )
  })

  it('a public exact path admits only that pathname, never a prefix/suffix/case/encoding alias', () => {
    fc.assert(
      fc.property(pathArb, (publicPath) => {
        const options = { sessionCookieNames: [COOKIE], publicPaths: [publicPath] }
        expect(decideAuthRedirect(request(publicPath), options)).toBeNull()
        for (const alias of aliasesOf(publicPath)) {
          const normalised = new URL(`${ORIGIN}${alias}`).pathname
          fc.pre(normalised !== publicPath && normalised !== '/sign-in')
          expect(decideAuthRedirect(request(alias), options)).not.toBeNull()
        }
      }),
      runs
    )
  })

  it('the decision depends only on the URL-normalised pathname (dot segments resolve first)', () => {
    fc.assert(
      fc.property(trickyPathArb, pathArb, fc.boolean(), (path, publicPath, withCookie) => {
        const options = { sessionCookieNames: [COOKIE], publicPaths: [publicPath] }
        const cookie = withCookie ? `${COOKIE}=v` : undefined
        const normalised = new URL(`${ORIGIN}${path}`).pathname
        const raw = decideAuthRedirect(request(path, cookie), options)
        const canonical = decideAuthRedirect(request(normalised, cookie), options)
        expect(raw?.href ?? null).toBe(canonical?.href ?? null)
      }),
      runs
    )
  })

  it('the sign-in path is public; its aliases are not (a bounce, never a loop)', () => {
    fc.assert(
      fc.property(pathArb, (signInPath) => {
        const options = { sessionCookieNames: [COOKIE], signInPath }
        expect(decideAuthRedirect(request(signInPath), options)).toBeNull()
        for (const alias of aliasesOf(signInPath)) {
          fc.pre(new URL(`${ORIGIN}${alias}`).pathname !== signInPath)
          const target = decideAuthRedirect(request(alias), options)
          expect(target?.pathname).toBe(signInPath)
        }
      }),
      runs
    )
  })

  it('only an exactly-named session cookie passes; look-alike names do not', () => {
    fc.assert(
      fc.property(
        trickyPathArb,
        fc.stringMatching(/^[A-Za-z0-9._~-]{0,12}$/),
        fc.constantFrom(
          `${COOKIE}x`,
          `x${COOKIE}`,
          COOKIE.toUpperCase(),
          `${COOKIE}.sig`,
          `__Secure-${COOKIE}x`
        ),
        (path, value, lookAlike) => {
          fc.pre(new URL(`${ORIGIN}${path}`).pathname !== '/sign-in')
          const options = { sessionCookieNames: [COOKIE] }
          expect(decideAuthRedirect(request(path, `${COOKIE}=${value}`), options)).toBeNull()
          expect(decideAuthRedirect(request(path, `${lookAlike}=${value}`), options)).not.toBeNull()
        }
      ),
      runs
    )
  })

  it('no configured cookie names fails closed: every non-public path bounces', () => {
    fc.assert(
      fc.property(trickyPathArb, (path) => {
        fc.pre(new URL(`${ORIGIN}${path}`).pathname !== '/sign-in')
        expect(
          decideAuthRedirect(request(path, `${COOKIE}=v`), { sessionCookieNames: [] })
        ).not.toBeNull()
      }),
      runs
    )
  })

  it('protocol-relative-looking paths still bounce to the request origin', () => {
    fc.assert(
      fc.property(fc.domain(), pathArb, (host, rest) => {
        const target = decideAuthRedirect(request(`//${host}${rest}`), {
          sessionCookieNames: [COOKIE],
        })
        expect(target?.origin).toBe(ORIGIN)
        expect(target?.pathname).toBe('/sign-in')
      }),
      runs
    )
  })
})
