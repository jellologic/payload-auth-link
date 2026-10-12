/**
 * Did the Auth.js credentials callback land on Auth.js's own failure
 * page? The callback always answers 302: to the callback URL on
 * success, to `<basePath>/error` or `<basePath>/signin` (carrying
 * `?error=…`) when `authorize` rejects. Decide on the final URL's
 * PATH: a substring check on `error=` would misreport a successful
 * sign-in whose own destination carries `error=` in its query.
 */
export function isAuthJsFailureLanding(finalUrl: string, basePath = '/api/authjs'): boolean {
  let url: URL
  try {
    url = new URL(finalUrl)
  } catch {
    // An unparseable landing is not a success we can vouch for.
    return true
  }
  return url.pathname === `${basePath}/error` || url.pathname === `${basePath}/signin`
}
