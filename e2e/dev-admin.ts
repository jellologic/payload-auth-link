/**
 * Seeded dev-admin identity, single-sourced for the e2e harness: configs
 * import it for `webServer.env` (the server seeds only when the flag is
 * set and the password provided — see `onInit` in either example) and
 * specs import it for the admin-login fills. Override the password with
 * `DEV_ADMIN_PASSWORD` (server and specs read the same variable, so they
 * cannot drift).
 */
export const DEV_ADMIN_EMAIL = 'dev@payload-auth-link.test'
export const DEV_ADMIN_PASSWORD = process.env.DEV_ADMIN_PASSWORD ?? 'e2e-dev-admin-password-1'

/** `webServer.env` entries that enable the dev-admin seed. */
export const DEV_ADMIN_SEED_ENV: Record<string, string> = {
  ALLOW_DEV_ADMIN_SEED: 'true',
  DEV_ADMIN_PASSWORD,
}
